"""MCP tool surface detection.

Measured motivation: on a 56-server corpus, 96% of findings landed in files that
register no MCP tools — release scripts, build tooling, examples. Those are not
reachable by an MCP client and must not outrank findings that are.
"""
from pathlib import Path

import pytest

from mcp_redteam.engine.tool_surface import compute_tool_surface


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p.resolve()


def test_returns_none_when_no_tools_registered(tmp_path):
    """Not a recognisable MCP server — say nothing rather than demote everything."""
    _write(tmp_path, "util.py", "def helper(x):\n    return open(x).read()\n")
    assert compute_tool_surface(tmp_path) is None


def test_entry_point_is_on_the_surface(tmp_path):
    server = _write(tmp_path, "server.py",
                    "from mcp.server.fastmcp import FastMCP\n"
                    "mcp = FastMCP('x')\n"
                    "@mcp.tool()\n"
                    "def read(path: str):\n    return open(path).read()\n")
    surface = compute_tool_surface(tmp_path)
    assert server in surface


def test_release_script_is_off_the_surface(tmp_path):
    """The exact shape that dominated the corpus: tooling next to the server."""
    _write(tmp_path, "server.py",
           "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"
           "@mcp.tool()\ndef ping():\n    return 'pong'\n")
    script = _write(tmp_path, "scripts/bump_version.py",
                    "import os\ndef bump(v):\n    os.system(f'git tag v{v}')\n")
    surface = compute_tool_surface(tmp_path)
    assert script not in surface


def test_helper_imported_by_a_handler_stays_on_the_surface(tmp_path):
    """A traversal in a helper called from a tool handler is a real finding.

    A file-level filter would discard it; reachability keeps it.
    """
    _write(tmp_path, "server.py",
           "from mcp.server.fastmcp import FastMCP\n"
           "from helpers.files import load\n"
           "mcp = FastMCP('x')\n"
           "@mcp.tool()\ndef read(p: str):\n    return load(p)\n")
    helper = _write(tmp_path, "helpers/files.py",
                    "def load(p):\n    return open(p).read()\n")
    _write(tmp_path, "helpers/__init__.py", "")
    surface = compute_tool_surface(tmp_path)
    assert helper in surface, "helper reachable from a tool handler was dropped"


def test_transitive_imports_are_followed(tmp_path):
    _write(tmp_path, "server.py",
           "from mcp.server.fastmcp import FastMCP\nimport layer1\n"
           "mcp = FastMCP('x')\n@mcp.tool()\ndef t():\n    return layer1.go()\n")
    _write(tmp_path, "layer1.py", "import layer2\ndef go():\n    return layer2.go()\n")
    deep = _write(tmp_path, "layer2.py", "def go():\n    return open('x').read()\n")
    assert deep in compute_tool_surface(tmp_path)


def test_src_layout_resolves(tmp_path):
    """`from pkg.mod import x` must find src/pkg/mod.py, not only pkg/mod.py."""
    _write(tmp_path, "src/pkg/__init__.py", "")
    _write(tmp_path, "src/pkg/server.py",
           "from mcp.server.fastmcp import FastMCP\n"
           "from pkg.tools import run\n"
           "mcp = FastMCP('x')\n@mcp.tool()\ndef t():\n    return run()\n")
    tools = _write(tmp_path, "src/pkg/tools.py", "def run():\n    return 1\n")
    assert tools in compute_tool_surface(tmp_path)


def test_relative_imports_resolve(tmp_path):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/server.py",
           "from mcp.server.fastmcp import FastMCP\nfrom .util import go\n"
           "mcp = FastMCP('x')\n@mcp.tool()\ndef t():\n    return go()\n")
    util = _write(tmp_path, "pkg/util.py", "def go():\n    return 1\n")
    assert util in compute_tool_surface(tmp_path)


def test_typescript_entry_point_and_relative_import(tmp_path):
    server = _write(tmp_path, "src/index.ts",
                    "import { Server } from '@modelcontextprotocol/sdk';\n"
                    "import { readFile } from './files';\n"
                    "server.setRequestHandler(ListToolsRequestSchema, async () => {});\n")
    helper = _write(tmp_path, "src/files.ts",
                    "export function readFile(p: string) { return p; }\n")
    surface = compute_tool_surface(tmp_path)
    assert server in surface and helper in surface


def test_third_party_imports_are_not_surface(tmp_path):
    _write(tmp_path, "server.py",
           "from mcp.server.fastmcp import FastMCP\nimport requests\n"
           "mcp = FastMCP('x')\n@mcp.tool()\ndef t():\n    return requests.get('u')\n")
    surface = compute_tool_surface(tmp_path)
    assert all("requests" not in str(p) for p in surface)


def test_sdk_dependency_alone_is_not_registration(tmp_path):
    """Importing the SDK without exposing anything is not a tool surface."""
    _write(tmp_path, "app.py", "import mcp\n\ndef main():\n    return 1\n")
    assert compute_tool_surface(tmp_path) is None


# ---------------------------------------------------------------------------
# Severity reclassification
# ---------------------------------------------------------------------------


def test_off_surface_findings_are_demoted_and_annotated():
    from mcp_redteam.engine.semgrep_runner import _classify_by_tool_surface
    from mcp_redteam.models import Finding, FindingCategory, Location, Severity

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _write(root, "server.py",
               "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"
               "@mcp.tool()\ndef t():\n    return 1\n")
        script = _write(root, "release.py", "import os\nos.system('git tag')\n")

        f = Finding(id="MRT001", rule_id="MRT001", title="Shell Injection",
                    severity=Severity.CRITICAL, category=FindingCategory.security,
                    description="d", evidence="e",
                    location=Location(file=str(script), line=2))

        out = _classify_by_tool_surface([f], root)[0]

    assert out.in_tool_surface is False
    assert out.severity == Severity.INFO
    assert out.original_severity == Severity.CRITICAL
    assert "not reachable from any MCP tool handler" in out.description


def test_on_surface_findings_keep_their_severity():
    from mcp_redteam.engine.semgrep_runner import _classify_by_tool_surface
    from mcp_redteam.models import Finding, FindingCategory, Location, Severity

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        server = _write(root, "server.py",
                        "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"
                        "@mcp.tool()\ndef t(cmd: str):\n    import subprocess\n"
                        "    subprocess.run(cmd, shell=True)\n")

        f = Finding(id="MRT001", rule_id="MRT001", title="Shell Injection",
                    severity=Severity.CRITICAL, category=FindingCategory.security,
                    description="d", evidence="e",
                    location=Location(file=str(server), line=5))

        out = _classify_by_tool_surface([f], root)[0]

    assert out.in_tool_surface is True
    assert out.severity == Severity.CRITICAL
    assert out.original_severity is None


def test_nothing_is_demoted_when_target_is_not_an_mcp_server():
    """No tool registration anywhere: leave every severity alone."""
    from mcp_redteam.engine.semgrep_runner import _classify_by_tool_surface
    from mcp_redteam.models import Finding, FindingCategory, Location, Severity

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        plain = _write(root, "app.py", "import os\nos.system('x')\n")

        f = Finding(id="MRT001", rule_id="MRT001", title="Shell Injection",
                    severity=Severity.CRITICAL, category=FindingCategory.security,
                    description="d", evidence="e",
                    location=Location(file=str(plain), line=2))

        out = _classify_by_tool_surface([f], root)[0]

    assert out.severity == Severity.CRITICAL
    assert out.in_tool_surface is None


def test_bare_relative_import_does_not_crash(tmp_path):
    """`from . import x` has no module part — Path().with_suffix() raises on that."""
    _write(tmp_path, "pkg/__init__.py", "VALUE = 1\n")
    _write(tmp_path, "pkg/server.py",
           "from mcp.server.fastmcp import FastMCP\nfrom . import VALUE\n"
           "mcp = FastMCP('x')\n@mcp.tool()\ndef t():\n    return VALUE\n")

    surface = compute_tool_surface(tmp_path)  # must not raise

    assert (tmp_path / "pkg" / "__init__.py").resolve() in surface
