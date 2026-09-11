"""Work out which files form a server's MCP tool surface.

A scanner for MCP servers only has something to say about code an MCP client can
reach. Treating every function parameter in a repository as attacker-controlled
produces findings in release scripts, build tooling and examples — measured at
96% of all findings on a 56-server corpus, with one rule alone responsible for
93% of everything rated HIGH.

The surface is computed as: files that register MCP tools (entry points), plus
every local file reachable from them through imports. The second half matters —
a path traversal in `utils/files.py` called from a tool handler is a real
finding, and a file-level filter would throw it away.
"""

import logging
import os
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

SOURCE_SUFFIXES = {".py", ".ts", ".js", ".mjs", ".mts", ".jsx", ".tsx"}

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "site-packages",
    "dist-packages", ".tox", ".nox", ".eggs", "build", "dist", ".next",
    ".mypy_cache", ".pytest_cache", ".ruff_cache",
}

# Registering a tool is what puts code on the MCP surface. Importing the SDK is
# not enough — plenty of repositories depend on it without exposing anything.
_TOOL_REGISTRATION = re.compile(
    r"""(
        @\w+\.tool\s*\(                 # FastMCP:  @mcp.tool()
      | @\w+\.resource\s*\(             # FastMCP:  @mcp.resource()
      | @\w+\.prompt\s*\(               # FastMCP:  @mcp.prompt()
      | \bFastMCP\s*\(                  # FastMCP server construction
      | \.setRequestHandler\s*\(        # TS SDK
      | \bListToolsRequestSchema\b      # TS SDK
      | \bCallToolRequestSchema\b       # TS SDK
      | \bserver\.tool\s*\(             # TS SDK sugar
      | \bregisterTool\s*\(             # TS SDK sugar
      | \btypes\.Tool\s*\(              # python raw SDK
      | \bmcp\.types\b
      | list_tools\s*\(                 # python raw SDK handlers
      | call_tool\s*\(
    )""",
    re.VERBOSE,
)

# Local imports only. A third-party package is not part of this repo's surface.
_PY_IMPORT = re.compile(
    r"^\s*(?:from\s+(\.*[\w.]*)\s+import\s|import\s+([\w.]+))", re.MULTILINE
)
_JS_IMPORT = re.compile(
    r"""(?:from\s*['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\)|import\s*\(\s*['"]([^'"]+)['"]\s*\))"""
)

MAX_FILES = 20_000
MAX_READ_BYTES = 400_000


def _iter_source_files(root: Path):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if Path(name).suffix in SOURCE_SUFFIXES:
                count += 1
                if count > MAX_FILES:
                    logger.warning("Tool surface scan capped at %d files", MAX_FILES)
                    return
                yield Path(dirpath) / name


def _read(path: Path) -> str:
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            return fh.read(MAX_READ_BYTES)
    except OSError:
        return ""


def _resolve_python(
    importer: Path, module: str, root: Path, index: dict[str, list[Path]]
) -> list[Path]:
    """Map a Python module reference onto files inside the repo.

    Absolute imports are matched against an index keyed by path suffix, so a
    `src/` layout resolves: `from serena.agent import X` finds
    `src/serena/agent.py` without having to guess where the source root is.
    """
    if not module:
        return []

    if module.startswith("."):
        up = len(module) - len(module.lstrip("."))
        base = importer.parent
        for _ in range(up - 1):
            base = base.parent
        tail = module.lstrip(".")
        # `from . import x` has no module part: the package __init__ is the target.
        candidates = [base / "__init__.py"] if not tail else [
            base / Path(*tail.split(".")).with_suffix(".py"),
            base / Path(*tail.split(".")) / "__init__.py",
        ]
        out = []
        for candidate in candidates:
            try:
                resolved = candidate.resolve()
                if candidate.is_file() and resolved.is_relative_to(root):
                    out.append(resolved)
            except (OSError, ValueError):
                continue
        return out

    parts = module.split(".")
    out = []
    # Try the longest dotted prefix first: serena.agent before serena.
    for length in range(len(parts), 0, -1):
        key = "/".join(parts[:length])
        if key in index:
            out.extend(index[key])
            break
    return out


def _resolve_js(importer: Path, spec: str, root: Path) -> list[Path]:
    """Map a JS/TS import specifier onto files inside the repo."""
    if not spec or not spec.startswith("."):
        return []  # bare specifier — a package, not our code
    target = (importer.parent / spec).resolve()
    out = []
    candidates = [target]
    for suffix in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".mts"):
        candidates.append(target.with_suffix(suffix))
        candidates.append(target / f"index{suffix}")
    for candidate in candidates:
        try:
            if candidate.is_file() and candidate.is_relative_to(root):
                out.append(candidate)
        except (OSError, ValueError):
            continue
    return out


def compute_tool_surface(target: Path) -> Optional[set[Path]]:
    """Return the set of files on the MCP tool surface.

    Returns None when no tool registration is found anywhere — the target is
    then not recognisably an MCP server, and callers should not reclassify
    anything rather than demote every finding it has.
    """
    try:
        root = target.resolve()
    except (OSError, ValueError):
        return None
    if root.is_file():
        root = root.parent

    contents: dict[Path, str] = {}
    entry_points: set[Path] = set()

    for path in _iter_source_files(root):
        try:
            resolved = path.resolve()
        except (OSError, ValueError):
            continue
        text = _read(resolved)
        if not text:
            continue
        contents[resolved] = text
        if _TOOL_REGISTRATION.search(text):
            entry_points.add(resolved)

    if not entry_points:
        return None

    # Index modules by path suffix so absolute imports resolve under any layout
    # (flat, src/, monorepo package dirs).
    index: dict[str, list[Path]] = {}
    for path in contents:
        if path.suffix != ".py":
            continue
        rel = path.relative_to(root).with_suffix("")
        parts = list(rel.parts)
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        for start in range(len(parts)):
            key = "/".join(parts[start:])
            if key:
                index.setdefault(key, []).append(path)

    surface = set(entry_points)
    queue = list(entry_points)
    while queue:
        current = queue.pop()
        text = contents.get(current, "")
        neighbours: list[Path] = []

        if current.suffix == ".py":
            for m in _PY_IMPORT.finditer(text):
                module = m.group(1) or m.group(2) or ""
                neighbours.extend(_resolve_python(current, module, root, index))
        else:
            for m in _JS_IMPORT.finditer(text):
                spec = m.group(1) or m.group(2) or m.group(3) or ""
                neighbours.extend(_resolve_js(current, spec, root))

        for nxt in neighbours:
            if nxt not in surface and nxt in contents:
                surface.add(nxt)
                queue.append(nxt)

    logger.debug(
        "Tool surface: %d entry points, %d files of %d",
        len(entry_points), len(surface), len(contents),
    )
    return surface
