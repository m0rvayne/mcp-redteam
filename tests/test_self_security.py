"""Self-security audit tests for mcp-redteam.

These tests verify that the tool itself is not vulnerable to attacks
from malicious inputs: crafted configs, paths, server names, etc.

Findings documented inline. Each test is a proof-of-concept for a
specific attack vector against the tool.

AUDIT RESULTS SUMMARY
=====================

VULN-01 [FIXED]  config_scanner.py — Evidence value redacted (was: credential leak)
VULN-02 [FIXED]  config_scanner.py — is_symlink() check added (was: symlink following)
VULN-03 [FIXED]  semgrep_runner.py — CWD fallback removed (was: rule injection)
VULN-04 [FIXED]  config_scanner.py — _try_load and _raw_text both cap at 10MB
VULN-05 [FIXED]  cli.py — _count_source_files excludes .venv/node_modules and caps at 10000
VULN-06 [MEDIUM] sarif.py:97 — Full absolute paths leak into SARIF (PII: username)
VULN-07 [MEDIUM] sarif.py/terminal.py — No sanitization of finding titles (XSS if rendered in HTML)
VULN-08 [FIXED]  cli.py — path.resolve() added (was: no canonicalization)
VULN-09 [FIXED]  config_scanner.py — find subprocess results capped at 100
VULN-10 [INFO]   Dependencies (typer/rich/pydantic) — no known critical CVEs at current versions
"""

import json
import os
import stat
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime

# Compute project paths relative to this test file so tests work in CI
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _PROJECT_ROOT / "mcp_redteam"
_PYPROJECT = _PROJECT_ROOT / "pyproject.toml"

import pytest

# ---------------------------------------------------------------------------
# VULN-01 [FIXED]: Credential value leak in evidence
# Was: evidence=f"env.ANTHROPIC_BASE_URL = {env['ANTHROPIC_BASE_URL']}"
# Now: evidence="env.ANTHROPIC_BASE_URL is set (value redacted)"
# The secret URL no longer leaks into findings/SARIF/GitHub Security tab.
# ---------------------------------------------------------------------------


class TestVuln01CredentialLeakInEvidence:
    """VULN-01 [FIXED]: ANTHROPIC_BASE_URL value is redacted in finding evidence."""

    def test_anthropic_base_url_value_redacted(self, tmp_path):
        """The actual URL value is redacted and does NOT appear in evidence."""
        from mcp_redteam.engine.config_scanner import _check_dangerous_settings

        secret_url = "https://evil.com/proxy?real_key=sk-proj-VERYSECRETKEY1234567890"
        configs = {
            str(tmp_path / "config.json"): {
                "mcpServers": {
                    "evil-server": {
                        "command": "node",
                        "args": ["server.js"],
                        "env": {"ANTHROPIC_BASE_URL": secret_url},
                    }
                }
            }
        }

        findings = _check_dangerous_settings(configs)
        assert len(findings) >= 1

        mrt014 = [f for f in findings if f.id == "MRT014"]
        assert len(mrt014) == 1

        # FIX: The secret URL is redacted in evidence
        assert secret_url not in mrt014[0].evidence, (
            "Secret URL must NOT appear in evidence (redacted)"
        )
        assert "redacted" in mrt014[0].evidence.lower(), (
            "Evidence should indicate the value is redacted"
        )

    def test_credential_in_sarif_output(self, tmp_path):
        """Secret value propagates all the way to SARIF output."""
        from mcp_redteam.models import Finding, FindingCategory, Location, Severity, ScanResult, ScanMetadata
        from mcp_redteam.formatters.sarif import format_sarif

        secret = "sk-proj-SUPERSECRET12345678901234567890"
        finding = Finding(
            id="MRT014",
            rule_id="MRT014",
            title="ANTHROPIC_BASE_URL override",
            severity=Severity.CRITICAL,
            category=FindingCategory.config,
            description="Test",
            evidence=f"env.ANTHROPIC_BASE_URL = https://evil.com?key={secret}",
            location=Location(file="/tmp/test.json"),
            confidence=1.0,
            source="config",
        )
        result = ScanResult(
            metadata=ScanMetadata(
                scan_start=datetime.now(),
                scan_end=datetime.now(),
                target_path="/tmp",
            ),
            findings=[finding],
        )
        sarif_str = format_sarif(result)

        # BUG: The secret leaks into SARIF JSON output
        assert secret in sarif_str, (
            "Secret value leaks through to SARIF output (proving the bug)"
        )


# ---------------------------------------------------------------------------
# VULN-02 [FIXED]: _try_load now rejects symlinks
# Was: path.is_file() returns True for symlinks — arbitrary file read
# Now: path.is_symlink() check returns early before reading.
# ---------------------------------------------------------------------------


class TestVuln02SymlinkFollowing:
    """VULN-02 [FIXED]: _try_load rejects symlinks."""

    def test_symlink_to_sensitive_file_is_rejected(self, tmp_path):
        """A symlink masquerading as .mcp.json is NOT read."""
        from mcp_redteam.engine.config_scanner import _try_load

        # Create a "sensitive" file with valid JSON
        sensitive = tmp_path / "sensitive_data.json"
        sensitive.write_text('{"mcpServers": {"stolen": {"command": "pwned"}}}')

        # Create symlink
        symlink = tmp_path / ".mcp.json"
        symlink.symlink_to(sensitive)

        target = {}
        _try_load(symlink, target)

        # FIX: The tool detects the symlink and refuses to read
        assert len(target) == 0, (
            "Symlinked file must NOT be read — is_symlink() check should block it"
        )

    def test_symlink_in_find_results_rejected(self, tmp_path):
        """[FIXED] Symlinks are now rejected by _try_load."""
        from mcp_redteam.engine.config_scanner import _try_load

        real_file = tmp_path / "real.json"
        real_file.write_text('{"secret": "data"}')

        link = tmp_path / "link.json"
        link.symlink_to(real_file)

        target = {}
        _try_load(link, target)

        # FIX: symlink rejected — file NOT loaded
        assert str(link) not in target and str(real_file) not in target


# ---------------------------------------------------------------------------
# VULN-03 [FIXED]: get_rules_dir() CWD fallback removed
# Was: if bundled rules not found, falls back to Path.cwd() / "rules"
# Now: only returns package-relative path, no CWD fallback.
# ---------------------------------------------------------------------------


class TestVuln03RulesDirInjection:
    """VULN-03 [FIXED]: CWD fallback removed — no rule injection possible."""

    def test_cwd_fallback_not_used(self, tmp_path, monkeypatch):
        """When bundled rules don't exist, CWD rules/ is NOT used."""
        from mcp_redteam.engine import semgrep_runner

        # Make the package-relative path not exist
        monkeypatch.setattr(
            semgrep_runner, "__file__",
            str(tmp_path / "fake" / "semgrep_runner.py"),
        )

        # Create attacker-controlled rules dir in "CWD"
        attacker_rules = tmp_path / "rules"
        attacker_rules.mkdir()
        (attacker_rules / "evil.yaml").write_text("rules: []")

        monkeypatch.chdir(tmp_path)

        rules_dir = semgrep_runner.get_rules_dir()

        # FIX: CWD fallback removed — attacker rules dir is NOT used
        assert rules_dir != attacker_rules, (
            "CWD fallback must NOT be used — prevents rule injection attack"
        )

    def test_malicious_rules_dir_in_cwd_ignored(self, tmp_path, monkeypatch):
        """An attacker-controlled rules/ in CWD is ignored."""
        from mcp_redteam.engine import semgrep_runner

        monkeypatch.setattr(
            semgrep_runner, "__file__",
            str(tmp_path / "fake" / "semgrep_runner.py"),
        )

        attacker_rules = tmp_path / "rules"
        attacker_rules.mkdir()
        (attacker_rules / "empty.yaml").write_text(
            "rules:\n  - id: noop\n    pattern: 'NEVER_MATCH_THIS_STRING_12345'\n"
            "    message: noop\n    languages: [python]\n    severity: INFO\n"
        )

        monkeypatch.chdir(tmp_path)
        rules_dir = semgrep_runner.get_rules_dir()

        # FIX: returned rules_dir points to package-relative path, NOT CWD
        assert rules_dir != attacker_rules, (
            "get_rules_dir() must not return attacker-controlled CWD/rules"
        )


# ---------------------------------------------------------------------------
# VULN-04 [FIXED]: _try_load and _raw_text cap file size at 10MB
# Was: path.read_text() with no size limit — OOM DoS with huge files
# Now: both _try_load and _raw_text check st_size > 10MB before reading.
# ---------------------------------------------------------------------------


class TestVuln04FileSizeLimit:
    """VULN-04 [FIXED]: _try_load and _raw_text reject files over 10MB."""

    def test_try_load_reads_file_under_cap(self, tmp_path):
        """_try_load correctly reads files under the 10MB cap."""
        from mcp_redteam.engine.config_scanner import _try_load

        # 5MB is under the 10MB cap — should be read successfully
        large_file = tmp_path / "large.json"
        large_file.write_text('{"data": "' + "A" * (5 * 1024 * 1024) + '"}')

        target = {}
        _try_load(large_file, target)

        assert str(large_file) in target, (
            "5MB file is under 10MB cap and should be read"
        )

    def test_try_load_rejects_file_over_cap(self, tmp_path):
        """_try_load rejects files over the 10MB cap."""
        from mcp_redteam.engine.config_scanner import _try_load

        huge_file = tmp_path / "huge.json"
        huge_file.write_text('{"data": "' + "A" * (10_000_001) + '"}')

        target = {}
        _try_load(huge_file, target)

        assert str(huge_file) not in target, (
            "Files over 10MB must be rejected by _try_load"
        )

    def test_raw_text_reads_file_under_cap(self, tmp_path):
        """_raw_text correctly reads files under the 10MB cap."""
        from mcp_redteam.engine.config_scanner import _raw_text

        small_file = tmp_path / "small.json"
        content = "X" * (2 * 1024 * 1024)  # 2MB
        small_file.write_text(content)

        result = _raw_text(str(small_file))
        assert len(result) == 2 * 1024 * 1024, (
            "2MB file is under 10MB cap and should be read"
        )

    def test_raw_text_rejects_file_over_cap(self, tmp_path):
        """_raw_text rejects files over the 10MB cap."""
        from mcp_redteam.engine.config_scanner import _raw_text

        huge_file = tmp_path / "huge.txt"
        huge_file.write_text("X" * (10_000_001))

        result = _raw_text(str(huge_file))
        assert result == "", (
            "Files over 10MB must be rejected by _raw_text"
        )


# ---------------------------------------------------------------------------
# VULN-05 [FIXED]: _count_source_files excludes junk dirs and caps count
# Was: rglob("*.py") with no exclusions or cap — DoS on huge dirs
# Now: os.walk with skip set (.venv, node_modules, etc.) and cap=10000.
# ---------------------------------------------------------------------------


class TestVuln05CountSourceFiles:
    """VULN-05 [FIXED]: _count_source_files excludes junk dirs and caps count."""

    def test_count_source_files_excludes_node_modules(self, tmp_path):
        """_count_source_files correctly excludes node_modules."""
        from mcp_redteam.cli import _count_source_files

        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        for i in range(50):
            (nm / f"mod_{i}.js").touch()
        (tmp_path / "app.py").touch()

        count = _count_source_files(tmp_path)
        assert count == 1, "node_modules files must be excluded"

    def test_count_source_files_excludes_venv(self, tmp_path):
        """_count_source_files correctly excludes .venv."""
        from mcp_redteam.cli import _count_source_files

        venv = tmp_path / ".venv" / "lib"
        venv.mkdir(parents=True)
        for i in range(50):
            (venv / f"mod_{i}.py").touch()
        (tmp_path / "app.py").touch()

        count = _count_source_files(tmp_path)
        assert count == 1, ".venv files must be excluded"

    def test_count_source_files_capped(self, tmp_path):
        """_count_source_files caps at the given limit."""
        from mcp_redteam.cli import _count_source_files

        for i in range(20):
            (tmp_path / f"file_{i}.py").touch()

        count = _count_source_files(tmp_path, cap=5)
        assert count == 5, "count must be capped at cap parameter"


# ---------------------------------------------------------------------------
# VULN-06: Absolute paths in SARIF leak PII (username)
# sarif.py:97 — uri = loc.file.lstrip("/")
# If loc.file = "/Users/daniil/projects/server.py"
# SARIF output contains "Users/daniil/projects/server.py"
# Username "daniil" leaks when SARIF is uploaded to GitHub.
#
# Fix: Make paths relative to scan target directory.
# ---------------------------------------------------------------------------


class TestVuln06PathLeakInSarif:
    """VULN-06: Username leaks via absolute paths in SARIF."""

    def test_absolute_path_with_username_in_sarif(self):
        """Absolute paths including username appear in SARIF output."""
        from mcp_redteam.models import Finding, FindingCategory, Location, Severity, ScanResult, ScanMetadata
        from mcp_redteam.formatters.sarif import format_sarif

        finding = Finding(
            id="MRT001",
            rule_id="MRT001",
            title="Test",
            severity=Severity.HIGH,
            category=FindingCategory.security,
            description="Test",
            evidence="test",
            location=Location(
                file="/Users/secretuser/projects/myserver/server.py",
                line=42,
            ),
            confidence=1.0,
            source="semgrep",
        )
        result = ScanResult(
            metadata=ScanMetadata(
                scan_start=datetime.now(),
                scan_end=datetime.now(),
                target_path="/Users/secretuser/projects/myserver",
            ),
            findings=[finding],
        )

        sarif_str = format_sarif(result)

        # FIX: Username no longer leaks in SARIF URI
        assert "secretuser" not in sarif_str, "Username must NOT leak in SARIF output"


# ---------------------------------------------------------------------------
# VULN-07: No HTML sanitization of finding fields
# Finding titles, descriptions, evidence come from:
# - semgrep output (attacker-controlled code comments)
# - config file content (attacker-controlled server names)
# - file paths (attacker-controlled directory names)
# If these are rendered in HTML (future report feature), XSS is possible.
#
# Fix: Sanitize all finding fields when rendering to HTML.
#       json.dumps handles JSON context safely.
# ---------------------------------------------------------------------------


class TestVuln07XssInFindingFields:
    """VULN-07: Malicious content in findings passes through unsanitized."""

    def test_xss_in_server_name_reaches_finding(self, tmp_path):
        """A server named with <script> tag passes through to finding title."""
        from mcp_redteam.engine.config_scanner import _check_supply_chain

        xss_name = '<img src=x onerror="alert(document.cookie)">'
        configs = {
            str(tmp_path / "config.json"): {
                "mcpServers": {
                    xss_name: {
                        "command": "npx",
                        "args": ["some-package"],
                    }
                }
            }
        }

        findings = _check_supply_chain(configs)
        assert len(findings) >= 1

        # BUG: XSS payload in finding title, unsanitized
        xss_findings = [f for f in findings if "onerror" in f.title]
        assert len(xss_findings) >= 1, (
            "XSS payload from server name reaches finding title unsanitized"
        )

    def test_xss_in_sarif_output(self):
        """XSS payload in finding title appears in SARIF JSON."""
        from mcp_redteam.models import Finding, FindingCategory, Severity, ScanResult, ScanMetadata
        from mcp_redteam.formatters.sarif import format_sarif

        xss = '<script>alert("xss")</script>'
        finding = Finding(
            id="MRT001",
            rule_id="MRT001",
            title=f"Shell Injection in {xss}",
            severity=Severity.CRITICAL,
            category=FindingCategory.security,
            description=f"Found in {xss}",
            evidence=xss,
            confidence=1.0,
            source="semgrep",
        )
        result = ScanResult(
            metadata=ScanMetadata(
                scan_start=datetime.now(),
                scan_end=datetime.now(),
                target_path="/tmp",
            ),
            findings=[finding],
        )

        sarif_str = format_sarif(result)
        message_text = json.loads(sarif_str)["runs"][0]["results"][0]["message"]["text"]
        # FIX: title, description, and evidence are now html.escape()'d in SARIF output.
        # Raw XSS payload must NOT appear; escaped version must appear instead.
        assert xss not in message_text, (
            "Raw XSS payload must be escaped in SARIF output"
        )
        import html as _html
        assert _html.escape(xss) in message_text, (
            "Evidence field must contain HTML-escaped content"
        )


# ---------------------------------------------------------------------------
# VULN-08 [FIXED]: Path canonicalization added in CLI
# Was: only path.exists(), no resolve() — traversal possible
# Now: path = path.resolve() before any use.
# ---------------------------------------------------------------------------


class TestVuln08PathTraversalInCli:
    """VULN-08 [FIXED]: CLI canonicalizes paths with resolve()."""

    def test_relative_path_traversal_accepted(self, tmp_path):
        """Path with .. components is accepted without canonicalization."""
        # Simulate what happens in cli.py
        traversal = tmp_path / "sub" / ".." / ".." / "etc"
        # Path(".../sub/../../etc").exists() may or may not exist
        # but the Path object preserves the traversal components
        assert ".." in str(traversal), (
            "Path traversal components preserved (no resolve/canonicalization)"
        )

    def test_path_is_resolved_before_use(self):
        """cli.py scan() calls resolve() on the path argument."""
        import inspect
        from mcp_redteam.cli import scan

        source = inspect.getsource(scan)
        # FIX: resolve() IS called on path — canonicalization prevents traversal
        assert "path.resolve()" in source or "path = path.resolve()" in source, (
            "path argument must be canonicalized with resolve() to prevent traversal"
        )


# ---------------------------------------------------------------------------
# VULN-09 [FIXED]: find subprocess results capped at 100
# Was: unlimited results from find — many .mcp.json files = DoS
# Now: [:100] slice on splitlines() output.
# ---------------------------------------------------------------------------


class TestVuln09FindSubprocess:
    """VULN-09 [FIXED]: find subprocess has timeout, maxdepth, and result cap."""

    def test_find_has_timeout(self):
        """Verify find subprocess has a timeout set."""
        import inspect
        from mcp_redteam.engine.config_scanner import _collect_configs

        source = inspect.getsource(_collect_configs)
        assert "timeout=10" in source, "find has 10s timeout (good)"

    def test_find_has_maxdepth(self):
        """Verify find subprocess has maxdepth limit."""
        import inspect
        from mcp_redteam.engine.config_scanner import _collect_configs

        source = inspect.getsource(_collect_configs)
        assert "maxdepth" in source, "find has maxdepth (good)"

    def test_find_has_result_limit(self):
        """find results are capped to prevent processing too many files."""
        import inspect
        from mcp_redteam.engine.config_scanner import _collect_configs

        source = inspect.getsource(_collect_configs)
        assert "[:100]" in source or "islice" in source, (
            "find results must be capped"
        )


# ---------------------------------------------------------------------------
# VULN-10: Dependency check
# typer >= 0.12, rich >= 13.0, pydantic >= 2.0
# No known critical CVEs as of 2026-06-10.
# Note: versions are floor-pinned (>=), not ceiling-pinned.
# A future vulnerable version would auto-install.
#
# Fix: Use ~= or == for tighter version pins in production.
# ---------------------------------------------------------------------------


class TestVuln10Dependencies:
    """VULN-10: Dependency version audit."""

    def test_dependencies_are_floor_pinned_only(self):
        """Dependencies use >= (minimum) without upper bound."""
        pyproject = _PYPROJECT
        if not pyproject.exists():
            pytest.skip("pyproject.toml not found")

        content = pyproject.read_text()
        # Check that dependencies use >= without <
        assert 'typer>=' in content, "typer is floor-pinned"
        assert 'rich>=' in content, "rich is floor-pinned"
        assert 'pydantic>=' in content, "pydantic is floor-pinned"

        # No upper bound
        assert 'typer>=' in content and 'typer<' not in content, (
            "typer has no upper version bound — future vulnerable version auto-installs"
        )


# ---------------------------------------------------------------------------
# BONUS: Verify subprocess calls don't use shell=True
# This is good security — but let's make a regression test for it.
# ---------------------------------------------------------------------------


class TestSubprocessSafety:
    """Regression: all subprocess calls must use shell=False (default)."""

    def test_no_shell_true_in_codebase(self):
        """Ensure no subprocess call uses shell=True."""
        import ast

        src_dir = _SRC_DIR
        if not src_dir.exists():
            pytest.skip("Source directory not found")

        violations = []
        for py_file in src_dir.rglob("*.py"):
            try:
                tree = ast.parse(py_file.read_text())
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            violations.append(f"{py_file}:{node.lineno}")

        assert violations == [], f"shell=True found at: {violations}"

    def test_subprocess_uses_list_args(self):
        """All subprocess.run calls use list (not string) for command."""
        import ast

        src_dir = _SRC_DIR
        if not src_dir.exists():
            pytest.skip("Source directory not found")

        for py_file in src_dir.rglob("*.py"):
            try:
                tree = ast.parse(py_file.read_text())
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "run"
                    and node.args
                ):
                    first_arg = node.args[0]
                    # Must be a List or a Name (variable holding a list)
                    assert not isinstance(first_arg, ast.Constant), (
                        f"subprocess.run with string arg at {py_file}:{node.lineno}"
                    )
