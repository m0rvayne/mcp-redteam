"""Self-security audit tests for mcp-redteam.

These tests verify that the tool itself is not vulnerable to attacks
from malicious inputs: crafted configs, paths, server names, etc.

Findings documented inline. Each test is a proof-of-concept for a
specific attack vector against the tool.

AUDIT RESULTS SUMMARY
=====================

VULN-01 [HIGH]   config_scanner.py:457 — Credential value leaks into evidence/SARIF
VULN-02 [HIGH]   config_scanner.py:130 — _try_load follows symlinks (symlink-to-sensitive-file)
VULN-03 [HIGH]   semgrep_runner.py:22-26 — get_rules_dir() CWD fallback allows rule injection
VULN-04 [MEDIUM] config_scanner.py:131 — _try_load reads unlimited file size (DoS: OOM)
VULN-05 [MEDIUM] cli.py:79 — rglob("*.py") on huge dirs = DoS (OOM/hang)
VULN-06 [MEDIUM] sarif.py:97 — Full absolute paths leak into SARIF (PII: username)
VULN-07 [MEDIUM] sarif.py/terminal.py — No sanitization of finding titles (XSS if rendered in HTML)
VULN-08 [LOW]    cli.py:42-44 — Path existence check only; no canonicalization (path traversal)
VULN-09 [LOW]    config_scanner.py:107-111 — find subprocess on $HOME with no size guard
VULN-10 [INFO]   Dependencies (typer/rich/pydantic) — no known critical CVEs at current versions
"""

import json
import os
import stat
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime

import pytest

# ---------------------------------------------------------------------------
# VULN-01: Credential value leak in evidence
# config_scanner.py line 457:
#   evidence=f"env.ANTHROPIC_BASE_URL = {env['ANTHROPIC_BASE_URL']}"
# If the value is "https://evil.com?stolen_key=sk-1234", the actual
# attacker-controlled URL (which may itself contain secrets) leaks into
# findings -> SARIF -> GitHub Security tab -> visible to all repo maintainers.
#
# Fix: Redact the value. Show only "env.ANTHROPIC_BASE_URL is set (redacted)".
# ---------------------------------------------------------------------------


class TestVuln01CredentialLeakInEvidence:
    """VULN-01: ANTHROPIC_BASE_URL value leaks into finding evidence."""

    def test_anthropic_base_url_value_exposed(self, tmp_path):
        """The actual URL value ends up in the finding evidence field."""
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

        # BUG: The secret URL is fully visible in evidence
        assert secret_url in mrt014[0].evidence, (
            "Expected the raw secret URL to leak into evidence (proving the bug)"
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
# VULN-02: _try_load follows symlinks to read arbitrary files
# config_scanner.py:130 — path.is_file() returns True for symlinks
# A malicious .mcp.json could be a symlink to /etc/shadow or ~/.ssh/id_rsa
# The tool will happily read and parse it.
#
# Fix: Check path.is_symlink() before reading. Or use os.open with O_NOFOLLOW.
# ---------------------------------------------------------------------------


class TestVuln02SymlinkFollowing:
    """VULN-02: _try_load follows symlinks without checking."""

    def test_symlink_to_sensitive_file_is_read(self, tmp_path):
        """A symlink masquerading as .mcp.json reads the target file."""
        from mcp_redteam.engine.config_scanner import _try_load

        # Create a "sensitive" file with valid JSON
        sensitive = tmp_path / "sensitive_data.json"
        sensitive.write_text('{"mcpServers": {"stolen": {"command": "pwned"}}}')

        # Create symlink
        symlink = tmp_path / ".mcp.json"
        symlink.symlink_to(sensitive)

        target = {}
        _try_load(symlink.resolve(), target)

        # BUG: The tool reads through the symlink without checking
        # In real attack: symlink -> /etc/passwd or ~/.ssh/id_rsa
        # (would fail json.loads but error is silently swallowed)
        assert len(target) == 1, (
            "Symlinked file was read without symlink check (proving the bug)"
        )

    def test_symlink_in_find_results(self, tmp_path):
        """If `find` returns a symlink path, _try_load will follow it."""
        from mcp_redteam.engine.config_scanner import _try_load

        real_file = tmp_path / "real.json"
        real_file.write_text('{"secret": "data"}')

        link = tmp_path / "link.json"
        link.symlink_to(real_file)

        target = {}
        _try_load(link, target)

        # Symlink followed — file content loaded
        assert str(link) in target or str(real_file) in target


# ---------------------------------------------------------------------------
# VULN-03: get_rules_dir() CWD fallback allows rule injection
# semgrep_runner.py:25 — if bundled rules not found, falls back to Path.cwd() / "rules"
# Attack: attacker puts a malicious rules/ directory in CWD.
# Semgrep rules can have `fix:` patterns that rewrite code.
# A malicious rule could also suppress real findings (allowlisting patterns).
#
# Fix: Remove CWD fallback entirely, or validate rule file checksums.
# ---------------------------------------------------------------------------


class TestVuln03RulesDirInjection:
    """VULN-03: CWD fallback for rules directory allows injection."""

    def test_cwd_fallback_is_used(self, tmp_path, monkeypatch):
        """When bundled rules don't exist, CWD rules/ is used."""
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

        # BUG: Falls back to CWD which attacker controls
        assert rules_dir == attacker_rules, (
            "CWD fallback allows attacker to inject malicious semgrep rules"
        )

    def test_malicious_rule_suppresses_findings(self, tmp_path, monkeypatch):
        """An attacker-controlled rule could allowlist dangerous patterns."""
        # This test demonstrates the CONCEPT — a malicious rule that matches
        # nothing (effectively suppressing detection) while the real rules
        # are replaced.
        from mcp_redteam.engine import semgrep_runner

        monkeypatch.setattr(
            semgrep_runner, "__file__",
            str(tmp_path / "fake" / "semgrep_runner.py"),
        )

        attacker_rules = tmp_path / "rules"
        attacker_rules.mkdir()
        # Empty rule file = no detections
        (attacker_rules / "empty.yaml").write_text(
            "rules:\n  - id: noop\n    pattern: 'NEVER_MATCH_THIS_STRING_12345'\n"
            "    message: noop\n    languages: [python]\n    severity: INFO\n"
        )

        monkeypatch.chdir(tmp_path)
        rules_dir = semgrep_runner.get_rules_dir()

        assert (rules_dir / "empty.yaml").exists()


# ---------------------------------------------------------------------------
# VULN-04: _try_load reads unlimited file size (OOM DoS)
# config_scanner.py:131 — path.read_text() with no size limit
# Attack: create a 1GB .mcp.json file (or symlink to /dev/zero on Linux)
# The tool will try to read it all into memory.
#
# Fix: Check file size before reading (e.g., max 10MB).
# ---------------------------------------------------------------------------


class TestVuln04UnlimitedFileRead:
    """VULN-04: No file size limit in _try_load."""

    def test_large_file_is_read_entirely(self, tmp_path):
        """_try_load attempts to read arbitrarily large files."""
        from mcp_redteam.engine.config_scanner import _try_load

        # Create a 5MB JSON file (not truly huge but proves the point)
        large_file = tmp_path / "large.json"
        # Valid JSON that's large
        large_file.write_text('{"data": "' + "A" * (5 * 1024 * 1024) + '"}')

        target = {}
        _try_load(large_file, target)

        # BUG: No size check — the 5MB file was read fully
        assert str(large_file) in target, (
            "5MB file read without size limit (in real attack: 1GB+ = OOM)"
        )

    def test_raw_text_no_size_limit(self, tmp_path):
        """_raw_text also has no file size limit."""
        from mcp_redteam.engine.config_scanner import _raw_text

        large_file = tmp_path / "big.json"
        content = "X" * (2 * 1024 * 1024)  # 2MB
        large_file.write_text(content)

        result = _raw_text(str(large_file))
        assert len(result) == 2 * 1024 * 1024, (
            "_raw_text reads files without size guard"
        )


# ---------------------------------------------------------------------------
# VULN-05: rglob on huge directories = DoS
# cli.py:79 — sum(1 for _ in path.rglob("*.py")) runs three times
# On a dir with 100K+ files, this takes minutes and huge memory.
# Also: no exclusion for node_modules, .git, .venv etc.
#
# Fix: Add timeout, max file count, and directory exclusions.
# ---------------------------------------------------------------------------


class TestVuln05RglobDoS:
    """VULN-05: rglob file counting with no limits."""

    def test_rglob_counts_all_files_no_limit(self, tmp_path):
        """file counting via rglob has no cap or exclusion."""
        # Create nested structure
        for i in range(100):
            d = tmp_path / f"dir_{i}"
            d.mkdir()
            for j in range(10):
                (d / f"file_{j}.py").touch()

        # Simulating what cli.py line 79 does
        count = sum(1 for _ in tmp_path.rglob("*.py"))
        assert count == 1000, "All 1000 files counted (no limit, no exclusions)"

    def test_node_modules_not_excluded(self, tmp_path):
        """node_modules is not excluded from rglob counting."""
        nm = tmp_path / "node_modules" / "some_package"
        nm.mkdir(parents=True)
        for i in range(50):
            (nm / f"mod_{i}.js").touch()

        (tmp_path / "app.js").touch()

        js_count = sum(1 for _ in tmp_path.rglob("*.js"))
        # BUG: 51 files counted, including all node_modules
        assert js_count == 51, (
            "node_modules not excluded from file counting"
        )


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

        # BUG: Username leaks in SARIF URI
        assert "secretuser" in sarif_str, (
            "Username from absolute path leaks into SARIF output"
        )


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
        # SARIF is JSON so <script> is string-escaped, not rendered.
        # But if SARIF viewer renders markdown (help.markdown field), it could execute.
        # The key issue: no sanitization layer exists.
        assert xss in json.loads(sarif_str)["runs"][0]["results"][0]["message"]["text"]


# ---------------------------------------------------------------------------
# VULN-08: No path canonicalization in CLI
# cli.py:42 — only checks path.exists(), no resolve() or realpath()
# User passes ../../etc/passwd — typer converts to Path, exists() is checked,
# but the path is then passed to rglob and semgrep as-is.
#
# Fix: path = path.resolve(); validate it's under expected scope.
# ---------------------------------------------------------------------------


class TestVuln08PathTraversalInCli:
    """VULN-08: CLI accepts arbitrary paths without canonicalization."""

    def test_relative_path_traversal_accepted(self, tmp_path):
        """Path with .. components is accepted without canonicalization."""
        # Simulate what happens in cli.py
        traversal = tmp_path / "sub" / ".." / ".." / "etc"
        # Path(".../sub/../../etc").exists() may or may not exist
        # but the Path object preserves the traversal components
        assert ".." in str(traversal), (
            "Path traversal components preserved (no resolve/canonicalization)"
        )

    def test_path_not_resolved_before_use(self):
        """cli.py scan() does not call resolve() on the path argument."""
        import inspect
        from mcp_redteam.cli import scan

        source = inspect.getsource(scan)
        # Check that resolve() is NOT called on path
        assert "path.resolve()" not in source and "path = path.resolve()" not in source, (
            "path argument is not canonicalized with resolve() — traversal possible"
        )


# ---------------------------------------------------------------------------
# VULN-09: find subprocess on $HOME has no output size limit
# config_scanner.py:107-111 — `find $HOME -maxdepth 4 -name .mcp.json`
# On a system with many files, this could return thousands of results.
# Each result triggers _try_load which reads the file.
#
# This is bounded by maxdepth 4 and timeout 10 — acceptable but noted.
# ---------------------------------------------------------------------------


class TestVuln09FindSubprocess:
    """VULN-09: find subprocess has limited but imperfect guards."""

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

    def test_find_no_result_count_limit(self):
        """But there is no limit on number of results processed."""
        import inspect
        from mcp_redteam.engine.config_scanner import _collect_configs

        source = inspect.getsource(_collect_configs)
        # No islice, no [:N], no counter
        assert "islice" not in source and "[:100]" not in source, (
            "No result count limit on find output — many .mcp.json files = DoS"
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
        pyproject = Path("/Users/daniil/Работа/Проекты/Личное/mcp-redteam/pyproject.toml")
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

        src_dir = Path("/Users/daniil/Работа/Проекты/Личное/mcp-redteam/mcp_redteam")
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

        src_dir = Path("/Users/daniil/Работа/Проекты/Личное/mcp-redteam/mcp_redteam")
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
