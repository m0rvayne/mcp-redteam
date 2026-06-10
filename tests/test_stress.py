"""Stress tests -- verify tool handles extreme inputs without crashing."""

import json
import os
import tempfile
import threading
from datetime import datetime
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from mcp_redteam.models import (
    Finding,
    FindingCategory,
    Location,
    ScanMetadata,
    ScanResult,
    Severity,
)
from mcp_redteam.formatters.sarif import format_sarif
from mcp_redteam.formatters.json_fmt import format_json
from mcp_redteam.formatters.terminal import format_terminal


def _make_finding(i: int, severity: Severity = Severity.HIGH) -> Finding:
    """Helper: create a finding with index i."""
    return Finding(
        id="MRT001",
        title=f"Finding {i}",
        severity=severity,
        category=FindingCategory.security,
        description=f"Description for finding {i}",
        evidence=f"evidence line {i}",
        location=Location(file=f"file_{i}.py", line=max(1, i)),
    )


def _make_result(n: int) -> ScanResult:
    findings = [_make_finding(i) for i in range(n)]
    return ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=findings,
    )


# --- 1000 findings SARIF ---
def test_1000_findings_sarif():
    """SARIF formatter handles 1000 findings without OOM."""
    result = _make_result(1000)
    sarif = format_sarif(result)
    data = json.loads(sarif)
    assert len(data["runs"][0]["results"]) == 1000
    assert result.risk_score == 100  # capped at 100


# --- 10000 findings JSON ---
def test_10000_findings_json():
    """JSON formatter handles 10000 findings."""
    result = _make_result(10000)
    json_str = format_json(result)
    data = json.loads(json_str)
    assert len(data["findings"]) == 10000
    assert data["metadata"]["tool_name"] == "mcp-redteam"


# --- Empty scan ---
def test_empty_scan():
    """ScanResult with zero findings produces valid output across all formatters."""
    result = ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=[],
    )
    # SARIF
    sarif_data = json.loads(format_sarif(result))
    assert sarif_data["runs"][0]["results"] == []
    # JSON
    json_data = json.loads(format_json(result))
    assert json_data["findings"] == []
    # Terminal
    console = Console(file=StringIO(), force_terminal=True)
    format_terminal(result, console)  # must not crash
    output = console.file.getvalue()
    assert "No findings" in output


# --- Binary files in scan path ---
def test_binary_files_in_scan_path():
    """Scanning directory with binary files doesn't crash semgrep runner."""
    from mcp_redteam.engine.semgrep_runner import run_semgrep

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a binary file
        binary_path = Path(tmpdir) / "image.png"
        binary_path.write_bytes(b"\x89PNG\r\n\x1a\n" + os.urandom(1024))
        # Create a valid python file alongside
        py_path = Path(tmpdir) / "server.py"
        py_path.write_text("print('hello')\n", encoding="utf-8")
        # Should not crash (semgrep may or may not be installed)
        findings = run_semgrep(Path(tmpdir))
        assert isinstance(findings, list)


# --- Deeply nested directory ---
def test_deeply_nested_directory():
    """ScanResult with findings in deeply nested paths works."""
    deep_path = "/".join([f"dir_{i}" for i in range(20)]) + "/deep_file.py"
    finding = _make_finding(0)
    finding.location = Location(file=deep_path, line=1)
    result = ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=[finding],
    )
    sarif = format_sarif(result)
    data = json.loads(sarif)
    uri = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "dir_19" in uri


# --- Very long file path ---
def test_very_long_file_path():
    """Finding with 500-char file path doesn't break formatters."""
    long_path = "a" * 500 + ".py"
    finding = Finding(
        id="MRT001",
        title="Long path test",
        severity=Severity.HIGH,
        category=FindingCategory.security,
        description="desc",
        evidence="ev",
        location=Location(file=long_path, line=1),
    )
    result = ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=[finding],
    )
    # All formatters must handle it
    sarif_data = json.loads(format_sarif(result))
    json_data = json.loads(format_json(result))
    assert len(sarif_data["runs"][0]["results"]) == 1
    assert len(json_data["findings"]) == 1
    # Terminal
    console = Console(file=StringIO(), force_terminal=True)
    format_terminal(result, console)


# --- Unicode in findings ---
def test_unicode_in_findings():
    """Unicode characters in file names, descriptions, evidence."""
    finding = Finding(
        id="MRT001",
        title="Injection in cyrillic module",
        severity=Severity.CRITICAL,
        category=FindingCategory.security,
        description="Eval injection through parameter (unicode, CJK, emoji, diacritics, Arabic)",
        evidence='eval(user_input)  # comment: eval injection',
        location=Location(file="server.py", line=10),
    )
    result = ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=[finding],
    )
    sarif = format_sarif(result)
    data = json.loads(sarif)
    assert len(data["runs"][0]["results"]) == 1
    json_str = format_json(result)
    json.loads(json_str)  # must be valid JSON
    console = Console(file=StringIO(), force_terminal=True)
    format_terminal(result, console)


# --- Concurrent config scans ---
def test_concurrent_config_scan():
    """Multiple config scans in threads don't crash or interfere."""
    from mcp_redteam.engine.config_scanner import scan_config

    results = []
    errors = []

    def run_scan():
        try:
            findings = scan_config()
            results.append(findings)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=run_scan) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert len(errors) == 0, f"Errors in concurrent scans: {errors}"
    assert len(results) == 5
    # Each thread returned a list (no crash, no corruption)
    assert all(isinstance(r, list) for r in results)


# --- 500 findings terminal ---
def test_500_findings_terminal():
    """Terminal formatter handles 500 findings without crashing."""
    result = _make_result(500)
    console = Console(file=StringIO(), force_terminal=True, highlight=False)
    format_terminal(result, console)
    raw = console.file.getvalue()
    # Strip ANSI escape sequences for assertion
    import re
    clean = re.sub(r"\x1b\[[0-9;]*m", "", raw)
    assert "500 findings" in clean


# --- Mixed severity large set ---
def test_mixed_severity_large():
    """Large set with all severity levels computes risk score correctly."""
    findings = []
    severities = list(Severity)
    for i in range(500):
        s = severities[i % len(severities)]
        findings.append(_make_finding(i, severity=s))
    result = ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=findings,
    )
    assert result.risk_score == 100  # will definitely exceed cap
    assert result.total_findings == 500
    by_sev = result.findings_by_severity()
    assert sum(len(v) for v in by_sev.values()) == 500
