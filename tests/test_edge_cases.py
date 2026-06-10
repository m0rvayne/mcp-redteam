"""Edge case tests -- boundary conditions, malformed input, missing files."""

import json
import os
import tempfile
from datetime import datetime
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
from rich.console import Console

from mcp_redteam.models import (
    Finding,
    FindingCategory,
    Location,
    ScanMetadata,
    ScanResult,
    Severity,
    severity_score,
)
from mcp_redteam.formatters.sarif import format_sarif
from mcp_redteam.formatters.json_fmt import format_json
from mcp_redteam.formatters.terminal import format_terminal
from mcp_redteam.engine.semgrep_runner import run_semgrep, is_semgrep_available
from mcp_redteam.engine.config_scanner import scan_config, _try_load, _check_credential_exposure


# --- Scan non-existent path ---
def test_scan_nonexistent_path():
    """run_semgrep on non-existent path returns empty list, no crash."""
    findings = run_semgrep(Path("/nonexistent/path/that/does/not/exist"))
    assert findings == []


# --- Scan a single file (not directory) ---
def test_scan_file_not_directory():
    """Scanning a single .py file works without crash."""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write("import os\nprint('hello')\n")
        f.flush()
        try:
            findings = run_semgrep(Path(f.name))
            assert isinstance(findings, list)
        finally:
            os.unlink(f.name)


# --- Scan empty file ---
def test_scan_empty_file():
    """Empty .py file doesn't crash semgrep runner."""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write("")
        f.flush()
        try:
            findings = run_semgrep(Path(f.name))
            assert isinstance(findings, list)
        finally:
            os.unlink(f.name)


# --- Scan file with syntax errors ---
def test_scan_syntax_error_file():
    """Python file with syntax errors doesn't crash semgrep runner."""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write("def broken(\n  for in while:\n    +++\n")
        f.flush()
        try:
            findings = run_semgrep(Path(f.name))
            assert isinstance(findings, list)
        finally:
            os.unlink(f.name)


# --- Finding without location ---
def test_finding_without_location():
    """Finding with no location doesn't break SARIF -- gets placeholder."""
    finding = Finding(
        id="MRT001",
        title="No location",
        severity=Severity.HIGH,
        category=FindingCategory.security,
        description="desc",
        evidence="ev",
        location=None,
    )
    result = ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=[finding],
    )
    sarif = format_sarif(result)
    data = json.loads(sarif)
    loc = data["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "unknown"


# --- Finding with optional fields as None ---
def test_finding_with_none_fields():
    """Finding with optional fields as None serializes correctly."""
    finding = Finding(
        id="MRT001",
        title="Minimal finding",
        severity=Severity.LOW,
        category=FindingCategory.health,
        description="",
        evidence="",
        location=None,
        fix=None,
        rule_id=None,
    )
    result = ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=[finding],
    )
    # SARIF
    sarif = format_sarif(result)
    data = json.loads(sarif)
    assert len(data["runs"][0]["results"]) == 1
    # JSON
    json_str = format_json(result)
    data = json.loads(json_str)
    assert data["findings"][0]["fix"] is None
    # Terminal
    console = Console(file=StringIO(), force_terminal=True)
    format_terminal(result, console)


# --- ScanResult with zero findings ---
def test_scan_result_zero_findings():
    """ScanResult with empty findings list has correct properties."""
    result = ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=[],
    )
    assert result.total_findings == 0
    assert result.critical_count == 0
    assert result.high_count == 0
    assert result.risk_score == 0
    by_sev = result.findings_by_severity()
    assert all(len(v) == 0 for v in by_sev.values())
    by_cat = result.findings_by_category()
    assert all(len(v) == 0 for v in by_cat.values())


# --- severity_score for all known severities ---
def test_severity_score_all():
    """severity_score returns correct values for all known severity levels."""
    expected = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 5,
        Severity.LOW: 1,
        Severity.INFO: 0,
    }
    for sev, score in expected.items():
        assert severity_score(sev) == score


# --- SARIF special characters ---
def test_sarif_special_characters():
    """SARIF handles special chars in evidence: quotes, backslashes, newlines, null bytes."""
    special_evidence = 'He said "hello\\world"\nnewline\there\x00null'
    finding = Finding(
        id="MRT001",
        title='Title with "quotes" and \\backslash',
        severity=Severity.HIGH,
        category=FindingCategory.security,
        description='Description\nwith\nnewlines\tand\ttabs',
        evidence=special_evidence,
        location=Location(file="test.py", line=1),
    )
    result = ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=[finding],
    )
    sarif = format_sarif(result)
    data = json.loads(sarif)  # must produce valid JSON
    assert len(data["runs"][0]["results"]) == 1


# --- Config scanner: missing claude CLI ---
def test_config_scanner_missing_claude():
    """Config scanner works gracefully when claude CLI not installed."""
    from mcp_redteam.engine.config_scanner import _check_dead_servers

    with patch("mcp_redteam.engine.config_scanner.subprocess.run", side_effect=FileNotFoundError):
        findings = _check_dead_servers()
        assert findings == []


# --- Config scanner: corrupt JSON ---
def test_config_scanner_corrupt_json():
    """Config scanner handles malformed JSON in config files."""
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        f.write("{corrupt json!!!")
        f.flush()
        try:
            target: dict[str, dict] = {}
            _try_load(Path(f.name), target)
            # Should silently skip -- no entry added
            assert str(Path(f.name).resolve()) not in target or len(target) == 0
        finally:
            os.unlink(f.name)


# --- Semgrep runner timeout ---
def test_semgrep_runner_timeout():
    """Semgrep runner handles timeout gracefully."""
    import subprocess

    with patch(
        "mcp_redteam.engine.semgrep_runner.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="semgrep", timeout=120),
    ):
        with patch("mcp_redteam.engine.semgrep_runner.is_semgrep_available", return_value=True):
            findings = run_semgrep(Path("."))
            assert findings == []


# --- Location with line=None ---
def test_location_line_none():
    """Finding with location but line=None produces valid SARIF (startLine defaults to 1)."""
    finding = Finding(
        id="MRT002",
        title="No line number",
        severity=Severity.MEDIUM,
        category=FindingCategory.security,
        description="d",
        evidence="e",
        location=Location(file="test.py", line=None),
    )
    result = ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=[finding],
    )
    data = json.loads(format_sarif(result))
    region = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 1  # fallback


# --- Finding with low confidence ---
def test_finding_low_confidence():
    """Finding with confidence < 1.0 includes confidence in SARIF properties."""
    finding = Finding(
        id="MRT015",
        title="Behavioral mismatch",
        severity=Severity.HIGH,
        category=FindingCategory.security,
        description="LLM-detected",
        evidence="mismatch",
        confidence=0.7,
    )
    result = ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=[finding],
    )
    data = json.loads(format_sarif(result))
    r = data["runs"][0]["results"][0]
    assert "properties" in r
    assert r["properties"]["confidence"] == 0.7


# --- Finding with fix ---
def test_finding_with_fix_sarif():
    """Finding with fix suggestion includes fixes array in SARIF."""
    finding = Finding(
        id="MRT001",
        title="Shell injection",
        severity=Severity.CRITICAL,
        category=FindingCategory.security,
        description="d",
        evidence="e",
        fix="Use subprocess without shell=True",
    )
    result = ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=[finding],
    )
    data = json.loads(format_sarif(result))
    r = data["runs"][0]["results"][0]
    assert "fixes" in r
    assert r["fixes"][0]["description"]["text"] == "Use subprocess without shell=True"


# --- risk_score capped at 100 ---
def test_risk_score_capped_at_100():
    """Risk score never exceeds 100 even with many critical findings."""
    findings = [
        Finding(
            id="MRT001",
            title=f"Critical {i}",
            severity=Severity.CRITICAL,
            category=FindingCategory.security,
            description="",
            evidence="",
        )
        for i in range(20)
    ]
    result = ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=findings,
    )
    assert result.risk_score == 100  # 20 * 25 = 500, capped at 100


# --- Config scanner credential detection ---
def test_credential_detection_in_config():
    """Config scanner detects secrets in JSON config."""
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        config_data = {
            "mcpServers": {
                "test-server": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {
                        "API_KEY": "sk-abcdefghijklmnopqrstuvwxyz1234567890"
                    },
                }
            }
        }
        json.dump(config_data, f)
        f.flush()
        try:
            configs = {str(Path(f.name).resolve()): config_data}
            findings = _check_credential_exposure(configs)
            assert len(findings) > 0
            assert any(f.id == "MRT011" for f in findings)
        finally:
            os.unlink(f.name)


# --- findings_by_category ---
def test_findings_by_category():
    """findings_by_category groups correctly."""
    findings = [
        Finding(id="MRT001", title="A", severity=Severity.CRITICAL, category=FindingCategory.security, description="", evidence=""),
        Finding(id="MRT009", title="B", severity=Severity.HIGH, category=FindingCategory.config, description="", evidence=""),
        Finding(id="MRT006", title="C", severity=Severity.MEDIUM, category=FindingCategory.health, description="", evidence=""),
    ]
    result = ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=findings,
    )
    by_cat = result.findings_by_category()
    assert len(by_cat[FindingCategory.security]) == 1
    assert len(by_cat[FindingCategory.config]) == 1
    assert len(by_cat[FindingCategory.health]) == 1
