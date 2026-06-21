"""Test output formatters."""
import json
import re
from datetime import datetime
from mcp_redteam.models import Finding, Severity, FindingCategory, ScanResult, ScanMetadata, Location
from mcp_redteam.formatters.sarif import format_sarif
from mcp_redteam.formatters.json_fmt import format_json
from mcp_redteam.formatters.html_fmt import format_html

def _make_result():
    return ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=[
            Finding(
                id="MRT001", title="Shell Injection", severity=Severity.CRITICAL,
                category=FindingCategory.security, description="test", evidence="test",
                location=Location(file="server.py", line=42)
            )
        ]
    )

def test_sarif_valid_json():
    result = _make_result()
    sarif = format_sarif(result)
    data = json.loads(sarif)
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    assert len(data["runs"][0]["results"]) == 1

def test_sarif_has_required_fields():
    result = _make_result()
    data = json.loads(format_sarif(result))
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcp-redteam"
    assert len(run["tool"]["driver"]["rules"]) > 0
    r = run["results"][0]
    assert "ruleId" in r
    assert "message" in r
    assert "locations" in r

def test_json_roundtrip():
    result = _make_result()
    json_str = format_json(result)
    data = json.loads(json_str)
    assert data["metadata"]["tool_name"] == "mcp-redteam"
    assert len(data["findings"]) == 1

def test_empty_result():
    result = ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=[]
    )
    sarif = format_sarif(result)
    data = json.loads(sarif)
    assert len(data["runs"][0]["results"]) == 0


# --- HTML formatter tests ---

def test_html_valid_output():
    """HTML formatter produces valid HTML with required sections."""
    result = _make_result()
    output = format_html(result)
    assert output.startswith("<!DOCTYPE html>")
    assert "<html" in output
    assert "</html>" in output
    assert "mcp-redteam" in output
    assert "Risk Score" in output
    assert "Findings" in output


def test_html_escapes_xss():
    """HTML formatter escapes XSS payloads in all user-controlled fields."""
    xss = '<script>alert("xss")</script>'
    result = ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=[
            Finding(
                id="XSS001", title=xss, severity=Severity.HIGH,
                category=FindingCategory.security, description=xss,
                evidence=xss, location=Location(file="server.py", line=1)
            )
        ]
    )
    output = format_html(result)
    assert "<script>" not in output
    assert "&lt;script&gt;" in output


def test_html_empty_result():
    """HTML formatter handles zero findings gracefully."""
    result = ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=[]
    )
    output = format_html(result)
    assert "No findings" in output


def test_html_details_closed():
    """All <details> elements are closed by default (no open attribute)."""
    result = _make_result()
    output = format_html(result)
    assert "<details " in output or "<details>" in output
    assert "<details open" not in output
