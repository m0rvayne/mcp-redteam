"""Test output formatters."""
import json
from datetime import datetime
from mcp_redteam.models import Finding, Severity, FindingCategory, ScanResult, ScanMetadata, Location
from mcp_redteam.formatters.sarif import format_sarif
from mcp_redteam.formatters.json_fmt import format_json

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
