"""Test Pydantic models."""
from mcp_redteam.models import (
    Finding, Severity, FindingCategory, Location,
    ScanResult, ScanMetadata, severity_score, RULE_REGISTRY
)
from datetime import datetime

def test_severity_scores():
    assert severity_score(Severity.CRITICAL) == 25
    assert severity_score(Severity.HIGH) == 15
    assert severity_score(Severity.MEDIUM) == 5
    assert severity_score(Severity.LOW) == 1
    assert severity_score(Severity.INFO) == 0

def test_finding_creation():
    f = Finding(
        id="MRT001", title="Test", severity=Severity.CRITICAL,
        category=FindingCategory.security, description="test",
        evidence="test evidence"
    )
    assert f.risk_score == 25
    assert f.confidence == 1.0

def test_scan_result_counts():
    findings = [
        Finding(id="MRT001", title="A", severity=Severity.CRITICAL, category=FindingCategory.security, description="", evidence=""),
        Finding(id="MRT002", title="B", severity=Severity.HIGH, category=FindingCategory.security, description="", evidence=""),
        Finding(id="MRT006", title="C", severity=Severity.MEDIUM, category=FindingCategory.health, description="", evidence=""),
    ]
    result = ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=findings
    )
    assert result.total_findings == 3
    assert result.critical_count == 1
    assert result.high_count == 1
    assert result.risk_score == 45  # 25 + 15 + 5

def test_rule_registry():
    assert len(RULE_REGISTRY) == 28
    assert "MRT001" in RULE_REGISTRY
    assert RULE_REGISTRY["MRT001"].name == "Shell Injection"

def test_findings_by_severity():
    findings = [
        Finding(id="MRT001", title="A", severity=Severity.CRITICAL, category=FindingCategory.security, description="", evidence=""),
        Finding(id="MRT002", title="B", severity=Severity.CRITICAL, category=FindingCategory.security, description="", evidence=""),
    ]
    result = ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=findings
    )
    by_sev = result.findings_by_severity()
    assert len(by_sev[Severity.CRITICAL]) == 2
    assert len(by_sev[Severity.HIGH]) == 0
