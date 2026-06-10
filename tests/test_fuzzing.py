"""Property-based tests with Hypothesis -- fuzzing inputs."""

import json
from datetime import datetime

import pytest
from hypothesis import given, settings, strategies as st
from hypothesis.strategies import composite

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


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

severity_st = st.sampled_from(list(Severity))
category_st = st.sampled_from(list(FindingCategory))

location_st = st.builds(
    Location,
    file=st.text(min_size=1, max_size=100).filter(lambda s: s.strip() != ""),
    line=st.integers(min_value=1, max_value=100_000),
)

finding_st = st.builds(
    Finding,
    id=st.from_regex(r"MRT[0-9]{3}", fullmatch=True),
    title=st.text(min_size=1, max_size=200),
    severity=severity_st,
    category=category_st,
    description=st.text(max_size=1000),
    evidence=st.text(max_size=500),
    location=st.one_of(st.none(), location_st),
    confidence=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    fix=st.one_of(st.none(), st.text(min_size=1, max_size=200)),
    rule_id=st.one_of(st.none(), st.from_regex(r"MRT[0-9]{3}", fullmatch=True)),
)


def _make_scan_result(findings: list[Finding]) -> ScanResult:
    return ScanResult(
        metadata=ScanMetadata(scan_start=datetime.now(), target_path="."),
        findings=findings,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@given(finding_st)
@settings(max_examples=200)
def test_finding_never_crashes(finding):
    """Any valid Finding must not crash risk_score."""
    score = finding.risk_score
    assert isinstance(score, int)
    assert score >= 0


@given(st.lists(finding_st, min_size=0, max_size=50))
@settings(max_examples=100)
def test_scan_result_never_crashes(findings):
    """ScanResult with arbitrary findings never crashes."""
    result = _make_scan_result(findings)
    assert result.risk_score >= 0
    assert result.risk_score <= 100
    assert result.total_findings == len(findings)
    assert result.critical_count >= 0
    assert result.high_count >= 0


@given(st.lists(finding_st, min_size=0, max_size=20))
@settings(max_examples=50)
def test_sarif_always_valid_json(findings):
    """SARIF output is always valid JSON regardless of input."""
    result = _make_scan_result(findings)
    sarif = format_sarif(result)
    data = json.loads(sarif)  # must not throw
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    assert len(data["runs"][0]["results"]) == len(findings)


@given(st.lists(finding_st, min_size=0, max_size=20))
@settings(max_examples=50)
def test_json_always_valid(findings):
    """JSON output is always valid regardless of input."""
    result = _make_scan_result(findings)
    json_str = format_json(result)
    data = json.loads(json_str)  # must not throw
    assert "findings" in data
    assert len(data["findings"]) == len(findings)


@given(st.text(min_size=0, max_size=5000))
@settings(max_examples=100)
def test_severity_score_never_crashes(text):
    """severity_score with any Severity value never crashes."""
    for s in Severity:
        score = severity_score(s)
        assert isinstance(score, int)
        assert score >= 0


@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=0, max_size=1000))
@settings(max_examples=100)
def test_sarif_handles_any_evidence_text(evidence):
    """SARIF doesn't break on any text in evidence field."""
    finding = Finding(
        id="MRT001",
        title="Test",
        severity=Severity.HIGH,
        category=FindingCategory.security,
        description="test",
        evidence=evidence,
    )
    result = _make_scan_result([finding])
    sarif = format_sarif(result)
    json.loads(sarif)  # must produce valid JSON


@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=0, max_size=1000))
@settings(max_examples=100)
def test_sarif_handles_any_description_text(description):
    """SARIF doesn't break on any text in description field."""
    finding = Finding(
        id="MRT001",
        title="Test",
        severity=Severity.HIGH,
        category=FindingCategory.security,
        description=description,
        evidence="ev",
    )
    result = _make_scan_result([finding])
    sarif = format_sarif(result)
    json.loads(sarif)


@given(st.text(min_size=1, max_size=300).filter(lambda s: s.strip() != ""))
@settings(max_examples=100)
def test_sarif_handles_any_file_path(file_path):
    """SARIF doesn't break on any file path in location."""
    finding = Finding(
        id="MRT001",
        title="Test",
        severity=Severity.HIGH,
        category=FindingCategory.security,
        description="d",
        evidence="e",
        location=Location(file=file_path, line=1),
    )
    result = _make_scan_result([finding])
    sarif = format_sarif(result)
    json.loads(sarif)


@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=200))
@settings(max_examples=100)
def test_json_handles_any_title(title):
    """JSON formatter doesn't break on any title text."""
    finding = Finding(
        id="MRT001",
        title=title,
        severity=Severity.MEDIUM,
        category=FindingCategory.health,
        description="d",
        evidence="e",
    )
    result = _make_scan_result([finding])
    json_str = format_json(result)
    data = json.loads(json_str)
    assert data["findings"][0]["title"] == title


@given(st.floats(min_value=0.0, max_value=1.0, allow_nan=False))
@settings(max_examples=100)
def test_confidence_range(confidence):
    """Any valid confidence [0.0, 1.0] is accepted by Finding."""
    finding = Finding(
        id="MRT001",
        title="Test",
        severity=Severity.HIGH,
        category=FindingCategory.security,
        description="d",
        evidence="e",
        confidence=confidence,
    )
    assert 0.0 <= finding.confidence <= 1.0


@given(
    st.lists(severity_st, min_size=1, max_size=100),
)
@settings(max_examples=50)
def test_risk_score_monotonic_with_findings(severities):
    """Adding findings never decreases risk score (it's a sum, capped at 100)."""
    findings = [
        Finding(
            id="MRT001",
            title=f"F{i}",
            severity=s,
            category=FindingCategory.security,
            description="",
            evidence="",
        )
        for i, s in enumerate(severities)
    ]
    prev_score = 0
    for i in range(1, len(findings) + 1):
        result = _make_scan_result(findings[:i])
        assert result.risk_score >= prev_score
        prev_score = result.risk_score


@given(finding_st)
@settings(max_examples=50)
def test_findings_by_severity_includes_all(finding):
    """Every finding appears in exactly one severity bucket."""
    result = _make_scan_result([finding])
    by_sev = result.findings_by_severity()
    total = sum(len(v) for v in by_sev.values())
    assert total == 1


@given(finding_st)
@settings(max_examples=50)
def test_findings_by_category_includes_all(finding):
    """Every finding appears in exactly one category bucket."""
    result = _make_scan_result([finding])
    by_cat = result.findings_by_category()
    total = sum(len(v) for v in by_cat.values())
    assert total == 1
