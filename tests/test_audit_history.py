"""Tests for audit history JSONL baseline storage and comparison."""

import pytest
from datetime import datetime

from mcp_redteam.models import (
    Finding, Severity, FindingCategory, Location,
    ScanResult, ScanMetadata,
)
from mcp_redteam.engine.audit_history import (
    save_run, load_history, get_previous_run, compare_runs,
    _target_hash, _compact_finding,
)


@pytest.fixture(autouse=True)
def use_tmp_baseline(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "mcp_redteam.engine.audit_history.get_baseline_dir", lambda: tmp_path
    )


def _make_finding(rule_id: str, file: str = "server.py", line: int = 1, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id=rule_id,
        rule_id=rule_id,
        title=f"Test {rule_id}",
        severity=severity,
        category=FindingCategory.security,
        description="test",
        evidence="test evidence",
        location=Location(file=file, line=line),
    )


def _make_result(findings: list[Finding], target: str = "/tmp/test-server") -> ScanResult:
    return ScanResult(
        metadata=ScanMetadata(
            scan_start=datetime(2026, 6, 21, 10, 0, 0),
            scan_end=datetime(2026, 6, 21, 10, 1, 0),
            target_path=target,
            mode="deterministic",
        ),
        findings=findings,
    )


def test_save_and_load_roundtrip(tmp_path):
    findings = [_make_finding("MRT001", "app.py", 10)]
    result = _make_result(findings)
    save_run(result)

    history = load_history("/tmp/test-server")
    assert len(history) == 1

    entry = history[0]
    assert entry["target"] == "/tmp/test-server"
    assert entry["total"] == 1
    assert entry["risk_score"] == 15  # HIGH = 15
    assert len(entry["findings"]) == 1
    assert entry["findings"][0]["rule_id"] == "MRT001"
    assert entry["findings"][0]["file"] == "app.py"
    assert entry["findings"][0]["line"] == 10


def test_target_hash_consistent():
    h1 = _target_hash("/some/path/server")
    h2 = _target_hash("/some/path/server")
    assert h1 == h2
    assert len(h1) == 16


def test_target_hash_different():
    h1 = _target_hash("/path/a")
    h2 = _target_hash("/path/b")
    assert h1 != h2


def test_compare_new_findings():
    previous = {
        "findings": [
            {"rule_id": "MRT001", "file": "a.py", "line": 1, "severity": "HIGH"},
            {"rule_id": "MRT002", "file": "b.py", "line": 2, "severity": "HIGH"},
        ],
        "risk_score": 30,
    }
    current = {
        "findings": [
            {"rule_id": "MRT001", "file": "a.py", "line": 1, "severity": "HIGH"},
            {"rule_id": "MRT002", "file": "b.py", "line": 2, "severity": "HIGH"},
            {"rule_id": "MRT003", "file": "c.py", "line": 3, "severity": "CRITICAL"},
        ],
        "risk_score": 55,
    }
    delta = compare_runs(previous, current)
    assert delta["summary"]["new_count"] == 1
    assert delta["summary"]["confirmed_count"] == 2
    assert delta["summary"]["fixed_count"] == 0
    assert delta["new"][0]["rule_id"] == "MRT003"


def test_compare_fixed_findings():
    previous = {
        "findings": [
            {"rule_id": "MRT001", "file": "a.py", "line": 1, "severity": "HIGH"},
            {"rule_id": "MRT002", "file": "b.py", "line": 2, "severity": "HIGH"},
            {"rule_id": "MRT003", "file": "c.py", "line": 3, "severity": "CRITICAL"},
        ],
        "risk_score": 55,
    }
    current = {
        "findings": [
            {"rule_id": "MRT001", "file": "a.py", "line": 1, "severity": "HIGH"},
            {"rule_id": "MRT002", "file": "b.py", "line": 2, "severity": "HIGH"},
        ],
        "risk_score": 30,
    }
    delta = compare_runs(previous, current)
    assert delta["summary"]["fixed_count"] == 1
    assert delta["summary"]["new_count"] == 0
    assert delta["fixed"][0]["rule_id"] == "MRT003"


def test_compare_confirmed():
    findings = [
        {"rule_id": "MRT001", "file": "a.py", "line": 1, "severity": "HIGH"},
        {"rule_id": "MRT002", "file": "b.py", "line": 2, "severity": "HIGH"},
    ]
    previous = {"findings": findings, "risk_score": 30}
    current = {"findings": findings, "risk_score": 30}
    delta = compare_runs(previous, current)
    assert delta["summary"]["confirmed_count"] == 2
    assert delta["summary"]["new_count"] == 0
    assert delta["summary"]["fixed_count"] == 0


def test_rotation_keeps_last_20(tmp_path):
    target = "/tmp/rotation-test"
    for i in range(25):
        finding = _make_finding(f"MRT{i:03d}", f"file{i}.py", line=i)
        result = _make_result([finding], target=target)
        save_run(result)

    history = load_history(target)
    assert len(history) == 20
    # Should keep the last 20 (runs 5-24)
    assert history[0]["findings"][0]["rule_id"] == "MRT005"
    assert history[-1]["findings"][0]["rule_id"] == "MRT024"


def test_first_run_no_previous(tmp_path):
    findings = [_make_finding("MRT001")]
    result = _make_result(findings, target="/tmp/first-run")
    save_run(result)

    previous = get_previous_run("/tmp/first-run")
    assert previous is None
