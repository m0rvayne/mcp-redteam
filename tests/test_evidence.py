"""Evidence extraction tests.

These exercise `_map_semgrep_results` with synthetic semgrep output, so they do
not need semgrep installed — unlike test_semgrep.py, which skips without it.
That matters here: the bug these cover (evidence reading "requires login") is
only visible to users who are NOT logged into semgrep.
"""
# ---------------------------------------------------------------------------
# Evidence extraction — semgrep redacts source for unauthenticated users
# ---------------------------------------------------------------------------


def test_evidence_falls_back_to_source_when_semgrep_redacts(tmp_path):
    """`requires login` must never reach a report as evidence.

    Semgrep only returns matched source to logged-in users. Mapping its
    `extra.lines` straight through left every finding with the literal string
    "requires login" where the vulnerable code should be — in the terminal,
    JSON, SARIF, HTML and the GitHub Security tab alike.
    """
    from mcp_redteam.engine.semgrep_runner import _map_semgrep_results

    src = tmp_path / "server.py"
    src.write_text(
        "import subprocess\n"
        "def run(cmd):\n"
        "    subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    data = {"results": [{
        "check_id": "mcp-python-shell-injection",
        "path": str(src),
        "start": {"line": 3, "col": 5},
        "end": {"line": 3},
        "extra": {"lines": "requires login", "message": "shell injection",
                  "metadata": {"rule_id": "MRT001"}},
    }]}

    finding = _map_semgrep_results(data)[0]

    assert "requires login" not in finding.evidence
    assert "subprocess.run(cmd, shell=True)" in finding.evidence
    assert finding.location.snippet == finding.evidence


def test_evidence_prefers_semgrep_lines_when_present(tmp_path):
    """When semgrep does return source, use it rather than re-reading."""
    from mcp_redteam.engine.semgrep_runner import _map_semgrep_results

    src = tmp_path / "server.py"
    src.write_text("actual file content\n", encoding="utf-8")
    data = {"results": [{
        "check_id": "x", "path": str(src),
        "start": {"line": 1}, "end": {"line": 1},
        "extra": {"lines": "lines from semgrep", "message": "m",
                  "metadata": {"rule_id": "MRT001"}},
    }]}

    assert _map_semgrep_results(data)[0].evidence == "lines from semgrep"


def test_evidence_survives_a_missing_file(tmp_path):
    """A deleted or unreadable target must not crash the mapper."""
    from mcp_redteam.engine.semgrep_runner import _map_semgrep_results

    data = {"results": [{
        "check_id": "x", "path": str(tmp_path / "gone.py"),
        "start": {"line": 3}, "end": {"line": 3},
        "extra": {"lines": "requires login", "message": "m",
                  "metadata": {"rule_id": "MRT001"}},
    }]}

    finding = _map_semgrep_results(data)[0]
    assert finding.evidence == ""


def test_source_evidence_masks_credentials(tmp_path):
    """Reading evidence from source must not print secrets into the report.

    MRT005 flags hardcoded secrets, so its evidence line contains one by
    definition — and SARIF often ends up in a shared Security tab.
    """
    from mcp_redteam.engine.semgrep_runner import _map_semgrep_results

    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"
    src = tmp_path / "conf.py"
    src.write_text(f'API_KEY = "{secret}"\n', encoding="utf-8")
    data = {"results": [{
        "check_id": "mcp-python-credential-in-code", "path": str(src),
        "start": {"line": 1}, "end": {"line": 1},
        "extra": {"lines": "requires login", "message": "secret",
                  "metadata": {"rule_id": "MRT005"}},
    }]}

    evidence = _map_semgrep_results(data)[0].evidence
    assert secret not in evidence
    assert "REDACTED" in evidence
    assert "API_KEY" in evidence, "the code shape must survive redaction"


def test_evidence_is_bounded(tmp_path):
    """A huge match must not blow up the report."""
    from mcp_redteam.engine.semgrep_runner import (
        _map_semgrep_results, MAX_EVIDENCE_CHARS,
    )

    src = tmp_path / "big.py"
    src.write_text("x = 1  # " + ("y" * 200) + "\n" * 500, encoding="utf-8")
    data = {"results": [{
        "check_id": "x", "path": str(src),
        "start": {"line": 1}, "end": {"line": 400},
        "extra": {"lines": "requires login", "message": "m",
                  "metadata": {"rule_id": "MRT001"}},
    }]}

    assert len(_map_semgrep_results(data)[0].evidence) <= MAX_EVIDENCE_CHARS + 1


def test_evidence_refuses_paths_outside_the_scan_target(tmp_path):
    """Evidence paths come from semgrep's output, not from us — confine them.

    This is the resolve() + containment check the scanner recommends to every
    server it audits; its own evidence reader has to pass it too.
    """
    from mcp_redteam.engine.semgrep_runner import _map_semgrep_results

    target = tmp_path / "project"
    target.mkdir()
    (target / "ok.py").write_text("inside = 1\n", encoding="utf-8")

    outside = tmp_path / "secret.txt"
    outside.write_text("TOP SECRET\n", encoding="utf-8")

    def result(path):
        return {"check_id": "x", "path": str(path),
                "start": {"line": 1}, "end": {"line": 1},
                "extra": {"lines": "requires login", "message": "m",
                          "metadata": {"rule_id": "MRT001"}}}

    findings = _map_semgrep_results(
        {"results": [result(target / "ok.py"), result(outside)]},
        target_root=target,
    )

    assert "inside = 1" in findings[0].evidence
    assert findings[1].evidence == "", "read a file outside the scan target"
    assert "TOP SECRET" not in findings[1].evidence


def test_traversal_path_from_semgrep_output_is_contained(tmp_path):
    """A ../ path in semgrep output must not escape the scan target."""
    from mcp_redteam.engine.semgrep_runner import _map_semgrep_results

    target = tmp_path / "project"
    target.mkdir()
    (tmp_path / "outside.py").write_text("leaked = 1\n", encoding="utf-8")

    findings = _map_semgrep_results(
        {"results": [{"check_id": "x", "path": str(target / ".." / "outside.py"),
                      "start": {"line": 1}, "end": {"line": 1},
                      "extra": {"lines": "requires login", "message": "m",
                                "metadata": {"rule_id": "MRT001"}}}]},
        target_root=target,
    )

    assert findings[0].evidence == ""
    assert "leaked" not in findings[0].evidence


# ---------------------------------------------------------------------------
# Partial scans must announce themselves
# ---------------------------------------------------------------------------


def test_timed_out_files_are_reported(caplog):
    """A partial scan otherwise looks exactly like a clean one.

    Semgrep's default per-file budget is 5s, so under load it silently drops
    files — the same target scanned twice gave 738 and 887 findings before this
    was surfaced.
    """
    import logging
    from mcp_redteam.engine.semgrep_runner import _report_skipped
    from pathlib import Path

    data = {"paths": {"skipped": [
        {"path": "a.py", "reason": "timeout"},
        {"path": "b.py", "reason": "excluded_by_config"},
    ]}}

    with caplog.at_level(logging.WARNING):
        _report_skipped(data, Path("/target"))

    assert "timed out on 1 file" in caplog.text
    assert "partial" in caplog.text


def test_semgrep_errors_are_reported(caplog):
    import logging
    from mcp_redteam.engine.semgrep_runner import _report_skipped
    from pathlib import Path

    with caplog.at_level(logging.WARNING):
        _report_skipped({"errors": [{"type": "x"}, {"type": "y"}]}, Path("/t"))

    assert "2 error(s)" in caplog.text


def test_clean_scan_reports_nothing(caplog):
    import logging
    from mcp_redteam.engine.semgrep_runner import _report_skipped
    from pathlib import Path

    with caplog.at_level(logging.WARNING):
        _report_skipped({"paths": {"skipped": []}, "errors": []}, Path("/t"))

    assert caplog.text == ""


def test_per_file_timeout_is_explicit():
    """Relying on semgrep's default makes results depend on machine load."""
    import inspect
    from mcp_redteam.engine import semgrep_runner

    src = inspect.getsource(semgrep_runner.run_semgrep)
    assert '"--timeout"' in src, "per-file timeout must be passed explicitly"
