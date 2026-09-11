"""Test Semgrep rules against known fixtures."""
import pytest
from pathlib import Path
from mcp_redteam.engine.semgrep_runner import run_semgrep, is_semgrep_available

FIXTURES_DIR = Path(__file__).parent / "fixtures"
RULES_DIR = Path(__file__).parent.parent / "rules"

pytestmark = pytest.mark.skipif(not is_semgrep_available(), reason="semgrep not installed")

# Parametrize over vulnerable fixtures
@pytest.mark.parametrize("fixture_file,expected_rules", [
    # Python fixtures
    ("vulnerable/shell_injection.py", ["MRT001"]),
    ("vulnerable/path_traversal.py", ["MRT002"]),
    ("vulnerable/ssrf.py", ["MRT003"]),
    ("vulnerable/eval_injection.py", ["MRT004"]),
    ("vulnerable/secrets_in_code.py", ["MRT005"]),
    ("vulnerable/stdout_pollution.py", ["MRT006"]),
    # MRT007 (missing error handling) and MRT008 (credential in response) may be harder for semgrep
    # JavaScript fixtures
    ("vulnerable/command_injection.js", ["MRT001"]),
    ("vulnerable/path_traversal.js", ["MRT002"]),
    ("vulnerable/ssrf.js", ["MRT003"]),
    ("vulnerable/eval_injection.js", ["MRT004"]),
    ("vulnerable/secrets_in_code.js", ["MRT005"]),
    ("vulnerable/dangerous_params.js", ["MRT025"]),
    ("vulnerable/credential_in_response.js", ["MRT027"]),
])
def test_vulnerable_detected(fixture_file, expected_rules):
    """Each vulnerable fixture must trigger its expected rule."""
    path = FIXTURES_DIR / fixture_file
    findings = run_semgrep(path, RULES_DIR)
    found_rules = {f.id for f in findings}
    for rule in expected_rules:
        assert rule in found_rules, f"Expected {rule} in {fixture_file}, got {found_rules}"

# Parametrize over benign fixtures
@pytest.mark.parametrize("fixture_file", [
    "benign/calculator.py",
    "benign/weather_api.py",
    "benign/file_reader_safe.py",
    "benign/echo_server.py",
    "benign/safe_server.js",
    "benign/config_paths.py",
    "benign/url_param_dict_get.py",
])
def test_benign_no_critical(fixture_file):
    """Benign fixtures must not trigger CRITICAL or HIGH findings.

    Judged on the severity the RULE produced, before any tool-surface demotion.
    A fixture that sits off the surface would otherwise have its findings
    lowered to INFO and pass this test while the false positive is still there.
    """
    path = FIXTURES_DIR / fixture_file
    findings = run_semgrep(path, RULES_DIR)
    critical_high = [
        f for f in findings
        if (f.original_severity or f.severity).value in ("CRITICAL", "HIGH")
    ]
    assert len(critical_high) == 0, f"False positive in {fixture_file}: {[f.id for f in critical_high]}"


# INFO/MEDIUM severity JS rules — tested separately from CRITICAL/HIGH
@pytest.mark.parametrize("fixture_file,expected_rules", [
    ("vulnerable/stdout_pollution.js", ["MRT006"]),
    ("vulnerable/missing_error_handling.js", ["MRT026"]),
    ("vulnerable/no_timeout_fetch.js", ["MRT024"]),
    ("vulnerable/no_timeout_spawn.js", ["MRT028"]),
])
def test_info_medium_detected(fixture_file, expected_rules):
    """Fixtures for INFO/MEDIUM severity rules must trigger their expected rule."""
    path = FIXTURES_DIR / fixture_file
    findings = run_semgrep(path, RULES_DIR)
    found_rules = {f.id for f in findings}
    for rule in expected_rules:
        assert rule in found_rules, f"Expected {rule} in {fixture_file}, got {found_rules}"


def test_ssrf_detected_regardless_of_client_variable_name():
    """Every SSRF in the fixture must be found, not just one of them.

    Regression guard: narrowing MRT003 with a name allowlist on the receiver
    cut detection from 8/8 to 3/8 while removing only 2 false positives. The
    parametrized test above cannot catch that — it only asserts the rule fires
    somewhere in the file. This one counts.
    """
    path = FIXTURES_DIR / "vulnerable" / "ssrf_client_names.py"
    findings = run_semgrep(path, RULES_DIR)
    ssrf_lines = {f.location.line for f in findings if f.id == "MRT003"}
    # detection is what is under test here, not severity after demotion

    expected = len([
        line for line in path.read_text(encoding="utf-8").splitlines()
        if ".get(url)" in line or ".post(url," in line
    ])
    assert len(ssrf_lines) == expected, (
        f"detected {len(ssrf_lines)} of {expected} SSRF sinks — a client variable "
        f"name must not determine whether SSRF is found. Found at lines: {sorted(ssrf_lines)}"
    )
