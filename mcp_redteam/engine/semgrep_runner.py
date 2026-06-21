"""Semgrep integration for deterministic MCP security analysis."""

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from mcp_redteam.constants import SEMGREP_TIMEOUT_SECONDS
from mcp_redteam.models import Finding, Severity, FindingCategory, Location, RULE_REGISTRY

logger = logging.getLogger(__name__)


def is_semgrep_available() -> bool:
    """Check if semgrep is installed and accessible."""
    return shutil.which("semgrep") is not None


def get_rules_dir() -> Path:
    """Get the path to our bundled semgrep rules."""
    # Rules are in the project root /rules/ directory
    # When installed via pip, they should be included in package data
    package_dir = Path(__file__).parent.parent
    rules_dir = package_dir.parent / "rules"
    # VULN-03 fix: no CWD fallback — prevents rule substitution attack
    return rules_dir


def run_semgrep(target_path: Path, rules_dir: Optional[Path] = None) -> list[Finding]:
    """
    Run semgrep with MCP-specific rules and return findings.

    Args:
        target_path: Path to scan (file or directory)
        rules_dir: Path to rules directory (defaults to bundled rules)

    Returns:
        List of Finding objects mapped from semgrep results
    """
    try:
        if not is_semgrep_available():
            return []  # Graceful skip — caller should warn user

        if rules_dir is None:
            rules_dir = get_rules_dir()

        if not rules_dir.exists():
            return []

        # Run semgrep with JSON output
        cmd = [
            "semgrep",
            "--config", str(rules_dir),
            "--json",
            "--quiet",  # suppress progress bar
            "--no-git-ignore",  # scan everything
            "--max-target-bytes", "1000000",  # skip files >1MB (binaries, minified JS)
            "--exclude", "*test*",
            "--exclude", "*__tests__*",
            "--exclude", "*spec*",
            "--exclude", "tests",
            "--exclude", "test",
            "--exclude", "fixtures",
            "--exclude", "examples",
            "--exclude", "mocks",
            "--exclude", "node_modules",
            "--exclude", ".venv",
            "--exclude", "__pycache__",
            str(target_path),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=SEMGREP_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            logger.error("Semgrep timed out after %ds on %s", SEMGREP_TIMEOUT_SECONDS, target_path)
            return []
        except FileNotFoundError:
            logger.error("Semgrep binary not found")
            return []

        if not result.stdout:
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.error("Failed to parse semgrep JSON output")
            return []

        return _map_semgrep_results(data)
    except Exception as e:
        logger.error("Semgrep scan failed: %s", e)
        return []


def _map_semgrep_results(data: dict) -> list[Finding]:
    """Map semgrep JSON output to Finding objects."""
    findings = []

    for match in data.get("results", []):
        rule_id = _extract_rule_id(match)
        # Use severity from RULE_REGISTRY if available (more accurate than semgrep mapping)
        if rule_id in RULE_REGISTRY:
            severity = RULE_REGISTRY[rule_id].severity
            category = RULE_REGISTRY[rule_id].category
        else:
            severity = _map_severity(match.get("extra", {}).get("severity", "WARNING"))
            category = _extract_category(match)

        finding = Finding(
            id=rule_id,
            title=_get_rule_title(rule_id, match),
            severity=severity,
            category=category,
            description=match.get("extra", {}).get("message", ""),
            evidence=match.get("extra", {}).get("lines", ""),
            location=Location(
                file=match.get("path", ""),
                line=match.get("start", {}).get("line"),
                end_line=match.get("end", {}).get("line"),
                column=match.get("start", {}).get("col"),
                snippet=match.get("extra", {}).get("lines", ""),
            ),
            confidence=1.0,  # Deterministic = 100% confidence
            source="semgrep",
            rule_id=rule_id,
        )
        findings.append(finding)

    return _deduplicate(findings)


def _extract_rule_id(match: dict) -> str:
    """Extract MRT rule ID from semgrep match metadata."""
    metadata = match.get("extra", {}).get("metadata", {})
    rule_id = metadata.get("rule_id", "")
    if rule_id and rule_id in RULE_REGISTRY:
        return rule_id

    # Fallback: try to derive from check_id
    check_id = match.get("check_id", "")

    # Map semgrep rule IDs to our MRT IDs
    mapping = {
        "shell-injection": "MRT001",
        "command-injection": "MRT001",
        "path-traversal": "MRT002",
        "ssrf": "MRT003",
        "eval": "MRT004",
        "credential": "MRT005",
        "secret": "MRT005",
        "stdout": "MRT006",
        "error-handling": "MRT007",
        "response": "MRT008",
        # New mappings for MRT018-028
        "signal-handler": "MRT018",
        "signal": "MRT018",
        "blocking": "MRT019",
        "sync-call": "MRT019",
        "oauth": "MRT020",
        "overprivilege": "MRT020",
        "env-secret": "MRT021",
        "rotation": "MRT021",
        "no-timeout-http": "MRT022",
        "no-timeout-subprocess": "MRT023",
        "no-timeout-fetch": "MRT024",
        "dangerous-param": "MRT025",
        "missing-error": "MRT026",
        "credential-in-response": "MRT027",
        "no-timeout-spawn": "MRT028",
    }
    for key, mrt_id in mapping.items():
        if key in check_id.lower():
            return mrt_id

    logger.warning("Unmapped semgrep rule: %s", check_id)
    return "MRT000"  # Unknown rule


def _map_severity(semgrep_severity: str) -> Severity:
    """Map semgrep severity to our Severity enum."""
    mapping = {
        "ERROR": Severity.CRITICAL,
        "WARNING": Severity.HIGH,
        "INFO": Severity.MEDIUM,
    }
    return mapping.get(semgrep_severity.upper(), Severity.MEDIUM)


def _extract_category(match: dict) -> FindingCategory:
    """Extract finding category from semgrep metadata."""
    metadata = match.get("extra", {}).get("metadata", {})
    cat = metadata.get("category", "security")
    try:
        return FindingCategory(cat)
    except ValueError:
        return FindingCategory.security


def _get_rule_title(rule_id: str, match: dict) -> str:
    """Get human-readable title for a finding."""
    if rule_id in RULE_REGISTRY:
        return RULE_REGISTRY[rule_id].name
    return match.get("check_id", "Unknown Finding")


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings (same rule + same location)."""
    seen: set[tuple[str, str, int]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (
            f.id,
            f.location.file if f.location else "",
            f.location.line if f.location else 0,
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
