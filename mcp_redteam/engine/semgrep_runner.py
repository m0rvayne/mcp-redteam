"""Semgrep integration for deterministic MCP security analysis."""

import json
import logging
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

from mcp_redteam.constants import (
    SEMGREP_FILE_TIMEOUT_SECONDS,
    SEMGREP_TIMEOUT_SECONDS,
)
from mcp_redteam.models import Finding, Severity, FindingCategory, Location, RULE_REGISTRY

logger = logging.getLogger(__name__)


def is_semgrep_available() -> bool:
    """Check if semgrep is installed and accessible."""
    return shutil.which("semgrep") is not None


def get_rules_dir() -> Path:
    """Locate the bundled semgrep rules directory.

    Candidates are tried in order; every one is anchored to the package location
    or sys.prefix, never to the CWD (VULN-03 — prevents rule substitution):

    1. ``mcp_redteam/rules``            — installed wheel (force-included)
    2. ``<repo root>/rules``            — editable install / git checkout
    3. ``<sys.prefix>/mcp_redteam/rules`` — legacy shared-data wheels (<= 1.0.0)

    Returns the first candidate that exists, else candidate 1 (caller reports
    the miss).
    """
    package_dir = Path(__file__).parent.parent
    candidates = [
        package_dir / "rules",
        package_dir.parent / "rules",
        Path(sys.prefix) / "mcp_redteam" / "rules",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return candidates[0]


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

        if not rules_dir.is_dir():
            logger.error(
                "Semgrep rules not found at %s — code analysis skipped. "
                "This usually means a broken install; reinstall with "
                "'pip install --force-reinstall redteam-mcp'.",
                rules_dir,
            )
            return []

        # Run semgrep with JSON output
        cmd = [
            "semgrep",
            "--config", str(rules_dir),
            "--json",
            "--quiet",  # suppress progress bar
            "--no-git-ignore",  # scan everything
            "--max-target-bytes", "1000000",  # skip files >1MB (binaries, minified JS)
            # Explicit per-file budget: semgrep's 5s default silently drops
            # files under load, so the same target scanned twice gives
            # different answers.
            "--timeout", str(SEMGREP_FILE_TIMEOUT_SECONDS),
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
            "--exclude", "venv",
            "--exclude", "*.venv/*",
            "--exclude", "*/venv/*",
            "--exclude", "site-packages",
            "--exclude", "dist-packages",
            "--exclude", ".tox",
            "--exclude", ".nox",
            "--exclude", ".eggs",
            "--exclude", "build",
            "--exclude", "dist",
            "--exclude", "__pycache__",
            "--exclude", ".git",
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

        _report_skipped(data, target_path)
        findings = _map_semgrep_results(data, target_root=target_path)
        return _classify_by_tool_surface(findings, target_path)
    except Exception as e:
        logger.error("Semgrep scan failed: %s", e)
        return []


# Semgrep redacts `extra.lines` to this string for unauthenticated users, so the
# evidence we would otherwise show is not the code — it is an advert.
_REDACTED_MARKERS = {"requires login", "requires login."}

MAX_EVIDENCE_LINES = 12
MAX_EVIDENCE_CHARS = 2000

# Evidence is read straight from source, so a hardcoded-secret finding would
# otherwise print the secret into the report (and into SARIF, which often lands
# in a shared Security tab). Mask the value, keep the shape.
_SECRET_IN_SOURCE = [
    re.compile(r"(sk-[a-zA-Z0-9_\-]{8})[a-zA-Z0-9_\-]{6,}"),
    re.compile(r"(ghp_[a-zA-Z0-9]{4})[a-zA-Z0-9]{28,}"),
    re.compile(r"(AKIA[0-9A-Z]{4})[0-9A-Z]{8,}"),
    re.compile(
        r"((?i:api[_-]?key|token|password|passwd|secret|bearer)"
        r"\s*[=:]\s*[\"\'])([^\"\']{6,})"
    ),
]


def _redact_secrets(text: str) -> str:
    """Mask credential values in source evidence, preserving surrounding code."""
    for rx in _SECRET_IN_SOURCE:
        text = rx.sub(lambda m: m.group(1) + "\u2026REDACTED", text)
    return text


def _read_source_lines(
    path: str,
    start: Optional[int],
    end: Optional[int],
    target_root: Optional[Path] = None,
) -> str:
    """Read the flagged lines from disk.

    Semgrep only returns the matched source to authenticated users, so relying on
    its `extra.lines` leaves every finding without evidence. The location it
    reports is enough to recover the code ourselves.

    The path comes from semgrep's output rather than from us, so it is
    canonicalized and confined to the scan target — the same resolve() +
    containment check this scanner tells everyone else to apply.
    """
    if not path or not start:
        return ""
    try:
        resolved = Path(path).resolve()
    except (OSError, ValueError):
        return ""

    if target_root is not None:
        try:
            root = target_root.resolve()
            root = root if root.is_dir() else root.parent
            if not resolved.is_relative_to(root):
                logger.warning("Refusing to read evidence outside scan target: %s", resolved)
                return ""
        except (OSError, ValueError):
            return ""

    try:
        with resolved.open(encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return ""

    first = max(start - 1, 0)
    last = min(end or start, first + MAX_EVIDENCE_LINES)
    snippet = "".join(lines[first:last]).rstrip("\n")
    if len(snippet) > MAX_EVIDENCE_CHARS:
        snippet = snippet[:MAX_EVIDENCE_CHARS] + "\u2026"
    return _redact_secrets(snippet)


def _evidence_for(match: dict, target_root: Optional[Path] = None) -> str:
    """Best available evidence: semgrep's own lines, else the file itself."""
    lines = (match.get("extra", {}).get("lines") or "").strip()
    if lines and lines.lower() not in _REDACTED_MARKERS:
        return _redact_secrets(lines)
    return _read_source_lines(
        match.get("path", ""),
        match.get("start", {}).get("line"),
        match.get("end", {}).get("line"),
        target_root,
    )


def _report_skipped(data: dict, target_path: Path) -> None:
    """Warn when semgrep could not analyse part of the target.

    A partial scan otherwise looks exactly like a clean one — the caller sees
    fewer findings and no indication that files were dropped.
    """
    skipped = data.get("paths", {}).get("skipped", []) or []
    timed_out = [s for s in skipped if "timeout" in str(s.get("reason", "")).lower()]
    if timed_out:
        logger.warning(
            "Semgrep timed out on %d file(s) in %s — results are partial. "
            "Raise SEMGREP_FILE_TIMEOUT_SECONDS or scan a smaller target.",
            len(timed_out), target_path,
        )
    errors = data.get("errors", []) or []
    if errors:
        logger.warning("Semgrep reported %d error(s) while scanning %s", len(errors), target_path)


def _map_semgrep_results(data: dict, target_root: Optional[Path] = None) -> list[Finding]:
    """Map semgrep JSON output to Finding objects."""
    findings = []

    for match in data.get("results", []):
        rule_id = _extract_rule_id(match)
        evidence = _evidence_for(match, target_root)
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
            evidence=evidence,
            location=Location(
                file=match.get("path", ""),
                line=match.get("start", {}).get("line"),
                end_line=match.get("end", {}).get("line"),
                column=match.get("start", {}).get("col"),
                snippet=evidence,
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


# ---------------------------------------------------------------------------
# MCP tool surface classification
# ---------------------------------------------------------------------------

# Security findings in code an MCP client cannot reach are not MCP findings.
# They stay in the report — a real bug is worth knowing about — but they must
# not outrank the ones that are actually reachable.
_OFF_SURFACE_SEVERITY = Severity.INFO

_OFF_SURFACE_NOTE = (
    "This file is not reachable from any MCP tool handler (no tool registration, "
    "and not imported by a file that has one), so it is not part of the server's "
    "attack surface. Severity lowered from {original}."
)


def _classify_by_tool_surface(findings: list[Finding], target_path: Path) -> list[Finding]:
    """Mark findings on/off the MCP tool surface and demote the ones off it.

    Left untouched when the target has no tool registrations at all: the target
    is then not a recognisable MCP server, and demoting everything would be
    worse than saying nothing.
    """
    if not findings:
        return findings

    try:
        from mcp_redteam.engine.tool_surface import compute_tool_surface
        surface = compute_tool_surface(target_path)
    except Exception as e:  # never let classification break a scan
        logger.warning("Tool surface detection failed: %s", e)
        return findings

    if surface is None:
        logger.info("No MCP tool registration found — severities left as-is")
        return findings

    for f in findings:
        if not f.location or not f.location.file:
            continue
        try:
            path = Path(f.location.file).resolve()
        except (OSError, ValueError):
            continue

        f.in_tool_surface = path in surface
        if f.in_tool_surface or f.severity == _OFF_SURFACE_SEVERITY:
            continue

        f.original_severity = f.severity
        f.severity = _OFF_SURFACE_SEVERITY
        note = _OFF_SURFACE_NOTE.format(original=f.original_severity.value)
        f.description = f"{f.description}\n\n{note}" if f.description else note

    return findings
