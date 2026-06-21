"""Deterministic MCP config health scanner (Phase 0).

Scans MCP server configurations from all known sources and detects:
- Dead servers (MRT009)
- Scope conflicts (MRT010)
- Credential exposure in configs (MRT011)
- Unpinned supply chain packages (MRT012)
- Dangerous global settings (MRT013, MRT014)
"""

import json
import logging
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Optional

from mcp_redteam.models import (
    Finding,
    FindingCategory,
    Location,
    Severity,
)

# ---------------------------------------------------------------------------
# Credential regex patterns
# ---------------------------------------------------------------------------

SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub token"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (
        r'(?i)(api[_-]?key|token|password|secret)\s*[=:]\s*["\'][^"\']{8,}',
        "Generic secret",
    ),
]

_SECRET_RE = [(re.compile(p), label) for p, label in SECRET_PATTERNS]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known config locations
# ---------------------------------------------------------------------------

_HOME = Path.home()

_KNOWN_CONFIG_PATHS: list[Path] = [
    _HOME / ".claude.json",
    Path(".mcp.json"),
    _HOME / ".claude" / "settings.json",
    _HOME / ".claude" / "settings.local.json",
    _HOME / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_config(project_dir: Optional[str] = None) -> list[Finding]:
    """Run all config health checks. Returns findings.

    Args:
        project_dir: Optional project directory to look for .mcp.json.
                     Defaults to cwd.
    """
    try:
        findings: list[Finding] = []

        configs = _collect_configs(project_dir=project_dir)

        findings.extend(_check_scope_conflicts(configs))
        findings.extend(_check_credential_exposure(configs))
        findings.extend(_check_supply_chain(configs))
        findings.extend(_check_dangerous_settings(configs))
        findings.extend(_check_dead_servers())

        return findings
    except Exception as e:
        logger.error("Config scan failed: %s", e)
        return []


# ---------------------------------------------------------------------------
# Config collection
# ---------------------------------------------------------------------------


def _collect_configs(project_dir: Optional[str] = None) -> dict[str, dict]:
    """Collect all MCP config files from known locations.

    Returns:
        dict mapping absolute path (str) -> parsed JSON content.
    """
    configs: dict[str, dict] = {}

    paths = list(_KNOWN_CONFIG_PATHS)

    # Resolve project-local .mcp.json
    if project_dir:
        paths.append(Path(project_dir) / ".mcp.json")

    for p in paths:
        resolved = p.expanduser().resolve()
        _try_load(resolved, configs)

    # Discover orphaned .mcp.json files under $HOME (max depth 4)
    try:
        result = subprocess.run(
            ["find", str(_HOME), "-maxdepth", "4", "-name", ".mcp.json", "-type", "f"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.strip().splitlines()[:100]:  # VULN-09 fix: cap results
                line = line.strip()
                if line:
                    _try_load(Path(line).resolve(), configs)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass  # graceful skip

    return configs


def _try_load(path: Path, target: dict[str, dict]) -> None:
    """Try to load a JSON file into *target*. Silently skip on any error."""
    key = str(path)
    if key in target:
        return
    try:
        if path.is_symlink():
            return  # VULN-02 fix: don't follow symlinks
        if path.is_file():
            if path.stat().st_size > 10_000_000:  # VULN-04 fix: 10MB max
                return
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                target[key] = data
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_servers(config: dict) -> dict[str, dict]:
    """Extract mcpServers map from a config dict (handles nesting variants)."""
    # claude_desktop_config.json & .claude.json use "mcpServers"
    if "mcpServers" in config:
        servers = config["mcpServers"]
        if isinstance(servers, dict):
            return servers
    # .mcp.json sometimes has bare server definitions at top level
    # Check if values look like server defs (have "command" or "url")
    if all(
        isinstance(v, dict) and ("command" in v or "url" in v)
        for v in config.values()
        if isinstance(v, dict)
    ) and any(isinstance(v, dict) for v in config.values()):
        return {k: v for k, v in config.items() if isinstance(v, dict)}
    return {}


def _raw_text(path: str) -> str:
    """Read file as raw text. Returns '' on error."""
    try:
        p = Path(path)
        if p.stat().st_size > 10_000_000:  # VULN-04 fix: 10MB max
            return ""
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _is_git_tracked(path: str) -> bool:
    """Check if *path* is tracked by git."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "--error-unmatch", path],
            capture_output=True,
            timeout=5,
            cwd=str(Path(path).parent),
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _file_is_world_readable(path: str) -> bool:
    """Check if file permissions include group/other read (broader than 600)."""
    try:
        mode = os.stat(path).st_mode
        return bool(mode & (stat.S_IRGRP | stat.S_IROTH))
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Check: scope conflicts (MRT010)
# ---------------------------------------------------------------------------


def _check_scope_conflicts(configs: dict[str, dict]) -> list[Finding]:
    findings: list[Finding] = []

    # Build mapping: server_name -> [(config_path, server_config)]
    server_map: dict[str, list[tuple[str, dict]]] = {}
    for cfg_path, cfg_data in configs.items():
        for name, srv in _extract_servers(cfg_data).items():
            server_map.setdefault(name, []).append((cfg_path, srv))

    for server_name, entries in server_map.items():
        if len(entries) < 2:
            continue

        # Compare configs pairwise — identical vs conflicting
        configs_json = [json.dumps(e[1], sort_keys=True) for e in entries]
        all_same = len(set(configs_json)) == 1
        paths_str = ", ".join(e[0] for e in entries)

        if all_same:
            findings.append(
                Finding(
                    id="MRT010",
                    rule_id="MRT010",
                    title=f"Redundant config: server '{server_name}' duplicated across scopes",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.config,
                    description=(
                        f"Server '{server_name}' is defined identically in "
                        f"{len(entries)} config files. This is redundant and "
                        "may cause confusion about which scope is active."
                    ),
                    evidence=f"Files: {paths_str}",
                    location=Location(file=entries[0][0]),
                    fix="Remove duplicate definitions, keep only the most appropriate scope.",
                    confidence=1.0,
                    source="config",
                )
            )
        else:
            findings.append(
                Finding(
                    id="MRT010",
                    rule_id="MRT010",
                    title=f"Scope conflict: server '{server_name}' has different configs",
                    severity=Severity.HIGH,
                    category=FindingCategory.config,
                    description=(
                        f"Server '{server_name}' is defined in {len(entries)} "
                        "config files with DIFFERENT settings. The effective "
                        "config depends on scope precedence, which may lead to "
                        "unexpected behavior or security bypass."
                    ),
                    evidence=f"Files: {paths_str}",
                    location=Location(file=entries[0][0]),
                    fix="Consolidate to a single config scope or ensure settings match.",
                    confidence=1.0,
                    source="config",
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Check: credential exposure (MRT011)
# ---------------------------------------------------------------------------


def _check_credential_exposure(configs: dict[str, dict]) -> list[Finding]:
    findings: list[Finding] = []

    for cfg_path, cfg_data in configs.items():
        raw = _raw_text(cfg_path)
        if not raw:
            continue

        matched_secrets: list[str] = []
        for regex, label in _SECRET_RE:
            if regex.search(raw):
                matched_secrets.append(label)

        if not matched_secrets:
            continue

        # Determine severity: git-tracked + secrets = CRITICAL
        git_tracked = _is_git_tracked(cfg_path)
        world_readable = _file_is_world_readable(cfg_path)

        if git_tracked:
            severity = Severity.CRITICAL
            extra = " File is tracked by git — secrets are in version history."
        elif world_readable:
            severity = Severity.HIGH
            extra = " File is world-readable (permissions too broad)."
        else:
            severity = Severity.HIGH
            extra = ""

        findings.append(
            Finding(
                id="MRT011",
                rule_id="MRT011",
                title=f"Credential in config: {cfg_path}",
                severity=severity,
                category=FindingCategory.config,
                description=(
                    f"Detected {len(matched_secrets)} secret pattern(s) in config file: "
                    f"{', '.join(matched_secrets)}.{extra}"
                ),
                evidence=f"Patterns matched: {', '.join(matched_secrets)}",
                location=Location(file=cfg_path),
                fix=(
                    "Move secrets to environment variables or a secrets manager. "
                    "If git-tracked, rotate all exposed credentials immediately."
                ),
                confidence=0.9,
                source="config",
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Check: supply chain — unpinned packages (MRT012)
# ---------------------------------------------------------------------------


def _check_supply_chain(configs: dict[str, dict]) -> list[Finding]:
    findings: list[Finding] = []

    for cfg_path, cfg_data in configs.items():
        for name, srv in _extract_servers(cfg_data).items():
            command = srv.get("command", "")
            args = srv.get("args", [])
            if not isinstance(args, list):
                args = []

            if command not in ("npx", "uvx"):
                continue

            # Find the package argument (first arg that isn't a flag)
            package_arg: Optional[str] = None
            has_prefer_offline = False
            for a in args:
                if a == "--prefer-offline":
                    has_prefer_offline = True
                if not str(a).startswith("-") and package_arg is None:
                    package_arg = str(a)

            if package_arg is None:
                continue

            # Check version pinning
            has_at_latest = "@latest" in package_arg
            # npx: package@version, uvx: package==version or package>=version
            has_version = bool(
                re.search(r"@[\d^~]", package_arg)
                or re.search(r"[=<>!]=", package_arg)
            )

            if has_at_latest or not has_version:
                findings.append(
                    Finding(
                        id="MRT012",
                        rule_id="MRT012",
                        title=f"Unpinned package: {name} ({package_arg})",
                        severity=Severity.HIGH,
                        category=FindingCategory.config,
                        description=(
                            f"Server '{name}' uses {command} with "
                            f"{'@latest' if has_at_latest else 'no version pin'} "
                            f"for package '{package_arg}'. An attacker who compromises "
                            "the package registry can inject malicious code."
                        ),
                        evidence=f"command: {command}, args: {args}",
                        location=Location(file=cfg_path),
                        fix=f"Pin to a specific version, e.g. {package_arg}@<version>",
                        confidence=1.0,
                        source="config",
                    )
                )

            if command == "npx" and not has_prefer_offline:
                findings.append(
                    Finding(
                        id="MRT012",
                        rule_id="MRT012",
                        title=f"No --prefer-offline for npx: {name}",
                        severity=Severity.LOW,
                        category=FindingCategory.config,
                        description=(
                            f"Server '{name}' uses npx without --prefer-offline. "
                            "This means every invocation may fetch from the registry, "
                            "increasing the supply chain attack window."
                        ),
                        evidence=f"command: {command}, args: {args}",
                        location=Location(file=cfg_path),
                        fix="Add --prefer-offline to args.",
                        confidence=1.0,
                        source="config",
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# Check: dangerous settings (MRT013, MRT014)
# ---------------------------------------------------------------------------


def _check_dangerous_settings(configs: dict[str, dict]) -> list[Finding]:
    findings: list[Finding] = []

    for cfg_path, cfg_data in configs.items():
        # MRT013: enableAllProjectMcpServers
        raw = _raw_text(cfg_path)

        if _deep_get(cfg_data, "enableAllProjectMcpServers") is True or (
            "enableAllProjectMcpServers" in raw and "true" in raw
        ):
            findings.append(
                Finding(
                    id="MRT013",
                    rule_id="MRT013",
                    title="Auto-enable all project MCP servers is ON",
                    severity=Severity.CRITICAL,
                    category=FindingCategory.config,
                    description=(
                        "enableAllProjectMcpServers is set to true. "
                        "Any .mcp.json in a cloned repo will auto-start its servers "
                        "without user confirmation. This is CVE-2026-21852."
                    ),
                    evidence=f"File: {cfg_path}",
                    location=Location(file=cfg_path),
                    fix="Set enableAllProjectMcpServers to false in settings.",
                    confidence=1.0,
                    source="config",
                )
            )

        # MRT014: ANTHROPIC_BASE_URL override in any server env
        for name, srv in _extract_servers(cfg_data).items():
            env = srv.get("env", {})
            if not isinstance(env, dict):
                continue
            if "ANTHROPIC_BASE_URL" in env:
                findings.append(
                    Finding(
                        id="MRT014",
                        rule_id="MRT014",
                        title=f"ANTHROPIC_BASE_URL override in server '{name}'",
                        severity=Severity.CRITICAL,
                        category=FindingCategory.config,
                        description=(
                            f"Server '{name}' sets ANTHROPIC_BASE_URL in its env. "
                            "This redirects API traffic to an attacker-controlled "
                            "endpoint, enabling credential theft. CVE-2025-59536."
                        ),
                        evidence="env.ANTHROPIC_BASE_URL is set (value redacted)",
                        location=Location(file=cfg_path),
                        fix="Remove ANTHROPIC_BASE_URL from server env configuration.",
                        confidence=1.0,
                        source="config",
                    )
                )

    return findings


def _deep_get(data: dict, key: str) -> object:
    """Recursively search for *key* in nested dicts."""
    if key in data:
        return data[key]
    for v in data.values():
        if isinstance(v, dict):
            result = _deep_get(v, key)
            if result is not None:
                return result
    return None


# ---------------------------------------------------------------------------
# Check: dead servers (MRT009)
# ---------------------------------------------------------------------------


def _check_dead_servers() -> list[Finding]:
    findings: list[Finding] = []

    try:
        result = subprocess.run(
            ["claude", "mcp", "list"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        # claude CLI not available — skip this check
        return findings

    if result.returncode != 0:
        return findings

    # Parse output lines. Expected format (may vary):
    #   <name>: <status> (type: <type>, ...)
    # or ANSI-colored variants
    for line in result.stdout.splitlines():
        line_clean = _strip_ansi(line).strip()
        if not line_clean:
            continue

        # Try to detect status — look for common patterns
        # e.g. "server-name: Disconnected" or "server-name  not connected"
        name_match = re.match(r"^([^\s:]+)\s*:\s*(.+)", line_clean)
        if not name_match:
            continue

        server_name = name_match.group(1)
        rest = name_match.group(2).lower()

        if "connected" in rest and "not connected" not in rest and "disconnected" not in rest:
            continue  # healthy

        # Any other status is suspicious
        findings.append(
            Finding(
                id="MRT009",
                rule_id="MRT009",
                title=f"Dead server: {server_name}",
                severity=Severity.HIGH,
                category=FindingCategory.config,
                description=(
                    f"Server '{server_name}' is configured but not in Connected state. "
                    f"Status line: {line_clean.strip()}"
                ),
                evidence=line_clean.strip(),
                location=Location(file="claude mcp list"),
                fix="Check server command/args, restart or remove the server.",
                confidence=0.9,
                source="config",
            )
        )

    return findings


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)
