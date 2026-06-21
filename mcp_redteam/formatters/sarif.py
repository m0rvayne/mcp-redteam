"""SARIF 2.1.0 formatter for mcp-redteam scan results.

Generates valid SARIF JSON for upload to GitHub Security tab (Code Scanning alerts).
"""

import html
import json
import os
from pathlib import Path
from typing import Any

from mcp_redteam.models import (
    Finding,
    Rule,
    RULE_REGISTRY,
    ScanResult,
    Severity,
)

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_INFORMATION_URI = "https://github.com/m0rvayne/mcp-redteam"

# Severity -> SARIF level mapping
_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# Severity -> SARIF problem.severity (GitHub-specific property)
_SEVERITY_TO_PROBLEM: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "recommendation",
    Severity.INFO: "recommendation",
}


def _resolve_rule_id(finding: Finding) -> str:
    """Get the effective rule ID for a finding."""
    return finding.rule_id or finding.id


def _build_rule(rule_id: str, finding: Finding) -> dict[str, Any]:
    """Build a SARIF rule descriptor from a finding's rule_id."""
    registry_rule: Rule | None = RULE_REGISTRY.get(rule_id)

    if registry_rule:
        name = registry_rule.name
        description = registry_rule.description
        severity = registry_rule.severity
    else:
        name = finding.title
        description = finding.description
        severity = finding.severity

    return {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": name},
        "fullDescription": {"text": description},
        "help": {
            "text": description,
            "markdown": f"**{name}**\n\n{description}",
        },
        "properties": {
            "problem": {
                "severity": _SEVERITY_TO_PROBLEM[severity],
            },
            "tags": sorted(set([finding.category.value, "security"])),
        },
    }


def _build_result(finding: Finding) -> dict[str, Any]:
    """Build a SARIF result entry from a Finding."""
    rule_id = _resolve_rule_id(finding)
    level = _SEVERITY_TO_LEVEL[finding.severity]

    # VULN-07 fix: sanitize to prevent XSS if SARIF rendered in HTML viewer
    message_parts = [html.escape(finding.title)]
    if finding.description and finding.description != finding.title:
        message_parts.append(html.escape(finding.description))
    if finding.evidence:
        message_parts.append(f"Evidence: {html.escape(finding.evidence)}")

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": "\n\n".join(message_parts)},
    }

    # Location (required by GitHub — provide a fallback)
    if finding.location:
        loc = finding.location
        # VULN-06 fix: make paths relative to avoid PII (username) leak
        try:
            uri = os.path.relpath(loc.file)
        except ValueError:
            uri = loc.file.lstrip("/")
        region: dict[str, Any] = {"startLine": loc.line or 1}
        if loc.end_line:
            region["endLine"] = loc.end_line
        if loc.column:
            region["startColumn"] = loc.column

        physical: dict[str, Any] = {
            "artifactLocation": {"uri": uri},
            "region": region,
        }

        if loc.snippet:
            physical["region"]["snippet"] = {"text": loc.snippet}

        result["locations"] = [{"physicalLocation": physical}]
    else:
        # GitHub requires at least one location — use a placeholder
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "unknown"},
                    "region": {"startLine": 1},
                }
            }
        ]

    # Confidence as a property
    if finding.confidence < 1.0:
        result["properties"] = {"confidence": finding.confidence}

    # Fix suggestion
    if finding.fix:
        result["fixes"] = [
            {
                "description": {"text": finding.fix},
            }
        ]

    return result


def _build_sarif(result: ScanResult) -> dict[str, Any]:
    """Build the complete SARIF 2.1.0 document."""
    # Collect unique rules from findings
    seen_rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in result.findings:
        rule_id = _resolve_rule_id(finding)
        if rule_id not in seen_rules:
            seen_rules[rule_id] = _build_rule(rule_id, finding)
        results.append(_build_result(finding))

    # Stable rule ordering
    rules = [seen_rules[rid] for rid in sorted(seen_rules)]

    # Build the rule index map for ruleIndex references
    rule_index_map = {r["id"]: i for i, r in enumerate(rules)}
    for r in results:
        if r["ruleId"] in rule_index_map:
            r["ruleIndex"] = rule_index_map[r["ruleId"]]

    meta = result.metadata

    sarif: dict[str, Any] = {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": meta.tool_name,
                        "version": meta.tool_version,
                        "informationUri": TOOL_INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": meta.scan_start.isoformat() + "Z"
                        if meta.scan_start.tzinfo is None
                        else meta.scan_start.isoformat(),
                        **(
                            {
                                "endTimeUtc": meta.scan_end.isoformat() + "Z"
                                if meta.scan_end.tzinfo is None
                                else meta.scan_end.isoformat()
                            }
                            if meta.scan_end
                            else {}
                        ),
                    }
                ],
            }
        ],
    }

    return sarif


def format_sarif(result: ScanResult) -> str:
    """Format scan result as SARIF 2.1.0 JSON string."""
    sarif = _build_sarif(result)
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def write_sarif(result: ScanResult, output_path: Path) -> None:
    """Write SARIF to file."""
    output_path.write_text(format_sarif(result), encoding="utf-8")
