"""LLM behavioral analysis for MCP servers — semantic mismatch, hidden ops, credential mishandling."""

import json
import os
import re
from pathlib import Path
from typing import Optional

from mcp_redteam.models import Finding, Severity, FindingCategory, Location


# Supported source file extensions
_SOURCE_EXTENSIONS = {".py", ".ts", ".js", ".mjs", ".mts", ".jsx", ".tsx"}

# LLM analysis rule IDs (MRT015+)
_LLM_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

_ANALYSIS_PROMPT = """You are a security auditor for MCP (Model Context Protocol) servers.
Analyze the source code below for security vulnerabilities specific to MCP servers.

SOURCE CODE:
{source_code}

{descriptions_block}

Find the following categories of issues:

1. **BEHAVIORAL MISMATCH** (rule MRT015): Tool description says one thing but the code does something different or additional.
   Examples: description says "read file" but code also writes; description says "local only" but code makes HTTP requests.

2. **HIDDEN OPERATIONS** (rule MRT015): Code performs network requests, file writes, subprocess calls, or data exfiltration not declared in tool descriptions.
   Examples: tool sends data to external endpoint; tool writes to files outside declared scope; tool spawns hidden subprocesses.

3. **CREDENTIAL MISHANDLING** (rule MRT015): Secrets logged, leaked in error messages, stored insecurely, or returned in tool responses.
   Examples: API key in log output; password in exception message; token stored in plaintext file.

For each finding, respond with a JSON array. Each element:
{{"rule":"MRT015","title":"short title","severity":"CRITICAL|HIGH|MEDIUM|LOW","category":"security","file":"filename.py","line":42,"evidence":"specific code snippet or reference","description":"what the issue is and why it matters","fix":"how to fix it","confidence":0.85}}

Rules:
- Only report findings you are confident about (confidence > 0.7).
- Do not speculate or invent issues that aren't clearly present in the code.
- If nothing found, respond with exactly: []
- Respond ONLY with the JSON array, no markdown fences, no commentary."""


def is_llm_available() -> bool:
    """Check if anthropic SDK is installed and API key is set."""
    try:
        import anthropic  # noqa: F401
        return bool(os.environ.get("ANTHROPIC_API_KEY"))
    except ImportError:
        return False


def analyze_behavioral(
    source_path: Path,
    tool_descriptions: Optional[dict] = None,
) -> list[Finding]:
    """
    Run LLM behavioral analysis on MCP server source code.

    Analyzes:
    1. Behavioral mismatch: does code match what tool descriptions claim?
    2. Hidden operations: does code do things not declared in descriptions?
    3. Credential handling: are secrets properly managed?

    Returns findings with confidence < 1.0 (LLM-based, not deterministic).
    Returns empty list if API key missing, SDK not installed, or on any error.
    """
    if not is_llm_available():
        return []

    import anthropic

    client = anthropic.Anthropic()

    # Read source files
    source_code = _read_source_files(source_path)
    if not source_code:
        return []

    # Build descriptions block
    descriptions_block = ""
    if tool_descriptions:
        desc_text = json.dumps(tool_descriptions, indent=2, ensure_ascii=False)
        descriptions_block = f"TOOL DESCRIPTIONS (from MCP manifest):\n{desc_text}\n"

    # Run analysis
    findings = _analyze_with_llm(client, source_code, descriptions_block)

    return findings


def _read_source_files(path: Path, max_chars: int = 50_000) -> str:
    """
    Read source files from path, respecting size limit.

    If path is a file, reads that file.
    If path is a directory, collects all source files recursively.
    Each file is prefixed with a header comment showing the filename.
    """
    collected: list[str] = []
    total_chars = 0

    if path.is_file():
        files = [path]
    elif path.is_dir():
        files = sorted(
            f for f in path.rglob("*")
            if f.is_file()
            and f.suffix in _SOURCE_EXTENSIONS
            and "node_modules" not in f.parts
            and ".venv" not in f.parts
            and "__pycache__" not in f.parts
            and ".git" not in f.parts
        )
    else:
        return ""

    for file in files:
        try:
            content = file.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            continue

        # Build header
        try:
            relative = file.relative_to(path)
        except ValueError:
            relative = file.name
        header = f"\n# === FILE: {relative} ===\n"

        chunk = header + content
        if total_chars + len(chunk) > max_chars:
            # Add as much as fits
            remaining = max_chars - total_chars
            if remaining > len(header) + 100:  # at least some useful content
                collected.append(chunk[:remaining])
            break
        collected.append(chunk)
        total_chars += len(chunk)

    return "".join(collected)


def _analyze_with_llm(
    client,
    source_code: str,
    descriptions_block: str,
) -> list[Finding]:
    """Send source code to Claude for behavioral analysis."""
    prompt = _ANALYSIS_PROMPT.format(
        source_code=source_code,
        descriptions_block=descriptions_block,
    )

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2000,
            temperature=0,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception:
        # API error, rate limit, network — fail gracefully
        return []

    if not response.content:
        return []

    return _parse_llm_findings(response.content[0].text)


def _parse_llm_findings(text: str) -> list[Finding]:
    """Parse LLM JSON response into Finding objects. Graceful on bad input."""
    # Try to extract JSON array from response
    text = text.strip()

    # Strip markdown fences if LLM added them despite instructions
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    text = text.strip()

    if not text or text == "[]":
        return []

    try:
        raw_findings = json.loads(text)
    except json.JSONDecodeError:
        # Try to find JSON array in the text
        match = re.search(r"\[.*\]", text, re.DOTALL)
        if not match:
            return []
        try:
            raw_findings = json.loads(match.group())
        except json.JSONDecodeError:
            return []

    if not isinstance(raw_findings, list):
        return []

    findings: list[Finding] = []
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        try:
            severity_str = item.get("severity", "MEDIUM").upper()
            severity = _LLM_SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

            confidence = float(item.get("confidence", 0.8))
            # Clamp confidence: LLM findings are never 1.0
            confidence = max(0.1, min(0.95, confidence))

            category_str = item.get("category", "security")
            try:
                category = FindingCategory(category_str)
            except ValueError:
                category = FindingCategory.security

            location = None
            if item.get("file"):
                location = Location(
                    file=item["file"],
                    line=item.get("line"),
                    snippet=item.get("evidence"),
                )

            finding = Finding(
                id=item.get("rule", "MRT015"),
                title=item.get("title", "LLM-detected issue"),
                severity=severity,
                category=category,
                description=item.get("description", item.get("evidence", "")),
                evidence=item.get("evidence", ""),
                location=location,
                fix=item.get("fix"),
                confidence=confidence,
                source="llm",
            )
            findings.append(finding)
        except (ValueError, TypeError, KeyError):
            # Skip malformed findings
            continue

    return findings
