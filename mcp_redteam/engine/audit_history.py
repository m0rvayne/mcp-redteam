"""Audit history -- JSONL baseline storage with cross-run comparison."""

import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional

from mcp_redteam.models import ScanResult, Finding


def get_baseline_dir() -> Path:
    """Get or create baseline storage directory."""
    d = Path.home() / ".mcp-redteam" / "baselines"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _target_hash(target: str) -> str:
    """Hash target path for filename. First 16 chars of SHA256."""
    return hashlib.sha256(target.encode()).hexdigest()[:16]


def _finding_key(f) -> tuple:
    """Unique key for a finding: (rule_id, file, line)."""
    rule = f.get("rule_id") or f.get("id", "")
    file = f.get("file", "")
    line = f.get("line", 0)
    return (rule, file, line)


def _compact_finding(f: Finding) -> dict:
    """Compact a Finding to minimal JSONL representation."""
    return {
        "id": f.id,
        "rule_id": f.rule_id or f.id,
        "file": f.location.file if f.location else "",
        "line": f.location.line if f.location and f.location.line else 0,
        "severity": f.severity.value,
    }


def save_run(result: ScanResult) -> Path:
    """Save scan result to JSONL baseline. Returns path to baseline file."""
    target = result.metadata.target_path
    baseline_dir = get_baseline_dir()
    filepath = baseline_dir / f"{_target_hash(target)}.jsonl"

    entry = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "mode": result.metadata.mode,
        "findings": [_compact_finding(f) for f in result.findings],
        "total": result.total_findings,
        "risk_score": result.risk_score,
    }

    with open(filepath, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    # Rotate: keep last 20 runs
    _rotate(filepath, max_runs=20)

    return filepath


def load_history(target: str) -> list[dict]:
    """Load all previous runs for a target. Returns list of run dicts, newest last."""
    baseline_dir = get_baseline_dir()
    filepath = baseline_dir / f"{_target_hash(target)}.jsonl"

    if not filepath.exists():
        return []

    runs = []
    for line in filepath.read_text(encoding="utf-8").strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            runs.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # skip corrupt lines

    return runs


def get_previous_run(target: str) -> Optional[dict]:
    """Get the most recent previous run for a target."""
    history = load_history(target)
    # Return second-to-last (last is current run we just saved)
    if len(history) >= 2:
        return history[-2]
    return None


def compare_runs(previous: dict, current: dict) -> dict:
    """Compare two runs and classify findings.

    Returns:
        {"new": [...], "confirmed": [...], "fixed": [...], "summary": {...}}
    """
    prev_keys = {_finding_key(f) for f in previous.get("findings", [])}
    curr_keys = {_finding_key(f) for f in current.get("findings", [])}

    curr_findings_map = {_finding_key(f): f for f in current.get("findings", [])}
    prev_findings_map = {_finding_key(f): f for f in previous.get("findings", [])}

    new_keys = curr_keys - prev_keys
    confirmed_keys = curr_keys & prev_keys
    fixed_keys = prev_keys - curr_keys

    return {
        "new": [curr_findings_map[k] for k in new_keys],
        "confirmed": [curr_findings_map[k] for k in confirmed_keys],
        "fixed": [prev_findings_map[k] for k in fixed_keys],
        "summary": {
            "new_count": len(new_keys),
            "confirmed_count": len(confirmed_keys),
            "fixed_count": len(fixed_keys),
            "prev_risk_score": previous.get("risk_score", 0),
            "curr_risk_score": current.get("risk_score", 0),
        },
    }


def _rotate(filepath: Path, max_runs: int = 20) -> None:
    """Keep only the last N runs in a JSONL file."""
    lines = filepath.read_text(encoding="utf-8").strip().splitlines()
    if len(lines) <= max_runs:
        return
    # Keep last max_runs lines
    filepath.write_text("\n".join(lines[-max_runs:]) + "\n", encoding="utf-8")
