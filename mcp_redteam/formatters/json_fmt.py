"""JSON formatter for mcp-redteam scan results."""

from pathlib import Path

from mcp_redteam.models import ScanResult


def format_json(result: ScanResult) -> str:
    """Format scan result as JSON string."""
    return result.model_dump_json(indent=2)


def write_json(result: ScanResult, output_path: Path) -> None:
    """Write JSON to file."""
    output_path.write_text(format_json(result), encoding="utf-8")
