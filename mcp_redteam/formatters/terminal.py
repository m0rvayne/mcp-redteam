"""Terminal formatter for mcp-redteam scan results using rich."""

import re

from rich.console import Console
from rich.table import Table
from rich.text import Text

from mcp_redteam.models import Finding, ScanResult, Severity

# Regex to match ANSI escape sequences (CSI and OSC)
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[^[\]()]')


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from user-controlled text."""
    return _ANSI_RE.sub('', text)

# Severity -> (color, style)
_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "yellow",
    Severity.MEDIUM: "cyan",
    Severity.LOW: "dim",
    Severity.INFO: "dim italic",
}


def _severity_text(severity: Severity) -> Text:
    """Create a styled Text object for a severity label."""
    return Text(severity.value, style=_SEVERITY_STYLES[severity])


def _location_str(finding: Finding) -> str:
    """Format location as File:Line string."""
    if not finding.location:
        return "-"
    loc = finding.location
    file_path = _strip_ansi(loc.file)
    if loc.line:
        return f"{file_path}:{loc.line}"
    return file_path


def format_terminal(result: ScanResult, console: Console) -> None:
    """Print scan result to terminal using rich."""
    meta = result.metadata

    # Header
    console.print()
    console.print(
        f"[bold]mcp-redteam[/bold] v{meta.tool_version}  "
        f"[dim]{meta.target_path}[/dim]"
    )
    console.print()

    if not result.findings:
        console.print("[green bold]No findings.[/green bold]")
        console.print()
        return

    # Findings table
    table = Table(
        show_header=True,
        header_style="bold",
        border_style="dim",
        pad_edge=False,
    )
    table.add_column("Severity", width=10, no_wrap=True)
    table.add_column("Rule", width=8, no_wrap=True)
    table.add_column("File:Line", min_width=20)
    table.add_column("Title", min_width=30)

    # Sort: CRITICAL first, then HIGH, etc.
    severity_order = list(Severity)
    sorted_findings = sorted(
        result.findings,
        key=lambda f: severity_order.index(f.severity),
    )

    for finding in sorted_findings:
        rule_id = _strip_ansi(finding.rule_id or finding.id)
        table.add_row(
            _severity_text(finding.severity),
            rule_id,
            _location_str(finding),
            _strip_ansi(finding.title),
        )

    console.print(table)
    console.print()

    # Summary line
    counts: list[str] = []
    crit = result.critical_count
    high = result.high_count
    med = sum(1 for f in result.findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in result.findings if f.severity == Severity.LOW)

    if crit:
        counts.append(f"[bold red]{crit} critical[/bold red]")
    if high:
        counts.append(f"[yellow]{high} high[/yellow]")
    if med:
        counts.append(f"[cyan]{med} medium[/cyan]")
    if low:
        counts.append(f"[dim]{low} low[/dim]")

    summary = ", ".join(counts)
    console.print(
        f"[bold]{result.total_findings} findings[/bold] ({summary})"
    )

    # Risk score
    score = result.risk_score
    if score >= 50:
        score_style = "bold red"
    elif score >= 20:
        score_style = "yellow"
    else:
        score_style = "green"

    console.print(f"Risk score: [{score_style}]{score}/100[/{score_style}]")
    console.print()
