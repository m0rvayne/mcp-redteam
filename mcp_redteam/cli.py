import sys
import typer
from rich.console import Console
from pathlib import Path
from typing import Optional
from enum import Enum
from datetime import datetime

app = typer.Typer(
    name="mcp-redteam",
    help="MCP server security auditor — deterministic engine + AI-native behavioral analysis",
    no_args_is_help=True,
)
console = Console()


class OutputFormat(str, Enum):
    terminal = "terminal"
    json = "json"
    sarif = "sarif"


@app.command()
def scan(
    path: Path = typer.Argument(..., help="Path to MCP server source code"),
    format: OutputFormat = typer.Option(OutputFormat.terminal, "--format", "-f", help="Output format"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Deterministic checks only (no LLM)"),
    config: bool = typer.Option(True, "--config/--no-config", help="Run config health checks"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit 1 if findings at this severity or above (critical, high)"),
):
    """Scan MCP server for security vulnerabilities."""
    from mcp_redteam.models import ScanResult, ScanMetadata, Severity
    from mcp_redteam.engine.semgrep_runner import run_semgrep, is_semgrep_available
    from mcp_redteam.engine.config_scanner import scan_config
    from mcp_redteam.formatters import format_sarif, format_json, format_terminal
    from mcp_redteam.formatters.sarif import write_sarif
    from mcp_redteam.formatters.json_fmt import write_json

    scan_start = datetime.now()

    path = path.resolve()  # VULN-08 fix: canonicalize path
    if not path.exists():
        console.print(f"[red]Error:[/red] path {path} does not exist")
        raise typer.Exit(code=2)

    findings = []

    # Phase 0: Config health
    if config:
        console.print("[bold cyan]Phase 0:[/bold cyan] Config validation...")
        config_findings = scan_config()
        findings.extend(config_findings)
        console.print(f"  {len(config_findings)} config issues found")

    # Phase 1: Semgrep deterministic scan
    semgrep_available = is_semgrep_available()
    if semgrep_available:
        console.print("[bold cyan]Phase 1:[/bold cyan] Semgrep analysis...")
        semgrep_findings = run_semgrep(path)
        findings.extend(semgrep_findings)
        console.print(f"  {len(semgrep_findings)} code findings")
    else:
        console.print("[yellow]Phase 1:[/yellow] Semgrep not installed — skipping deterministic code scan")
        console.print("  Install: [dim]pip install semgrep[/dim]")

    # Phase 2: LLM behavioral analysis
    if not no_llm:
        from mcp_redteam.llm.analyzer import analyze_behavioral, is_llm_available
        if is_llm_available():
            console.print("[bold cyan]Phase 2:[/bold cyan] LLM behavioral analysis...")
            llm_findings = analyze_behavioral(path)
            findings.extend(llm_findings)
            console.print(f"  {len(llm_findings)} behavioral findings")
        else:
            console.print("[yellow]Phase 2:[/yellow] No ANTHROPIC_API_KEY — skipping LLM analysis")
            console.print("  Set: [dim]export ANTHROPIC_API_KEY=sk-...[/dim]")

    # Build result
    result = ScanResult(
        metadata=ScanMetadata(
            scan_start=scan_start,
            scan_end=datetime.now(),
            target_path=str(path),
            mode="deterministic" if no_llm else "hybrid",
            llm_enabled=not no_llm,
            semgrep_available=semgrep_available,
            files_scanned=sum(1 for _ in path.rglob("*.py")) + sum(1 for _ in path.rglob("*.ts")) + sum(1 for _ in path.rglob("*.js")) if path.is_dir() else 1,
        ),
        findings=findings,
    )

    # Output
    if format == OutputFormat.terminal:
        format_terminal(result, console)
    elif format == OutputFormat.sarif:
        sarif_str = format_sarif(result)
        if output:
            write_sarif(result, output)
            console.print(f"[green]SARIF written to {output}[/green]")
        else:
            print(sarif_str)
    elif format == OutputFormat.json:
        json_str = format_json(result)
        if output:
            write_json(result, output)
            console.print(f"[green]JSON written to {output}[/green]")
        else:
            print(json_str)

    # Exit code for CI
    if fail_on:
        threshold = {"critical": Severity.CRITICAL, "high": Severity.HIGH}.get(fail_on.lower())
        if threshold:
            failing = [f for f in findings if _severity_rank(f.severity) >= _severity_rank(threshold)]
            if failing:
                raise typer.Exit(code=1)


def _severity_rank(severity) -> int:
    from mcp_redteam.models import Severity
    ranks = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
    return ranks.get(severity, 0)

@app.command()
def version():
    """Show version."""
    from mcp_redteam import __version__
    console.print(f"mcp-redteam {__version__}")

if __name__ == "__main__":
    app()
