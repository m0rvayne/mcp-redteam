import os
import sys
import typer
from rich.console import Console
from pathlib import Path
from typing import Optional
from enum import Enum
from datetime import datetime

from mcp_redteam.constants import MAX_SOURCE_FILES, SKIP_DIRS

app = typer.Typer(
    name="mcp-redteam",
    help="MCP server security auditor — deterministic engine + AI-native behavioral analysis",
    no_args_is_help=True,
)
console = Console(stderr=True)


class OutputFormat(str, Enum):
    terminal = "terminal"
    json = "json"
    sarif = "sarif"
    html = "html"


@app.command()
def scan(
    path: Path = typer.Argument(..., help="Path to MCP server source code"),
    format: OutputFormat = typer.Option(OutputFormat.terminal, "--format", "-f", help="Output format"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Deterministic checks only (no LLM)"),
    config: bool = typer.Option(True, "--config/--no-config", help="Run config health checks"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit 1 if findings at this severity or above (critical, high)"),
    quick: bool = typer.Option(False, "--quick", "-q", help="Quick scan: config checks only, CRITICAL+HIGH findings"),
):
    """Scan MCP server for security vulnerabilities."""
    from mcp_redteam.models import ScanResult, ScanMetadata
    from mcp_redteam.engine.semgrep_runner import run_semgrep, is_semgrep_available
    from mcp_redteam.engine.config_scanner import scan_config

    if quick:
        no_llm = True
        console.print("[bold yellow]Quick scan[/bold yellow] — config checks only, CRITICAL+HIGH findings")

    scan_start = datetime.now()

    path = path.resolve()  # VULN-08 fix: canonicalize path
    if not path.exists():
        console.print(f"[red]Error:[/red] path {path} does not exist")
        raise typer.Exit(code=2)

    findings = []

    # Phase 0: Config health
    if config:
        console.print("[bold cyan]Phase 0:[/bold cyan] Config validation...")
        # Derive server name from target path for filtering scope conflicts
        target_server = path.name.lower().replace("mcp_", "").replace("mcp-", "").replace("_", "-")
        config_findings = scan_config(target_server=target_server)
        findings.extend(config_findings)
        console.print(f"  {len(config_findings)} config issues found")

    # Phase 1: Semgrep deterministic scan (skip in quick mode)
    semgrep_available = is_semgrep_available()
    if quick:
        semgrep_available = False  # skip semgrep in quick mode
    if semgrep_available:
        console.print("[bold cyan]Phase 1:[/bold cyan] Semgrep analysis...")
        semgrep_findings = run_semgrep(path)
        findings.extend(semgrep_findings)
        console.print(f"  {len(semgrep_findings)} code findings")
    elif quick:
        console.print("[yellow]Phase 1:[/yellow] Skipped (quick mode)")
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
    if quick:
        mode = "quick"
    elif no_llm:
        mode = "deterministic"
    else:
        mode = "hybrid"

    result = ScanResult(
        metadata=ScanMetadata(
            scan_start=scan_start,
            scan_end=datetime.now(),
            target_path=str(path),
            mode=mode,
            llm_enabled=not no_llm,
            semgrep_available=semgrep_available,
            files_scanned=_count_source_files(path),
        ),
        findings=findings,
    )

    if quick:
        from mcp_redteam.models import Severity
        result.findings = [f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        console.print(f"[dim]Quick scan complete. Run without --quick for full analysis ({_count_source_files(path)} source files to scan).[/dim]")

    # Save to audit history and show delta if previous run exists
    from mcp_redteam.engine.audit_history import save_run, get_previous_run, compare_runs, _compact_finding
    save_run(result)
    previous = get_previous_run(str(path))
    if previous:
        current_entry = {
            "findings": [_compact_finding(f) for f in result.findings],
            "risk_score": result.risk_score,
        }
        delta = compare_runs(previous, current_entry)
        s = delta["summary"]
        console.print(
            f"  [green]fixed: {s['fixed_count']}[/green]  "
            f"[red]new: {s['new_count']}[/red]  "
            f"confirmed: {s['confirmed_count']}  "
            f"risk: {s['prev_risk_score']} \u2192 {s['curr_risk_score']}"
        )

    _output_and_exit(result, format, output, fail_on, console)


def _count_source_files(path: Path, cap: int = MAX_SOURCE_FILES) -> int:
    """Count source files with cap to avoid DoS on huge dirs."""
    if not path.is_dir():
        return 1
    count = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f.endswith((".py", ".ts", ".js")):
                count += 1
                if count >= cap:
                    return cap
    return count


def _severity_rank(severity) -> int:
    from mcp_redteam.models import Severity
    ranks = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
    return ranks.get(severity, 0)


def _output_and_exit(
    result: "ScanResult",
    format: OutputFormat,
    output: Optional[Path],
    fail_on: Optional[str],
    console: Console,
) -> None:
    """Format output, write to file if requested, and exit with CI code if needed."""
    from mcp_redteam.models import Severity
    from mcp_redteam.formatters import format_sarif, format_json, format_terminal, format_html
    from mcp_redteam.formatters.sarif import write_sarif
    from mcp_redteam.formatters.json_fmt import write_json
    from mcp_redteam.formatters.html_fmt import write_html

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
    elif format == OutputFormat.html:
        html_str = format_html(result)
        if output:
            write_html(result, output)
            console.print(f"[green]HTML report written to {output}[/green]")
        else:
            print(html_str)

    if fail_on:
        threshold = {"critical": Severity.CRITICAL, "high": Severity.HIGH}.get(fail_on.lower())
        if threshold:
            failing = [f for f in result.findings if _severity_rank(f.severity) >= _severity_rank(threshold)]
            if failing:
                raise typer.Exit(code=1)

@app.command()
def scan_remote(
    url: str = typer.Argument(..., help="Remote MCP server URL (https://...)"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="Bearer token (skip OAuth)"),
    format: OutputFormat = typer.Option(OutputFormat.terminal, "--format", "-f", help="Output format"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    no_auth: bool = typer.Option(False, "--no-auth", help="Skip authentication entirely"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit 1 if findings at this severity or above (critical, high)"),
):
    """Scan a remote MCP server for security issues."""
    from mcp_redteam.engine.remote_scanner import scan_remote as do_scan
    from mcp_redteam.models import ScanResult, ScanMetadata

    scan_start = datetime.now()

    console.print(f"[bold red]mcp-redteam[/bold red] scan-remote")
    console.print(f"target: {url}")

    effective_token = token
    if no_auth:
        console.print("[yellow]Warning: scanning without auth — may get limited results[/yellow]")
        effective_token = None
    elif not token:
        console.print("[cyan]OAuth: opening browser for authentication...[/cyan]")
        console.print("[dim]Press Ctrl+C to skip[/dim]")

    try:
        findings, metadata = do_scan(url, effective_token)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled[/yellow]")
        raise typer.Exit(0)
    except ImportError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=2)

    if "error" in metadata:
        console.print(f"[red]Error:[/red] {metadata['error']}")
        raise typer.Exit(code=2)

    tool_count = metadata.get("tool_count", 0)
    console.print(f"tools found: {tool_count}")
    console.print(f"findings: {len(findings)}")

    # Build result
    result = ScanResult(
        metadata=ScanMetadata(
            scan_start=scan_start,
            scan_end=datetime.now(),
            target_path=url,
            mode="remote",
        ),
        findings=findings,
    )

    _output_and_exit(result, format, output, fail_on, console)


@app.command()
def badge(
    path: Path = typer.Argument(..., help="Path to MCP server source code"),
):
    """Generate a security badge after scanning (config + semgrep, no LLM)."""
    from mcp_redteam.models import ScanResult, ScanMetadata, Severity
    from mcp_redteam.engine.semgrep_runner import run_semgrep, is_semgrep_available
    from mcp_redteam.engine.config_scanner import scan_config

    scan_start = datetime.now()

    path = path.resolve()
    if not path.exists():
        console.print(f"[red]Error:[/red] path {path} does not exist")
        raise typer.Exit(code=2)

    findings = []

    # Config checks
    console.print("[bold cyan]Config check...[/bold cyan]")
    config_findings = scan_config()
    findings.extend(config_findings)

    # Semgrep checks
    if is_semgrep_available():
        console.print("[bold cyan]Semgrep analysis...[/bold cyan]")
        semgrep_findings = run_semgrep(path)
        findings.extend(semgrep_findings)
    else:
        console.print("[yellow]Semgrep not installed — running config checks only[/yellow]")

    result = ScanResult(
        metadata=ScanMetadata(
            scan_start=scan_start,
            scan_end=datetime.now(),
            target_path=str(path),
            mode="badge",
            semgrep_available=is_semgrep_available(),
            files_scanned=_count_source_files(path),
        ),
        findings=findings,
    )

    critical = result.critical_count
    high = result.high_count
    medium = sum(1 for f in result.findings if f.severity == Severity.MEDIUM)

    # Determine badge
    if critical > 0:
        label = f"{critical}%20critical"
        color = "red"
    elif high > 0:
        label = f"{high}%20high"
        color = "orange"
    else:
        label = "passing"
        color = "green"

    badge_url = f"https://img.shields.io/badge/mcp--security-{label}-{color}"
    badge_link = "https://github.com/m0rvayne/mcp-redteam"
    markdown = f"[![MCP Security]({badge_url})]({badge_link})"

    console.print(f"\nScan complete: {critical} critical, {high} high, {medium} medium\n")
    console.print("Add this badge to your README:\n")
    console.print(markdown)


@app.command()
def version():
    """Show version."""
    from mcp_redteam import __version__
    console.print(f"mcp-redteam {__version__}")

if __name__ == "__main__":
    app()
