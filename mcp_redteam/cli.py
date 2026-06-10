import typer
from rich.console import Console
from pathlib import Path
from typing import Optional
from enum import Enum

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
):
    """Scan MCP server for security vulnerabilities."""
    console.print(f"[bold red]mcp-redteam[/bold red] v0.2.0")
    console.print(f"scanning: {path}")
    console.print(f"format: {format.value}")
    console.print(f"llm: {'enabled' if not no_llm else 'disabled (deterministic only)'}")

    if not path.exists():
        console.print(f"[red]Error:[/red] path {path} does not exist")
        raise typer.Exit(code=2)

    # TODO: wire up engine
    console.print("[yellow]Engine not yet connected — scaffold only[/yellow]")

@app.command()
def version():
    """Show version."""
    from mcp_redteam import __version__
    console.print(f"mcp-redteam {__version__}")

if __name__ == "__main__":
    app()
