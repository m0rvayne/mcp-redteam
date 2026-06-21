"""Integration tests for mcp-redteam CLI."""
import json
import pytest
from typer.testing import CliRunner
from mcp_redteam.cli import app

runner = CliRunner()


def _extract_json(output: str) -> dict:
    """Extract JSON object from CLI output that may contain Rich console text before it."""
    # Find the first '{' which starts the JSON output
    idx = output.index("{")
    return json.loads(output[idx:])


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "mcp-redteam" in result.output


def test_no_args_shows_help():
    result = runner.invoke(app, [])
    # Typer no_args_is_help may exit with 0 or 2 depending on version
    assert result.exit_code in (0, 2)
    assert "scan" in result.output.lower() or "usage" in result.output.lower()


def test_scan_nonexistent_path():
    result = runner.invoke(app, ["scan", "/nonexistent/path/xyz"])
    assert result.exit_code == 2
    assert "does not exist" in result.output


def test_scan_json_format(tmp_path):
    (tmp_path / "server.py").write_text("def hello(): return 'world'")
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--no-llm", "--no-config"])
    assert result.exit_code == 0
    data = _extract_json(result.output)
    assert "metadata" in data
    assert "findings" in data


def test_scan_sarif_format(tmp_path):
    (tmp_path / "server.py").write_text("def hello(): return 'world'")
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "sarif", "--no-llm", "--no-config"])
    assert result.exit_code == 0
    data = _extract_json(result.output)
    assert data.get("version") == "2.1.0"
    assert "$schema" in data


def test_scan_terminal_format(tmp_path):
    (tmp_path / "server.py").write_text("def hello(): return 'world'")
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-llm", "--no-config"])
    assert result.exit_code == 0


def test_scan_output_to_file(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "server.py").write_text("def hello(): return 'world'")
    out = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["scan", str(src), "--format", "json", "--no-llm", "--no-config", "-o", str(out)],
    )
    assert result.exit_code == 0
    assert out.exists()
    data = json.loads(out.read_text())
    assert "findings" in data


def test_scan_fail_on_with_no_findings(tmp_path):
    (tmp_path / "server.py").write_text("def hello(): return 'world'")
    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--no-llm", "--no-config", "--fail-on", "critical"],
    )
    # No findings = exit 0
    assert result.exit_code == 0


def test_scan_no_llm_flag(tmp_path):
    (tmp_path / "server.py").write_text("def hello(): return 'world'")
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-llm", "--no-config"])
    assert result.exit_code == 0
    # With --no-llm, LLM phase should be skipped entirely (no LLM output appears)


def test_scan_sarif_output_to_file(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "server.py").write_text("def hello(): return 'world'")
    out = tmp_path / "report.sarif"
    result = runner.invoke(
        app,
        ["scan", str(src), "--format", "sarif", "--no-llm", "--no-config", "-o", str(out)],
    )
    assert result.exit_code == 0
    assert out.exists()
    data = json.loads(out.read_text())
    assert data.get("version") == "2.1.0"


def test_scan_fail_on_high_no_findings(tmp_path):
    (tmp_path / "server.py").write_text("def hello(): return 'world'")
    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--no-llm", "--no-config", "--fail-on", "high"],
    )
    assert result.exit_code == 0


def test_scan_html_format(tmp_path):
    """HTML format output via CLI."""
    (tmp_path / "server.py").write_text("def hello(): return 'world'")
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "html", "--no-llm", "--no-config"])
    assert result.exit_code == 0
    assert "<!DOCTYPE html>" in result.output
    assert "mcp-redteam" in result.output


def test_scan_quick_mode(tmp_path):
    """Quick scan completes fast with only config checks."""
    (tmp_path / "server.py").write_text("def hello(): return 'world'")
    result = runner.invoke(app, ["scan", str(tmp_path), "--quick", "--no-config"])
    assert result.exit_code == 0
    assert "Quick scan" in result.output or "quick" in result.output.lower()


def test_scan_quick_filters_severity(tmp_path):
    """Quick scan shows only CRITICAL+HIGH, not MEDIUM/LOW."""
    (tmp_path / "server.py").write_text("def hello(): return 'world'")
    result = runner.invoke(app, ["scan", str(tmp_path), "--quick", "--format", "json", "--no-config"])
    assert result.exit_code == 0
    data = _extract_json(result.output)
    # With no config checks and no semgrep, should have no findings
    assert data["metadata"]["mode"] == "quick"
    for finding in data.get("findings", []):
        assert finding["severity"] in ("CRITICAL", "HIGH")


def test_scan_html_output_to_file(tmp_path):
    """HTML format written to file."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "server.py").write_text("def hello(): return 'world'")
    out = tmp_path / "report.html"
    result = runner.invoke(
        app,
        ["scan", str(src), "--format", "html", "--no-llm", "--no-config", "-o", str(out)],
    )
    assert result.exit_code == 0
    assert out.exists()
    content = out.read_text()
    assert "<!DOCTYPE html>" in content


def test_badge_command(tmp_path):
    """Badge command generates a shields.io badge URL."""
    (tmp_path / "server.py").write_text("def hello(): return 'world'")
    result = runner.invoke(app, ["badge", str(tmp_path)])
    assert result.exit_code == 0
    assert "img.shields.io" in result.output
    assert "mcp--security" in result.output


def test_badge_nonexistent_path():
    """Badge command fails for nonexistent path."""
    result = runner.invoke(app, ["badge", "/nonexistent/path/xyz"])
    assert result.exit_code == 2
    assert "does not exist" in result.output
