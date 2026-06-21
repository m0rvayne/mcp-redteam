"""Tests for mcp_redteam.llm.analyzer — LLM behavioral analysis module."""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mcp_redteam.llm.analyzer import (
    _extract_tool_descriptions,
    _parse_llm_findings,
    _read_source_files,
    _analyze_with_llm,
    is_llm_available,
)
from mcp_redteam.models import FindingCategory, Severity


# ---------------------------------------------------------------------------
# _parse_llm_findings
# ---------------------------------------------------------------------------


class TestParseLlmFindings:
    """Tests for the JSON parser that converts LLM responses into Finding objects."""

    def test_parse_valid_json_array(self):
        """Valid JSON array with one complete finding returns 1 Finding."""
        text = json.dumps([{
            "rule": "MRT015",
            "title": "Hardcoded API key",
            "severity": "HIGH",
            "category": "security",
            "file": "server.py",
            "line": 42,
            "evidence": "API_KEY = 'sk-123'",
            "description": "API key is hardcoded in source",
            "fix": "Use environment variable",
            "confidence": 0.9,
        }])
        findings = _parse_llm_findings(text)
        assert len(findings) == 1
        assert findings[0].title == "Hardcoded API key"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].category == FindingCategory.security
        assert findings[0].location is not None
        assert findings[0].location.file == "server.py"
        assert findings[0].location.line == 42
        assert findings[0].confidence == 0.9
        assert findings[0].source == "llm"

    def test_parse_empty_array(self):
        """Empty JSON array returns empty list."""
        assert _parse_llm_findings("[]") == []

    def test_parse_empty_string(self):
        """Empty string returns empty list."""
        assert _parse_llm_findings("") == []

    def test_parse_markdown_fenced(self):
        """Markdown-fenced JSON block is parsed after stripping fences."""
        inner = json.dumps([{
            "rule": "MRT015",
            "title": "Test issue",
            "severity": "LOW",
            "category": "security",
            "description": "desc",
            "evidence": "ev",
            "confidence": 0.8,
        }])
        text = f"```json\n{inner}\n```"
        findings = _parse_llm_findings(text)
        assert len(findings) == 1
        assert findings[0].title == "Test issue"

    def test_parse_malformed_json(self):
        """Completely invalid JSON returns empty list."""
        assert _parse_llm_findings("not json at all") == []

    def test_parse_json_with_surrounding_text(self):
        """JSON array embedded in prose is extracted and parsed."""
        inner = json.dumps([{
            "rule": "MRT015",
            "title": "Found it",
            "severity": "MEDIUM",
            "category": "security",
            "description": "d",
            "evidence": "e",
            "confidence": 0.8,
        }])
        text = f"Here are the findings: {inner} Hope this helps!"
        findings = _parse_llm_findings(text)
        assert len(findings) == 1
        assert findings[0].title == "Found it"

    def test_parse_missing_fields(self):
        """Finding with only title gets sensible defaults."""
        text = json.dumps([{"title": "minimal"}])
        findings = _parse_llm_findings(text)
        assert len(findings) == 1
        f = findings[0]
        assert f.title == "minimal"
        assert f.severity == Severity.MEDIUM  # default
        assert f.id == "MRT015"  # default rule
        assert f.confidence == 0.8  # default confidence clamped

    def test_parse_invalid_severity(self):
        """Unknown severity string defaults to MEDIUM."""
        text = json.dumps([{
            "title": "bad sev",
            "severity": "EXTREME",
            "category": "security",
            "description": "d",
            "evidence": "e",
            "confidence": 0.8,
        }])
        findings = _parse_llm_findings(text)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_parse_confidence_clamped_high(self):
        """Confidence above 0.95 is clamped to 0.95."""
        text = json.dumps([{
            "title": "high conf",
            "severity": "LOW",
            "category": "security",
            "description": "d",
            "evidence": "e",
            "confidence": 0.99,
        }])
        findings = _parse_llm_findings(text)
        assert findings[0].confidence == 0.95

    def test_parse_confidence_clamped_low(self):
        """Confidence below 0.1 is clamped to 0.1."""
        text = json.dumps([{
            "title": "low conf",
            "severity": "LOW",
            "category": "security",
            "description": "d",
            "evidence": "e",
            "confidence": 0.01,
        }])
        findings = _parse_llm_findings(text)
        assert findings[0].confidence == 0.1

    def test_parse_non_dict_items_skipped(self):
        """Non-dict items in array are silently skipped."""
        text = json.dumps([
            1,
            "string",
            {"title": "valid", "severity": "HIGH", "category": "security",
             "description": "d", "evidence": "e", "confidence": 0.8},
        ])
        findings = _parse_llm_findings(text)
        assert len(findings) == 1
        assert findings[0].title == "valid"

    def test_parse_invalid_category(self):
        """Unknown category defaults to 'security'."""
        text = json.dumps([{
            "title": "bad cat",
            "severity": "LOW",
            "category": "nonsense",
            "description": "d",
            "evidence": "e",
            "confidence": 0.8,
        }])
        findings = _parse_llm_findings(text)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.security


# ---------------------------------------------------------------------------
# _extract_tool_descriptions
# ---------------------------------------------------------------------------


class TestExtractToolDescriptions:
    """Tests for regex-based tool description extraction."""

    def test_extract_fastmcp_decorator(self):
        """Python FastMCP @mcp.tool() decorator with docstring is extracted."""
        source = '''
@mcp.tool()
async def read_file(path: str) -> str:
    """Read a file from disk."""
    return open(path).read()
'''
        result = _extract_tool_descriptions(source)
        assert "read_file" in result
        assert "Read a file from disk" in result

    def test_extract_dict_literal(self):
        """Python/JS dict literal with name and description is extracted."""
        source = '''
tools = [
    {"name": "search", "description": "Search the database for records"},
]
'''
        result = _extract_tool_descriptions(source)
        assert "search" in result
        assert "Search the database for records" in result

    def test_extract_js_server_tool(self):
        """JS/TS server.tool("name", "description", ...) pattern is extracted."""
        source = '''
server.tool("list_items", "List all items in the store", async (params) => {
    return items;
});
'''
        result = _extract_tool_descriptions(source)
        assert "list_items" in result
        assert "List all items in the store" in result

    def test_extract_no_descriptions(self):
        """Source with no recognizable tool patterns returns empty string."""
        source = '''
def helper():
    return 42

class Config:
    debug = True
'''
        result = _extract_tool_descriptions(source)
        assert result == ""


# ---------------------------------------------------------------------------
# _read_source_files
# ---------------------------------------------------------------------------


class TestReadSourceFiles:
    """Tests for source file reading with size limits and filtering."""

    def test_read_single_file(self, tmp_path):
        """Reading a single .py file returns its content with a FILE header."""
        f = tmp_path / "server.py"
        f.write_text("print('hello')", encoding="utf-8")
        result = _read_source_files(f)
        assert "print('hello')" in result
        assert "# === FILE:" in result

    def test_read_directory(self, tmp_path):
        """Reading a directory collects all .py and .js files recursively."""
        (tmp_path / "main.py").write_text("# main", encoding="utf-8")
        sub = tmp_path / "lib"
        sub.mkdir()
        (sub / "util.js").write_text("// util", encoding="utf-8")
        (sub / "data.txt").write_text("not source", encoding="utf-8")

        result = _read_source_files(tmp_path)
        assert "# main" in result
        assert "// util" in result
        assert "not source" not in result  # .txt excluded

    def test_read_respects_max_chars(self, tmp_path):
        """Large files are truncated at max_chars limit."""
        f = tmp_path / "big.py"
        f.write_text("x" * 100_000, encoding="utf-8")
        result = _read_source_files(tmp_path, max_chars=500)
        assert len(result) <= 500

    def test_read_skips_node_modules(self, tmp_path):
        """Files inside node_modules are excluded."""
        (tmp_path / "index.js").write_text("// root", encoding="utf-8")
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "lib.js").write_text("// should be skipped", encoding="utf-8")

        result = _read_source_files(tmp_path)
        assert "// root" in result
        assert "// should be skipped" not in result

    def test_read_nonexistent_path(self):
        """Non-existent path returns empty string."""
        result = _read_source_files(Path("/nonexistent/path/xyz"))
        assert result == ""


# ---------------------------------------------------------------------------
# _analyze_with_llm (mocked API)
# ---------------------------------------------------------------------------


class TestAnalyzeWithLlm:
    """Tests for LLM analysis with mocked Anthropic client."""

    def test_analyze_with_mocked_api(self):
        """Mocked API returning valid JSON produces parsed findings."""
        response_json = json.dumps([{
            "rule": "MRT015",
            "title": "Hidden HTTP call",
            "severity": "HIGH",
            "category": "security",
            "file": "server.py",
            "line": 10,
            "evidence": "requests.post(url)",
            "description": "Tool makes undeclared HTTP request",
            "fix": "Document the network call",
            "confidence": 0.85,
        }])

        mock_content = MagicMock()
        mock_content.text = response_json

        mock_response = MagicMock()
        mock_response.content = [mock_content]

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response

        findings = _analyze_with_llm(
            mock_client,
            "import requests\nrequests.post(url)",
            'TOOL DESCRIPTIONS:\n- mytool: "does stuff"',
        )
        assert len(findings) == 1
        assert findings[0].title == "Hidden HTTP call"
        mock_client.messages.create.assert_called_once()

    def test_analyze_api_error(self):
        """API exception returns empty list gracefully."""
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = Exception("rate limited")

        findings = _analyze_with_llm(mock_client, "source code", "")
        assert findings == []

    def test_analyze_empty_response(self):
        """API returning empty content list returns empty findings."""
        mock_response = MagicMock()
        mock_response.content = []

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response

        findings = _analyze_with_llm(mock_client, "source", "")
        assert findings == []

    def test_analyze_uses_descriptions_instruction(self):
        """When descriptions_block is provided, prompt includes comparison instruction."""
        mock_content = MagicMock()
        mock_content.text = "[]"
        mock_response = MagicMock()
        mock_response.content = [mock_content]
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response

        _analyze_with_llm(mock_client, "code", "TOOL DESCRIPTIONS:\n- tool: desc")

        call_args = mock_client.messages.create.call_args
        prompt_content = call_args.kwargs["messages"][0]["content"]
        assert "Compare each tool" in prompt_content

    def test_analyze_no_descriptions_instruction(self):
        """When descriptions_block is empty, prompt focuses on hidden ops."""
        mock_content = MagicMock()
        mock_content.text = "[]"
        mock_response = MagicMock()
        mock_response.content = [mock_content]
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response

        _analyze_with_llm(mock_client, "code", "")

        call_args = mock_client.messages.create.call_args
        prompt_content = call_args.kwargs["messages"][0]["content"]
        assert "No tool descriptions were extracted" in prompt_content


# ---------------------------------------------------------------------------
# is_llm_available
# ---------------------------------------------------------------------------


class TestIsLlmAvailable:
    """Tests for LLM availability check."""

    def test_llm_available_with_key(self, monkeypatch):
        """Returns True when anthropic is importable and API key is set."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-key")
        with patch.dict("sys.modules", {"anthropic": MagicMock()}):
            assert is_llm_available() is True

    def test_llm_not_available_no_key(self, monkeypatch):
        """Returns False when API key is not set."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        # Even if anthropic is importable, no key means not available
        assert is_llm_available() is False

    def test_llm_not_available_no_module(self, monkeypatch):
        """Returns False when anthropic module cannot be imported."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-key")
        with patch.dict("sys.modules", {"anthropic": None}):
            # Importing None from sys.modules raises ImportError
            result = is_llm_available()
            # When module is None in sys.modules, import raises ImportError
            assert result is False
