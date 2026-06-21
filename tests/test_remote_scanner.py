"""Tests for remote_scanner.py — pure logic, no network."""
import pytest
from unittest.mock import patch, MagicMock
from mcp_redteam.models import Severity, FindingCategory


def _make_tools(count: int) -> list[dict]:
    """Generate a list of minimal MCP tool dicts."""
    return [
        {
            "name": f"tool_{i}",
            "description": f"Tool number {i}",
            "inputSchema": {"properties": {}},
        }
        for i in range(count)
    ]


def _run_scan(url: str, tools: list[dict], token: str = "test-token"):
    """Run scan_remote with mocked network calls and embedding detector."""
    with patch("mcp_redteam.engine.remote_scanner._fetch_tools_list") as mock_fetch, \
         patch("mcp_redteam.engine.embedding_detector.scan_descriptions") as mock_embed:
        mock_fetch.return_value = tools
        mock_embed.return_value = []

        from mcp_redteam.engine.remote_scanner import scan_remote
        return scan_remote(url, token=token)


# ── TLS checks ──────────────────────────────────────────────────────────────


def test_tls_http_finding():
    """HTTP URL produces MRT031 CRITICAL."""
    findings, meta = _run_scan("http://example.com/mcp", _make_tools(3))

    tls_findings = [f for f in findings if f.id == "MRT031"]
    assert len(tls_findings) == 1
    assert tls_findings[0].severity == Severity.CRITICAL
    assert tls_findings[0].category == FindingCategory.security
    assert "HTTP" in tls_findings[0].title


def test_tls_https_no_finding():
    """HTTPS URL does not trigger MRT031."""
    findings, meta = _run_scan("https://example.com/mcp", _make_tools(3))

    tls_findings = [f for f in findings if f.id == "MRT031"]
    assert len(tls_findings) == 0


# ── Dangerous parameter detection ───────────────────────────────────────────


def test_dangerous_param_cmd():
    """Tool with 'cmd' param produces MRT030."""
    tools = [{
        "name": "executor",
        "description": "Run things",
        "inputSchema": {"properties": {"cmd": {"type": "string"}}},
    }]
    findings, _ = _run_scan("https://example.com/mcp", tools)

    dangerous = [f for f in findings if f.id == "MRT030"]
    assert len(dangerous) == 1
    assert dangerous[0].severity == Severity.HIGH
    assert "cmd" in dangerous[0].title
    assert "executor" in dangerous[0].title


def test_dangerous_param_eval():
    """Tool with 'eval' param produces MRT030."""
    tools = [{
        "name": "evaluator",
        "description": "Evaluate expression",
        "inputSchema": {"properties": {"eval": {"type": "string"}}},
    }]
    findings, _ = _run_scan("https://example.com/mcp", tools)

    dangerous = [f for f in findings if f.id == "MRT030"]
    assert len(dangerous) == 1
    assert "eval" in dangerous[0].title


def test_dangerous_param_multiple():
    """Multiple dangerous params produce multiple MRT030 findings."""
    tools = [{
        "name": "shell_tool",
        "description": "Runs shell",
        "inputSchema": {"properties": {
            "cmd": {"type": "string"},
            "shell": {"type": "string"},
        }},
    }]
    findings, _ = _run_scan("https://example.com/mcp", tools)

    dangerous = [f for f in findings if f.id == "MRT030"]
    assert len(dangerous) == 2


def test_safe_param_no_finding():
    """Tool with normal params (name, query) does not trigger MRT030."""
    tools = [{
        "name": "search",
        "description": "Search things",
        "inputSchema": {"properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer"},
        }},
    }]
    findings, _ = _run_scan("https://example.com/mcp", tools)

    dangerous = [f for f in findings if f.id == "MRT030"]
    assert len(dangerous) == 0


def test_dangerous_param_case_insensitive():
    """Dangerous param detection is case-insensitive."""
    tools = [{
        "name": "runner",
        "description": "Run code",
        "inputSchema": {"properties": {"CMD": {"type": "string"}}},
    }]
    findings, _ = _run_scan("https://example.com/mcp", tools)

    dangerous = [f for f in findings if f.id == "MRT030"]
    assert len(dangerous) == 1


# ── Over-privileged tool count ───────────────────────────────────────────────


def test_over_privileged_201_tools():
    """201 tools produces MRT029 HIGH."""
    findings, meta = _run_scan("https://example.com/mcp", _make_tools(201))

    mrt029 = [f for f in findings if f.id == "MRT029"]
    assert len(mrt029) == 1
    assert mrt029[0].severity == Severity.HIGH
    assert meta["tool_count"] == 201


def test_over_privileged_51_tools():
    """51 tools produces MRT029 MEDIUM."""
    findings, _ = _run_scan("https://example.com/mcp", _make_tools(51))

    mrt029 = [f for f in findings if f.id == "MRT029"]
    assert len(mrt029) == 1
    assert mrt029[0].severity == Severity.MEDIUM


def test_normal_count_no_finding():
    """10 tools produces no MRT029."""
    findings, _ = _run_scan("https://example.com/mcp", _make_tools(10))

    mrt029 = [f for f in findings if f.id == "MRT029"]
    assert len(mrt029) == 0


def test_exactly_50_tools_no_finding():
    """Exactly 50 tools does not trigger MRT029 (boundary)."""
    findings, _ = _run_scan("https://example.com/mcp", _make_tools(50))

    mrt029 = [f for f in findings if f.id == "MRT029"]
    assert len(mrt029) == 0


def test_exactly_200_tools_medium():
    """Exactly 200 tools triggers MRT029 MEDIUM (not HIGH)."""
    findings, _ = _run_scan("https://example.com/mcp", _make_tools(200))

    mrt029 = [f for f in findings if f.id == "MRT029"]
    assert len(mrt029) == 1
    assert mrt029[0].severity == Severity.MEDIUM


# ── Metadata ─────────────────────────────────────────────────────────────────


def test_metadata_contains_url_and_tool_count():
    """Metadata dict includes url, tool_count, and tool names."""
    tools = _make_tools(3)
    _, meta = _run_scan("https://example.com/mcp", tools)

    assert meta["url"] == "https://example.com/mcp"
    assert meta["tool_count"] == 3
    assert meta["tools"] == ["tool_0", "tool_1", "tool_2"]


def test_empty_tools_returns_error():
    """Empty tool list returns error metadata."""
    with patch("mcp_redteam.engine.remote_scanner._fetch_tools_list") as mock_fetch, \
         patch("mcp_redteam.engine.embedding_detector.scan_descriptions") as mock_embed:
        mock_fetch.return_value = []
        mock_embed.return_value = []

        from mcp_redteam.engine.remote_scanner import scan_remote
        findings, meta = scan_remote("https://example.com/mcp", token="test-token")

        assert "error" in meta
        assert findings == []


# ── No token triggers OAuth (mocked) ────────────────────────────────────────


def test_no_token_triggers_oauth():
    """When no token provided, _oauth_flow is called."""
    with patch("mcp_redteam.engine.remote_scanner._oauth_flow") as mock_oauth, \
         patch("mcp_redteam.engine.remote_scanner._fetch_tools_list") as mock_fetch, \
         patch("mcp_redteam.engine.embedding_detector.scan_descriptions") as mock_embed:
        mock_oauth.return_value = None
        mock_fetch.return_value = []
        mock_embed.return_value = []

        from mcp_redteam.engine.remote_scanner import scan_remote
        findings, meta = scan_remote("https://example.com/mcp", token=None)

        mock_oauth.assert_called_once()
        assert "error" in meta


# ── Combined findings ───────────────────────────────────────────────────────


def test_combined_http_and_dangerous_params():
    """HTTP URL with dangerous params produces both MRT031 and MRT030."""
    tools = [{
        "name": "shell",
        "description": "Execute shell",
        "inputSchema": {"properties": {"exec": {"type": "string"}}},
    }]
    findings, _ = _run_scan("http://evil.com/mcp", tools)

    ids = {f.id for f in findings}
    assert "MRT031" in ids
    assert "MRT030" in ids
