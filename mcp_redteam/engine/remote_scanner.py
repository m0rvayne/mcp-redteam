"""Remote MCP server scanner — fetch tools/list and analyze descriptions."""

import json
import hashlib
import base64
import secrets
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Optional
import logging

from mcp_redteam import __version__

logger = logging.getLogger(__name__)


def _check_requests_available():
    """Check that requests is installed, raise helpful error if not."""
    try:
        import requests  # noqa: F401
    except ImportError:
        raise ImportError(
            "requests is required for remote scanning. "
            "Install it with: pip install 'redteam-mcp[remote]'"
        )


def scan_remote(url: str, token: Optional[str] = None) -> tuple[list, dict]:
    """
    Scan remote MCP server.

    Args:
        url: MCP server URL (https://...)
        token: Bearer token. If None, attempts OAuth flow.

    Returns:
        (list of Finding, metadata dict with tool_count etc.)
    """
    _check_requests_available()  # ImportError is allowed to propagate

    try:
        if not token:
            token = _oauth_flow(url)
            if not token:
                return [], {"error": "Authentication failed"}

        tools = _fetch_tools_list(url, token)
        if not tools:
            return [], {"error": "Failed to fetch tools/list"}

        # Run embedding detector on descriptions
        from mcp_redteam.engine.embedding_detector import scan_descriptions

        descriptions = {t["name"]: t.get("description", "") for t in tools}
        findings = scan_descriptions(descriptions)

        # Add metadata findings
        from mcp_redteam.models import Finding, Severity, FindingCategory

        if len(tools) > 200:
            findings.append(Finding(
                id="MRT029",
                rule_id="MRT029",
                title=f"Over-privileged: {len(tools)} tools",
                severity=Severity.HIGH,
                category=FindingCategory.architecture,
                description=f"Server exposes {len(tools)} tools. Excessive tool count increases attack surface.",
                evidence=f"tools/list returned {len(tools)} tools",
                confidence=1.0,
                source="remote",
            ))
        elif len(tools) > 50:
            findings.append(Finding(
                id="MRT029",
                rule_id="MRT029",
                title=f"Many tools: {len(tools)}",
                severity=Severity.MEDIUM,
                category=FindingCategory.architecture,
                description=f"Server exposes {len(tools)} tools. Consider reducing scope.",
                evidence=f"tools/list returned {len(tools)} tools",
                confidence=1.0,
                source="remote",
            ))

        # Check for dangerous parameter names
        dangerous_params = {
            "cmd", "command", "shell", "exec", "eval",
            "code", "script", "sql",
        }
        for tool in tools:
            props = tool.get("inputSchema", {}).get("properties", {})
            for param_name in props:
                if param_name.lower() in dangerous_params:
                    findings.append(Finding(
                        id="MRT030",
                        rule_id="MRT030",
                        title=f"Dangerous parameter '{param_name}' in '{tool['name']}'",
                        severity=Severity.HIGH,
                        category=FindingCategory.security,
                        description=f"Parameter name '{param_name}' suggests code/command execution capability.",
                        evidence=f"Tool: {tool['name']}, param: {param_name}",
                        confidence=0.7,
                        source="remote",
                    ))

        # Check TLS
        parsed = urlparse(url)
        if parsed.scheme == "http":
            findings.append(Finding(
                id="MRT031",
                rule_id="MRT031",
                title="No TLS — HTTP connection",
                severity=Severity.CRITICAL,
                category=FindingCategory.security,
                description="MCP server uses HTTP without TLS. All traffic including tokens is unencrypted.",
                evidence=f"URL: {url}",
                confidence=1.0,
                source="remote",
            ))

        metadata = {
            "url": url,
            "tool_count": len(tools),
            "tools": [t["name"] for t in tools],
        }

        return findings, metadata
    except Exception as e:
        logger.error("Remote scan failed for %s: %s", url, e)
        return [], {"error": str(e)}


def _fetch_tools_list(url: str, token: str) -> list:
    """Fetch tools/list via MCP Streamable HTTP protocol."""
    import requests

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }

    # Initialize
    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}},
            "clientInfo": {"name": "mcp-redteam", "version": __version__},
        },
    }

    try:
        resp = requests.post(url, json=init_payload, headers=headers, timeout=15)
        session_id = resp.headers.get("MCP-Session-Id")
        if session_id:
            headers["MCP-Session-Id"] = session_id

        # Initialized notification
        requests.post(
            url,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=headers,
            timeout=5,
        )

        # tools/list
        tools_resp = requests.post(
            url,
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            headers=headers,
            timeout=30,
        )

        # Parse — could be direct JSON or SSE
        text = tools_resp.text

        # Try SSE first
        for line in text.split("\n"):
            if line.startswith("data: "):
                try:
                    data = json.loads(line[6:])
                    if data.get("result", {}).get("tools"):
                        return data["result"]["tools"]
                except json.JSONDecodeError:
                    continue

        # Try direct JSON
        try:
            data = json.loads(text)
            return data.get("result", {}).get("tools", [])
        except json.JSONDecodeError:
            pass

        return []
    except Exception as e:
        logger.error("Failed to fetch tools/list: %s", e)
        return []


def _oauth_flow(mcp_url: str, timeout: int = 120) -> Optional[str]:
    """Run OAuth 2.1 DCR + PKCE flow for MCP server."""
    import requests

    # Step 1: Discover OAuth endpoints
    parsed = urlparse(mcp_url)
    # Build base path: strip the last segment (the MCP endpoint itself)
    path_parts = parsed.path.rstrip("/").rsplit("/", 1)
    base_path = path_parts[0] if len(path_parts) > 1 else ""
    base = f"{parsed.scheme}://{parsed.netloc}{base_path}"

    discovery_url = f"{base}/.well-known/oauth-authorization-server"
    try:
        disc = requests.get(discovery_url, timeout=10).json()
    except Exception as e:
        logger.error("OAuth discovery failed at %s: %s", discovery_url, e)
        return None

    auth_endpoint = disc.get("authorization_endpoint")
    token_endpoint = disc.get("token_endpoint")
    reg_endpoint = disc.get("registration_endpoint")

    if not all([auth_endpoint, token_endpoint, reg_endpoint]):
        logger.error("Incomplete OAuth discovery")
        return None

    # Step 2: Dynamic Client Registration
    try:
        port = _find_free_port()
        reg_resp = requests.post(
            reg_endpoint,
            json={
                "client_name": "mcp-redteam-scanner",
                "redirect_uris": [f"http://localhost:{port}/callback"],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            },
            timeout=10,
        ).json()
        client_id = reg_resp["client_id"]
    except Exception as e:
        logger.error("DCR failed: %s", e)
        return None

    # Step 3: PKCE
    verifier = secrets.token_urlsafe(43)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )

    state = secrets.token_urlsafe(16)

    auth_url = (
        f"{auth_endpoint}?response_type=code&client_id={client_id}"
        f"&redirect_uri=http://localhost:{port}/callback"
        f"&code_challenge={challenge}&code_challenge_method=S256"
        f"&state={state}"
    )

    # Step 4: Callback server + browser
    code = _wait_for_oauth_callback(port, auth_url, timeout, expected_state=state)
    if not code:
        return None

    # Step 5: Exchange code for token
    try:
        token_resp = requests.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": f"http://localhost:{port}/callback",
                "client_id": client_id,
                "code_verifier": verifier,
            },
            timeout=10,
        ).json()
        return token_resp.get("access_token")
    except Exception as e:
        logger.error("Token exchange failed: %s", e)
        return None


def _wait_for_oauth_callback(
    port: int, auth_url: str, timeout: int, expected_state: str = ""
) -> Optional[str]:
    """Start callback server, open browser, wait for code."""
    result: dict[str, Optional[str]] = {"code": None}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            params = parse_qs(urlparse(self.path).query)
            # Validate state to prevent CSRF
            returned_state = params.get("state", [None])[0]
            if expected_state and returned_state != expected_state:
                logger.error("OAuth state mismatch — possible CSRF attack")
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"State mismatch. Authentication rejected.")
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return
            if "code" in params:
                result["code"] = params["code"][0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Authenticated. You can close this tab.")
            threading.Thread(target=self.server.shutdown, daemon=True).start()

        def log_message(self, *args):
            pass

    server = HTTPServer(("localhost", port), Handler)
    webbrowser.open(auth_url)
    server.timeout = timeout
    server.handle_request()
    return result["code"]


def _find_free_port() -> int:
    """Find a free port for OAuth callback."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]
