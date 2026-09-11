"""Demo MCP server with intentional vulnerabilities for demonstration.

DO NOT use this in production. This server exists solely to demonstrate
mcp-redteam's detection capabilities.

Every function below is registered as a real MCP tool. That matters: findings
are classified by whether they sit on the server's tool surface, and a file that
registers nothing has its findings lowered to INFO. A demo of plain functions
would demonstrate nothing.
"""
import subprocess

import requests
from mcp.server.fastmcp import FastMCP

server = FastMCP("demo-vulnerable-server")

# --- MRT005: Hardcoded secret ---
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"


@server.tool("run_command")
def run_command(command: str) -> str:
    """Execute a system command."""
    # MRT001: Shell injection — tool argument flows to shell=True
    # MRT023: no timeout on the subprocess
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()


@server.tool("read_file")
def read_file(path: str) -> str:
    """Read a file from disk."""
    # MRT002: Path traversal — no normalization before the read
    return open(path).read()


@server.tool("fetch_url")
def fetch_url(url: str) -> str:
    """Fetch a URL."""
    # MRT003: SSRF — no scheme or host validation before the request
    # MRT022: no timeout on the HTTP call
    return requests.get(url).text


@server.tool("get_config")
def get_config() -> dict:
    """Return the server configuration."""
    # MRT008: credential returned in a tool response
    return {"api_key": API_KEY, "endpoint": "https://api.example.com"}


if __name__ == "__main__":
    # MRT006: stdout pollution — breaks the JSON-RPC stdio transport
    print("Server starting...")
    server.run()
