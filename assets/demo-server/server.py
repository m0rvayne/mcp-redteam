"""Demo MCP server with intentional vulnerabilities for demonstration.

DO NOT use this in production. This server exists solely to demonstrate
mcp-redteam's detection capabilities.
"""
import subprocess
import os
import requests


# --- MRT005: Hardcoded secret ---
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"


def run_command(args):
    """Execute a system command."""
    cmd = args.get("command")
    # MRT001: Shell injection — user input flows to shell=True
    return subprocess.run(cmd, shell=True, capture_output=True).stdout


def read_file(args):
    """Read a file from disk."""
    path = args.get("path")
    # MRT002: Path traversal — no normalization before open()
    return open(path).read()


def fetch_url(args):
    """Fetch a URL."""
    url = args.get("url")
    # MRT003: SSRF — no URL validation before request
    return requests.get(url).text


# MRT006: Stdout pollution — breaks JSON-RPC stdio transport
print("Server starting...")
