# Эталонный MCP-сервер (Python)

**Версия:** 1.0
**Последнее обновление:** 7 июня 2026

Этот файл — шаблон идеального MCP-сервера со всеми best practices. Копируй и адаптируй.

---

## Минимальный эталон (Raw MCP SDK)

```python
"""
Example MCP Server — reference implementation.

Tools:
  example_tool — does something useful
"""
import asyncio
import os
import re
import signal
import sys
from pathlib import Path
from urllib.parse import urlparse

import httpx
from mcp.server import Server
from mcp import types
from mcp.server.stdio import stdio_server


# ── Config ───────────────────────────────────────────────────────────────────

APP_NAME = "example-mcp"
BASE_DIR = Path(os.environ.get("EXAMPLE_BASE_DIR", str(Path.home() / "example-data")))
BASE_DIR.mkdir(parents=True, exist_ok=True)

app = Server(APP_NAME)


# ── Signal Handling ──────────────────────────────────────────────────────────

def _handle_shutdown(sig, frame):
    sys.exit(0)

signal.signal(signal.SIGTERM, _handle_shutdown)
signal.signal(signal.SIGINT, _handle_shutdown)


# ── HTTP Client (cached, with recovery) ──────────────────────────────────────

_http_client: httpx.AsyncClient | None = None

def _get_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=30.0)
    return _http_client


async def _request(method: str, url: str, **kwargs) -> httpx.Response:
    """HTTP request with automatic client recovery on transport errors."""
    global _http_client
    client = _get_client()
    try:
        resp = await client.request(method, url, **kwargs)
        resp.raise_for_status()
        return resp
    except (httpx.ConnectError, httpx.PoolTimeout, httpx.RemoteProtocolError):
        try:
            await _http_client.aclose()
        except Exception:
            pass
        _http_client = None
        client = _get_client()
        resp = await client.request(method, url, **kwargs)
        resp.raise_for_status()
        return resp


# ── Security Helpers ─────────────────────────────────────────────────────────

_BLOCKED_HOSTS = {"169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1", "0.0.0.0", "[::1]"}


def _validate_url(url: str, allowed_hosts: set | None = None) -> str:
    """Validate URL scheme and host. Blocks file://, internal IPs, cloud metadata."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Invalid URL scheme: {parsed.scheme}")
    if parsed.hostname in _BLOCKED_HOSTS:
        raise ValueError(f"Blocked host: {parsed.hostname}")
    if allowed_hosts and not any(
        parsed.hostname == h or parsed.hostname.endswith("." + h)
        for h in allowed_hosts
    ):
        raise ValueError(f"Host not allowed: {parsed.hostname}")
    return url


def _validate_path(user_input: str, base_dir: Path) -> Path:
    """Validate that a user-supplied path stays within base_dir."""
    resolved = (base_dir / user_input).resolve()
    if not resolved.is_relative_to(base_dir.resolve()):
        raise ValueError("Path traversal detected")
    return resolved


def _safe_error(e: Exception) -> str:
    """Sanitize error message — strip paths and credentials."""
    msg = str(e)
    msg = re.sub(r'/Users/[^\s:]+', '[path]', msg)
    msg = re.sub(r'(key|token|secret|password)=[^\s&]+', r'\1=[REDACTED]', msg, flags=re.I)
    return msg[:500]


# ── Tool Definitions ─────────────────────────────────────────────────────────

@app.list_tools()
async def list_tools():
    return [
        types.Tool(
            name="example_search",
            description="Search for something by query.",
            inputSchema={
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "max_results": {"type": "integer", "description": "Max results (default 10)"},
                },
            },
        ),
        types.Tool(
            name="example_download",
            description="Download a file by URL.",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string", "description": "File URL"},
                    "filename": {"type": "string", "description": "Save as filename"},
                },
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict):
    try:
        if name == "example_search":
            return await _handle_search(arguments)
        elif name == "example_download":
            return await _handle_download(arguments)
        else:
            return [types.TextContent(type="text", text=f"Unknown tool: {name}")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"Error: {_safe_error(e)}")]


# ── Tool Handlers ────────────────────────────────────────────────────────────

async def _handle_search(a: dict):
    query = a.get("query", "").strip()
    if not query:
        return [types.TextContent(type="text", text="Error: query is required")]

    max_results = min(int(a.get("max_results", 10)), 50)  # cap at 50

    resp = await _request("GET", "https://api.example.com/search", params={
        "q": query,
        "limit": max_results,
    })

    data = resp.json()
    return [types.TextContent(type="text", text=json.dumps(data, indent=2, ensure_ascii=False))]


async def _handle_download(a: dict):
    url = _validate_url(a["url"])  # SSRF protection
    filename = a.get("filename", "download")

    dest = _validate_path(filename, BASE_DIR)  # path traversal protection

    resp = await _request("GET", url, timeout=120.0)

    # Size limit: 100MB
    if len(resp.content) > 100 * 1024 * 1024:
        return [types.TextContent(type="text", text="Error: file exceeds 100MB limit")]

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(resp.content)

    return [types.TextContent(type="text", text=f"Downloaded to {dest.name} ({len(resp.content)} bytes)")]


# ── Entry Point ──────────────────────────────────────────────────────────────

async def main():
    async with stdio_server() as (read, write):
        await app.run(read, write, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
```

---

## Минимальный эталон (FastMCP)

```python
"""
Example FastMCP Server — reference implementation.
"""
import os
import re
import signal
import sys
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastmcp import FastMCP, ToolError

mcp = FastMCP("example-fastmcp")

BASE_DIR = Path(os.environ.get("EXAMPLE_BASE_DIR", str(Path.home() / "example-data")))


# ── Signal Handling ──────────────────────────────────────────────────────────

def _handle_shutdown(sig, frame):
    sys.exit(0)

signal.signal(signal.SIGTERM, _handle_shutdown)
signal.signal(signal.SIGINT, _handle_shutdown)


# ── HTTP Client ──────────────────────────────────────────────────────────────

_http: httpx.AsyncClient | None = None

def _client() -> httpx.AsyncClient:
    global _http
    if _http is None:
        _http = httpx.AsyncClient(timeout=30.0)
    return _http


# ── Security ─────────────────────────────────────────────────────────────────

def _validate_path(user_input: str, base: Path) -> Path:
    resolved = (base / user_input).resolve()
    if not resolved.is_relative_to(base.resolve()):
        raise ToolError("Path traversal detected")
    return resolved


def _validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ToolError(f"Invalid scheme: {parsed.scheme}")
    blocked = {"169.254.169.254", "localhost", "127.0.0.1"}
    if parsed.hostname in blocked:
        raise ToolError(f"Blocked host: {parsed.hostname}")
    return url


# ── Tools ────────────────────────────────────────────────────────────────────

@mcp.tool()
async def search(query: str, max_results: int = 10) -> str:
    """Search for something."""
    max_results = min(max_results, 50)
    resp = await _client().get("https://api.example.com/search", params={"q": query, "limit": max_results})
    resp.raise_for_status()
    return resp.text


@mcp.tool()
async def download(url: str, filename: str = "download") -> str:
    """Download a file by URL."""
    url = _validate_url(url)
    dest = _validate_path(filename, BASE_DIR)
    resp = await _client().get(url, timeout=120.0)
    resp.raise_for_status()
    dest.write_bytes(resp.content)
    return f"Saved {dest.name} ({len(resp.content)} bytes)"
```

---

## Эталон Node.js

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "example-mcp", version: "1.0.0" });

// Signal handling
process.on("SIGTERM", () => process.exit(0));
process.on("SIGINT", () => process.exit(0));

// Tool with error handling
server.tool("example_search", { query: z.string(), max_results: z.number().default(10) },
  async ({ query, max_results }) => {
    try {
      const resp = await fetch(`https://api.example.com/search?q=${encodeURIComponent(query)}&limit=${Math.min(max_results, 50)}`);
      const data = await resp.json();
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    } catch (error) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Start
const transport = new StdioServerTransport();
await server.connect(transport);
```

---

## Анти-паттерны (НЕ делать)

```python
# 1. NEVER: print to stdout
print("debug")                          # kills MCP connection
print("debug", file=sys.stderr)         # correct

# 2. NEVER: unhandled exception in handler
async def handle(args):
    data = await api.get(args["id"])     # crashes if 404
    return data

# 3. NEVER: blocking subprocess in async
subprocess.run(["cmd", "arg"])           # blocks event loop
await asyncio.create_subprocess_exec()   # correct

# 4. NEVER: new HTTP client per request
async with httpx.AsyncClient() as c:    # leaked on every call
    await c.get(url)

# 5. NEVER: unsanitized user path
path = BASE / user_input                 # path traversal
path = (BASE / user_input).resolve()     # + is_relative_to check

# 6. NEVER: pass URL to subprocess without validation
proc = await exec("curl", user_url)     # SSRF
validate_url(user_url); proc = ...       # correct

# 7. NEVER: async cleanup in signal handler
def handler(sig, frame):
    loop.create_task(cleanup())          # never runs
    sys.exit(0)

def handler(sig, frame):
    sys.exit(0)                          # correct — OS cleans up
```
