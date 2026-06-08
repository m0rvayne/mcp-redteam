# MCP Server Best Practices

**Version:** 1.0
**MCP Specification:** 2025-03-26
**Last updated:** June 7, 2026

---

## Table of Contents

1. [Golden Rules](#1-golden-rules)
2. [Architecture and Transport](#2-architecture-and-transport)
3. [Code Patterns](#3-code-patterns)
4. [Security](#4-security)
5. [Stability](#5-stability)
6. [Debugging](#6-debugging)
7. [Framework Selection](#7-framework-selection)
8. [Pre-Release Checklist](#8-pre-release-checklist)

---

## 1. Golden Rules

| # | Rule | Why |
|---|------|-----|
| 1 | **stdout = ONLY JSON-RPC** | Any `print()` kills the connection instantly |
| 2 | **Tool errors -> isError=True, never raise** | Unhandled exception crashes the entire process |
| 3 | **Signal handling (SIGTERM/SIGINT)** | Claude Desktop sends SIGTERM on close |
| 4 | **HTTP clients — reuse** | New AsyncClient per request = connection leak |
| 5 | **Timeouts on ALL outgoing requests** | No timeout = server hung forever |
| 6 | **Absolute paths everywhere** | CWD in Claude Desktop = `/` on macOS |
| 7 | **Heavy resources — cache** | Browser, ML model, auth — initialize once |
| 8 | **Path validation via is_relative_to()** | Protection against path traversal |
| 9 | **URL validation before fetch** | Protection against SSRF |
| 10 | **Don't return str(e) to client** | Leaks paths, tokens, internal details |

---

## 2. Architecture and Transport

### stdio (for Claude Desktop / Claude Code)

- Client launches server as subprocess
- stdin/stdout = JSON-RPC, stderr = logs
- Client manages lifecycle: launch -> communicate -> close stdin -> SIGTERM -> SIGKILL
- **Rule:** nothing except JSON-RPC in stdout

### Streamable HTTP (for remote servers)

- Server — independent process with HTTP endpoint
- POST for JSON-RPC, GET for SSE streams
- Session support via `Mcp-Session-Id`
- **SSE (Server-Sent Events) deprecated** since spec 2025-03-26

### When to use what

| Scenario | Transport |
|----------|-----------|
| Local tool for Claude Desktop | stdio |
| Server in Docker/Kubernetes | Streamable HTTP |
| Multiple clients simultaneously | Streamable HTTP |
| Maximum compatibility | stdio |

---

## 3. Code Patterns

### Signal Handler

```python
import signal, sys

def _handle_shutdown(sig, frame):
    sys.exit(0)

signal.signal(signal.SIGTERM, _handle_shutdown)
signal.signal(signal.SIGINT, _handle_shutdown)
```

**Important:** Do NOT perform async cleanup in signal handler. `create_task(_cleanup())` + `sys.exit(0)` = cleanup never executes (race condition). Just `sys.exit(0)`.

### Cached HTTP Client

```python
import httpx

_http_client: httpx.AsyncClient | None = None

def _get_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=30.0)
    return _http_client
```

### Stale Client Recovery

```python
async def _request_safe(method, url, **kwargs):
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
```

### Error Handling in Tool Handlers

```python
# Raw MCP SDK:
try:
    # tool logic
except Exception as e:
    return [types.TextContent(type="text", text=f"Error: {safe_error(e)}")]

# FastMCP:
try:
    # tool logic
except Exception as e:
    raise ToolError(safe_error(e))
```

### Safe Error (does not leak internal information)

```python
import re

def safe_error(e: Exception) -> str:
    msg = str(e)
    msg = re.sub(r'/Users/[^\s:]+', '[path]', msg)
    msg = re.sub(r'(key|token|secret|password)=[^\s&]+', r'\1=[REDACTED]', msg, flags=re.I)
    return msg[:500]  # limit length
```

### Subprocess with Timeout and Kill

```python
proc = await asyncio.create_subprocess_exec(
    "command", "arg1", "arg2",
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE
)
try:
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
except asyncio.TimeoutError:
    proc.kill()
    await proc.wait()
    raise ValueError("Command timed out after 60s")
```

**Never:** `subprocess.run()` in async handler (blocks event loop), `shell=True` (command injection).

### Path Traversal Protection

```python
user_path = (BASE_DIR / user_input).resolve()
if not user_path.is_relative_to(BASE_DIR.resolve()):
    return error("Path traversal detected")
```

### URL Validation (SSRF Protection)

```python
from urllib.parse import urlparse

_BLOCKED_HOSTS = {"169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1", "0.0.0.0", "[::1]"}

def validate_url(url: str, allowed_hosts: set | None = None) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Invalid scheme: {parsed.scheme}")
    if parsed.hostname in _BLOCKED_HOSTS:
        raise ValueError(f"Blocked host: {parsed.hostname}")
    if allowed_hosts and not any(parsed.hostname == h or parsed.hostname.endswith("." + h) for h in allowed_hosts):
        raise ValueError(f"Host not allowed: {parsed.hostname}")
    return url
```

---

## 4. Security

### What to check (checklist)

- [ ] All file paths validated via `is_relative_to()`
- [ ] All URLs validated before fetch (scheme + host)
- [ ] `subprocess.run` -> `create_subprocess_exec` (no shell)
- [ ] Errors don't leak paths, tokens, internal details
- [ ] Credentials not in code, not in plaintext config
- [ ] `.env`, `token.json`, `credentials.json` in `.gitignore`
- [ ] Files with secrets have `chmod 600`
- [ ] No `print()` without `file=sys.stderr`

### Known Attacks on MCP (as of 2026)

1. **Tool Poisoning** — hidden `<IMPORTANT>` instructions in tool description
2. **Cross-Server Shadowing** — one MCP server influences another's behavior through descriptions
3. **Rug Pull** — server changes tool descriptions after approval
4. **Output Poisoning** — instruction injection in tool responses
5. **SSRF** — forcing server to access internal services
6. **Path Traversal** — reading/writing arbitrary files (76% of servers vulnerable)
7. **Credential Theft** — reading config/env files through another MCP server

---

## 5. Stability

### What Kills MCP Servers

| Cause | How to protect |
|-------|---------------|
| `print()` to stdout | Only `file=sys.stderr` |
| Unhandled exception | try/except in every handler |
| Blocking sync in async | `asyncio.to_thread()` or `run_in_executor` |
| HTTP without timeout | `httpx.AsyncClient(timeout=30.0)` |
| Subprocess without timeout | `asyncio.wait_for()` + `proc.kill()` |
| New HTTP client per request | Module-level singleton |
| Broken signal handler | Just `sys.exit(0)`, no async |
| venv shebang after moving directory | Recreate venv: `uv sync` or `python -m venv .venv` |

### Graceful Shutdown Sequence (Claude Desktop)

1. Client closes stdin
2. Waits for process to finish
3. Sends SIGTERM
4. Waits
5. Sends SIGKILL

---

## 6. Debugging

### Claude Desktop Logs (macOS)

```
~/Library/Logs/Claude/mcp.log              — general log for all MCP
~/Library/Logs/Claude/mcp-server-NAME.log  — log for a specific server
```

### MCP Inspector

```bash
npx @modelcontextprotocol/inspector
```

Browser UI for testing servers.

### Claude Code

```bash
claude --debug mcp
```

### Chrome DevTools in Claude Desktop

File `~/Library/Application Support/Claude/developer_settings.json`:
```json
{"allowDevTools": true}
```

---

## 7. Framework Selection

### FastMCP (recommended for new servers)

- `@mcp.tool()` decorator on a function — and you're done
- Automatic schema generation from type hints
- Pydantic validation for input data
- `ToolError` for structured errors
- ~5x less boilerplate

### Raw MCP SDK

- 1:1 mapping to wire format
- Full control over the protocol
- When you need custom transport or non-standard capabilities

### Node.js (@modelcontextprotocol/sdk)

- `McpServer` class with `server.tool()` registration
- Type safety via TypeScript
- `process.on("SIGTERM")` for signal handling

---

## 8. Pre-Release Checklist

```
STABILITY
[ ] Signal handling (SIGTERM + SIGINT)
[ ] All tool handlers in try/except
[ ] No print() without file=sys.stderr
[ ] HTTP client reuse (not per-request)
[ ] Timeouts on all HTTP and subprocess
[ ] No blocking sync in async handlers

SECURITY
[ ] Path traversal: is_relative_to() on all file operations
[ ] SSRF: validate_url() on all user-provided URLs
[ ] No shell=True in subprocess
[ ] Error messages don't leak secrets
[ ] Credentials not in code / not plaintext
[ ] Sensitive files in .gitignore

QUALITY
[ ] py_compile / node --check passes
[ ] Dependencies pinned (==X.Y.Z)
[ ] venv isolated from system Python
[ ] No dead code / unused dependencies
```
