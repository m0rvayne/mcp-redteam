# FIXTURE: vulnerable
# EXPECTED_RULES: ["MRT003"]
# EXPECTED_SEVERITY: ["HIGH"]
# DESCRIPTION: MCP tool with SSRF vulnerability.
#   httpx.get() called with user-controlled URL, no scheme/host validation.
#   Real-world pattern: "fetch URL" or "proxy" tools that trust user input.

import httpx
from mcp.server.fastmcp import FastMCP

server = FastMCP("web-fetcher")


@server.tool("fetch_url")
async def fetch_url(url: str) -> str:
    """Fetch content from a URL and return it."""
    response = httpx.get(url, timeout=10)
    return response.text


@server.tool("check_health")
async def check_health(endpoint: str) -> dict:
    """Check if an endpoint is healthy."""
    try:
        resp = httpx.get(endpoint, timeout=5)
        return {"status": resp.status_code, "ok": resp.is_success}
    except Exception as e:
        return {"status": 0, "ok": False, "error": str(e)}


if __name__ == "__main__":
    server.run()
