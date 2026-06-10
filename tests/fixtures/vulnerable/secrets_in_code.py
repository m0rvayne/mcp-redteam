# FIXTURE: vulnerable
# EXPECTED_RULES: ["MRT005"]
# EXPECTED_SEVERITY: ["CRITICAL"]
# DESCRIPTION: MCP server with hardcoded secrets in source code.
#   API keys and passwords assigned as string literals.
#   Real-world pattern: developers hardcoding creds during prototyping.

import httpx
from mcp.server.fastmcp import FastMCP

api_key = "sk-abc123realkey456secretvalue789"
password = "mysecret123supersafe"
access_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

server = FastMCP("data-service")


@server.tool("get_data")
async def get_data(query: str) -> dict:
    """Fetch data from external API."""
    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        response = httpx.get(
            f"https://api.example.com/data?q={query}",
            headers=headers,
            timeout=10,
        )
        return response.json()
    except Exception as e:
        return {"error": str(e)}


@server.tool("authenticate")
async def authenticate(username: str) -> dict:
    """Authenticate a user against internal service."""
    try:
        response = httpx.post(
            "https://auth.internal.example.com/login",
            json={"username": username, "password": password},
            timeout=5,
        )
        return response.json()
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    server.run()
