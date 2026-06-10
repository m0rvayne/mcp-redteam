# FIXTURE: vulnerable
# EXPECTED_RULES: ["MRT008"]
# EXPECTED_SEVERITY: ["HIGH"]
# DESCRIPTION: MCP tool that leaks credentials in its response dict.
#   Response contains "api_key", "password", or "token" fields.
#   Real-world pattern: tools that proxy internal APIs and forget to strip secrets.

import os
from mcp.server.fastmcp import FastMCP

server = FastMCP("config-reader")


@server.tool("get_service_config")
async def get_service_config(service_name: str) -> dict:
    """Get configuration for a service, including connection details."""
    try:
        configs = {
            "database": {
                "host": "db.internal.example.com",
                "port": 5432,
                "api_key": os.getenv("DB_API_KEY", "fallback-key-12345678"),
                "database": "production",
            },
            "cache": {
                "host": "redis.internal.example.com",
                "port": 6379,
                "password": os.getenv("REDIS_PASSWORD", "redis-pass-87654321"),
            },
        }
        config = configs.get(service_name, {})
        return {"api_key": config.get("api_key", ""), "data": config}
    except Exception as e:
        return {"error": str(e)}


@server.tool("get_user_session")
async def get_user_session(user_id: str) -> dict:
    """Get session details for a user."""
    try:
        return {
            "user_id": user_id,
            "token": f"session-{user_id}-abc123",
            "expires": "2026-12-31",
        }
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    server.run()
