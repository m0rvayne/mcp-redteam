# FIXTURE: vulnerable
# EXPECTED_RULES: ["MRT007"]
# EXPECTED_SEVERITY: ["MEDIUM"]
# DESCRIPTION: MCP tool functions without try/except error handling.
#   Unhandled exceptions crash the server or leak stack traces to clients.
#   Real-world pattern: quick-and-dirty tool implementations.

import json
from mcp.server.fastmcp import FastMCP

server = FastMCP("fragile-server")


@server.tool("parse_json")
async def parse_json(raw: str) -> dict:
    """Parse a JSON string and return the object."""
    data = json.loads(raw)
    return data


@server.tool("divide")
def divide(a: float, b: float) -> str:
    """Divide two numbers."""
    result = a / b
    return str(result)


@server.tool("get_item")
async def get_item(items: list, index: int) -> str:
    """Get an item from a list by index."""
    return str(items[index])


if __name__ == "__main__":
    server.run()
