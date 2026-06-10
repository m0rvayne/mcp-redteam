# FIXTURE: vulnerable
# EXPECTED_RULES: ["MRT006"]
# EXPECTED_SEVERITY: ["MEDIUM"]
# DESCRIPTION: MCP server with print() calls that pollute JSON-RPC stdio stream.
#   print() writes to stdout, which in stdio transport mode corrupts the protocol.
#   Real-world pattern: debug prints left in production MCP servers.

from mcp.server.fastmcp import FastMCP

server = FastMCP("noisy-server")


@server.tool("process_data")
async def process_data(data: str) -> str:
    """Process input data and return result."""
    try:
        print(f"Processing data: {data}")
        result = data.upper()
        print(f"Result: {result}")
        return result
    except Exception as e:
        print(f"Error: {e}")
        return str(e)


@server.tool("ping")
async def ping() -> str:
    """Simple health check."""
    try:
        print("Ping received!")
        return "pong"
    except Exception as e:
        return str(e)


if __name__ == "__main__":
    server.run()
