# FIXTURE: benign
# EXPECTED_RULES: []
# EXPECTED_SEVERITY: []
# DESCRIPTION: Safe MCP echo server. Returns input as-is, no side effects,
#   proper error handling, no external calls.

import logging
from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

server = FastMCP("echo-server")


@server.tool("echo")
async def echo(message: str) -> str:
    """Return the input message as-is."""
    try:
        return message
    except Exception as e:
        logger.exception("Unexpected error in echo")
        return f"Error: {type(e).__name__}"


@server.tool("echo_upper")
async def echo_upper(message: str) -> str:
    """Return the input message in uppercase."""
    try:
        return message.upper()
    except Exception as e:
        logger.exception("Unexpected error in echo_upper")
        return f"Error: {type(e).__name__}"


@server.tool("echo_reverse")
async def echo_reverse(message: str) -> str:
    """Return the input message reversed."""
    try:
        return message[::-1]
    except Exception as e:
        logger.exception("Unexpected error in echo_reverse")
        return f"Error: {type(e).__name__}"


if __name__ == "__main__":
    server.run()
