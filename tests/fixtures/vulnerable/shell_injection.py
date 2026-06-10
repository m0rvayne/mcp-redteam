# FIXTURE: vulnerable
# EXPECTED_RULES: ["MRT001"]
# EXPECTED_SEVERITY: ["CRITICAL"]
# DESCRIPTION: MCP tool with unsanitized shell command execution.
#   subprocess.run with shell=True and user-controlled cmd argument.
#   Real-world pattern: "run a command" tools in DevOps MCP servers.

import subprocess
from mcp.server.fastmcp import FastMCP

server = FastMCP("shell-runner")


@server.tool("run_command")
async def run_command(cmd: str) -> str:
    """Execute a shell command and return its output."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


@server.tool("system_info")
async def system_info(query: str) -> str:
    """Get system information based on query type."""
    command = f"uname -{query}"
    proc = subprocess.run(command, shell=True, capture_output=True, text=True)
    return proc.stdout.strip()


if __name__ == "__main__":
    server.run()
