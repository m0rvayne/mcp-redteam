# FIXTURE: vulnerable
# EXPECTED_RULES: ["MRT002"]
# EXPECTED_SEVERITY: ["HIGH"]
# DESCRIPTION: MCP tool with path traversal vulnerability.
#   open() called with user-controlled path, no realpath/resolve or prefix check.
#   Real-world pattern: "read file" tools that trust the path argument.

from mcp.server.fastmcp import FastMCP

server = FastMCP("file-reader")


@server.tool("read_file")
async def read_file(path: str) -> str:
    """Read a file from the workspace and return its contents."""
    try:
        with open(path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return f"File not found: {path}"


@server.tool("read_config")
async def read_config(filename: str) -> str:
    """Read a config file by name."""
    try:
        import os
        full_path = os.path.join("/app/configs", filename)
        with open(full_path, "r") as f:
            return f.read()
    except Exception as e:
        return str(e)


@server.tool("read_with_path_operator")
async def read_with_path_operator(user_path: str) -> str:
    """Read a file using Path / operator — should trigger MRT002."""
    from pathlib import Path

    base = Path("/data")
    full = base / user_path  # vulnerable
    return full.read_text()


@server.tool("read_with_fstring")
async def read_with_fstring(name: str) -> str:
    """Read a file using f-string path — should trigger MRT002."""
    path = f"/uploads/{name}/config.json"  # vulnerable
    return open(path).read()


if __name__ == "__main__":
    server.run()
