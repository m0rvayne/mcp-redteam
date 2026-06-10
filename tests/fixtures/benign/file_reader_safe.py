# FIXTURE: benign
# EXPECTED_RULES: []
# EXPECTED_SEVERITY: []
# DESCRIPTION: Safe MCP file reader tool. Path resolved with Path.resolve(),
#   validated with startswith() to prevent traversal. Proper error handling.

import logging
from pathlib import Path

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

server = FastMCP("safe-file-reader")

WORKSPACE_ROOT = Path("/app/workspace").resolve()


@server.tool("read_file")
async def read_file(path: str) -> str:
    """Read a file from the workspace directory only."""
    try:
        resolved = Path(path).resolve()

        if not str(resolved).startswith(str(WORKSPACE_ROOT)):
            return "Error: Access denied. Path is outside workspace."

        if not resolved.is_file():
            return f"Error: File not found: {path}"

        content = resolved.read_text(encoding="utf-8")
        return content
    except PermissionError:
        logger.warning("Permission denied for path: %s", path)
        return "Error: Permission denied"
    except UnicodeDecodeError:
        return "Error: File is not valid UTF-8 text"
    except Exception as e:
        logger.exception("Unexpected error reading file: %s", path)
        return f"Error: {type(e).__name__}"


@server.tool("list_files")
async def list_files(directory: str) -> list[str]:
    """List files in a workspace subdirectory."""
    try:
        resolved = Path(directory).resolve()

        if not str(resolved).startswith(str(WORKSPACE_ROOT)):
            return ["Error: Access denied. Path is outside workspace."]

        if not resolved.is_dir():
            return [f"Error: Not a directory: {directory}"]

        return [str(p.relative_to(WORKSPACE_ROOT)) for p in resolved.iterdir() if p.is_file()]
    except Exception as e:
        logger.exception("Unexpected error listing files: %s", directory)
        return [f"Error: {type(e).__name__}"]


if __name__ == "__main__":
    server.run()
