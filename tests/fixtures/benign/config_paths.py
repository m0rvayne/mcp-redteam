# FIXTURE: benign
# EXPECTED_RULES: []
# EXPECTED_SEVERITY: []
# DESCRIPTION: Safe patterns that should NOT trigger path traversal or SSRF.
#   - Path.home() / ".config" / "app" chains (not user-controlled)
#   - API response .get("url") for display (not used in HTTP requests)
#   Real-world pattern: config file readers, API wrappers returning metadata.

import httpx
import logging
from pathlib import Path

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)
server = FastMCP("config-reader")

# Multi-level config path chains — safe, not user-controlled
CONFIG_DIR = Path.home() / ".config" / "myapp"
DATA_DIR = Path.home() / ".local" / "share" / "myapp"
CACHE_DIR = Path(__file__).parent / "data" / "cache"


@server.tool("get_config")
async def get_config(key: str) -> str:
    """Read a config value from the app config file."""
    try:
        config_file = CONFIG_DIR / "settings.json"
        if config_file.is_file():
            import json
            data = json.loads(config_file.read_text())
            return str(data.get(key, "not found"))
        return "config file not found"
    except Exception:
        logger.error("Config read failed for key: %s", key)
        return "error"


@server.tool("get_notebook_info")
async def get_notebook_info(notebook_id: str) -> dict:
    """Get notebook metadata from API — returns URLs for display only."""
    try:
        response = httpx.get(
            f"https://api.example.com/v1/notebooks/{notebook_id}",
            timeout=10,
        )
        data = response.json()
        # These URL fields come from the API response, NOT user input
        return {
            "id": data.get("id"),
            "title": data.get("title"),
            "url": data.get("url"),
            "link": data.get("link"),
            "endpoint": data.get("endpoint"),
        }
    except Exception:
        logger.error("API call failed for notebook: %s", notebook_id)
        return {"error": "failed"}
