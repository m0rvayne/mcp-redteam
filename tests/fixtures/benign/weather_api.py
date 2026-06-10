# FIXTURE: benign
# EXPECTED_RULES: []
# EXPECTED_SEVERITY: []
"""Benign MCP server — weather lookup from local data, no network calls."""

import logging
from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)
server = FastMCP("weather")

WEATHER_DATA = {
    "london": {"temp": 15, "condition": "cloudy"},
    "tokyo": {"temp": 28, "condition": "sunny"},
    "new york": {"temp": 22, "condition": "partly cloudy"},
}


@server.tool("get_weather")
async def get_weather(city: str) -> dict:
    """Get current weather for a city from local dataset."""
    try:
        normalized = city.strip().lower()
        if normalized not in WEATHER_DATA:
            return {"error": f"City '{city}' not in database. Available: {list(WEATHER_DATA.keys())}"}
        data = WEATHER_DATA[normalized]
        return {"city": city, "temperature_c": data["temp"], "condition": data["condition"]}
    except Exception:
        logger.error("Weather lookup failed for %s", city)
        return {"error": "Lookup failed"}
