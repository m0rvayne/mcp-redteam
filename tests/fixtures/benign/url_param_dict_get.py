# FIXTURE: benign
# EXPECTED_RULES: []
# EXPECTED_SEVERITY: []
"""Benign: a function that takes a `url` parameter and reads dict keys.

Regression guard for an MRT003 false positive found by dogfooding: the generic
`$CLIENT.get($URL, ...)` sink matched plain `dict.get("literal")` calls, so any
function with a URL-named parameter that also read a dict was reported as SSRF.
That shape is extremely common in MCP servers.

Nothing here makes a request with a caller-controlled URL.
"""

import logging

logger = logging.getLogger(__name__)


def summarize_scan(url: str, metadata: dict) -> dict:
    """Read scan metadata. `url` is only ever echoed back, never fetched."""
    tool_count = metadata.get("tool_count", 0)
    descriptions = metadata.get("descriptions") or {}
    errors = metadata.get("errors", [])

    logger.info("scanned %s", url)
    return {
        "target": url,
        "tools": tool_count,
        "described": len(descriptions),
        "errors": len(errors),
    }


def build_report(endpoint: str, config: dict) -> str:
    """`endpoint` is a label here; config lookups are dict access, not requests."""
    title = config.get("title", "report")
    fmt = config.get("format", "text")
    return f"{title} [{fmt}] for {endpoint}"


def load_cached(webhook_url: str, store: dict) -> dict:
    """Session-like name on a plain dict must not be treated as an HTTP client."""
    session = {"cached": True}
    entry = session.get("cached")
    return {"webhook": webhook_url, "cached": entry, "size": len(store)}
