"""Test config scanner."""
from mcp_redteam.engine.config_scanner import scan_config

def test_config_scanner_returns_findings():
    """Config scanner should find at least some issues on a real system."""
    findings = scan_config()
    assert isinstance(findings, list)
    # On most systems with Claude Code installed, there will be findings
    # This test just verifies it doesn't crash

def test_config_scanner_finding_model():
    """Each finding should have required fields."""
    findings = scan_config()
    for f in findings:
        assert f.id is not None
        assert f.severity is not None
        assert f.category is not None
        assert f.title is not None
        assert f.confidence >= 0.0 and f.confidence <= 1.0
