"""Version consistency tests.

The version is declared in five places that no build step ties together, so they
drift silently — plugin.json sat at 0.3.0 and the SKILL.md banner at v0.1.0 while
the package shipped 0.5.1, meaning every plugin user saw a wrong version.
"""
import json
import re
from pathlib import Path

import pytest

from mcp_redteam import __version__

REPO_ROOT = Path(__file__).parent.parent


def test_pyproject_matches_package_version():
    """pyproject.toml version == mcp_redteam.__version__."""
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match, "no version field in pyproject.toml"
    assert match.group(1) == __version__


def test_plugin_manifest_matches_package_version():
    """.claude-plugin/plugin.json version == package version."""
    manifest = json.loads((REPO_ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    assert manifest["version"] == __version__


def test_skill_banner_matches_package_version():
    """The banner every plugin user sees must show the real version."""
    skill = (REPO_ROOT / "skills" / "mcp-redteam" / "SKILL.md").read_text(encoding="utf-8")
    versions = set(re.findall(r"mcp-redteam v(\d+\.\d+\.\d+)", skill))
    assert versions, "no version string found in SKILL.md banner"
    assert versions == {__version__}, f"SKILL.md shows {versions}, package is {__version__}"


def test_security_policy_covers_current_minor():
    """SECURITY.md must list the shipping minor as supported."""
    policy = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")
    major_minor = ".".join(__version__.split(".")[:2])
    assert f"{major_minor}.x" in policy, (
        f"SECURITY.md does not mention {major_minor}.x as a supported version"
    )


def test_readme_action_pin_matches_package_version():
    """The `uses:` pin in README must point at the current tag."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    pins = set(re.findall(r"m0rvayne/mcp-redteam@v(\d+\.\d+\.\d+)", readme))
    if not pins:
        pytest.skip("README does not pin a versioned action reference")
    assert pins == {__version__}, f"README pins {pins}, package is {__version__}"
