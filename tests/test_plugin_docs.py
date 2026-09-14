"""Consistency between the plugin instructions and the code.

What these tests are: a check that CLAUDE.md and SKILL.md do not contradict the
implementation or reference things that do not exist.

What they are not: a test of the plugin's behaviour. The plugin is an LLM
following prose, and no unit test establishes that it audits well. It had zero
coverage of any kind before this; these close the part that is mechanically
checkable, and the gap should be stated rather than papered over.

The failures they would have caught, all real:
  - the plugin wrote history to ~/Desktop/redteam-results/ while the CLI used
    ~/.mcp-redteam/baselines/ — two incompatible baselines in one project
  - severity guidance had no INFO tier, so findings off the MCP tool surface had
    nowhere to go and the plugin reproduced the noise the CLI had just removed
"""
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
CLAUDE_MD = REPO_ROOT / "CLAUDE.md"
SKILL_MD = REPO_ROOT / "skills" / "mcp-redteam" / "SKILL.md"


@pytest.fixture(scope="module")
def claude_md() -> str:
    return CLAUDE_MD.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def skill_md() -> str:
    return SKILL_MD.read_text(encoding="utf-8")


def test_referenced_paths_exist(claude_md, skill_md):
    """A plugin run that reads a missing file fails halfway through an audit."""
    referenced = set()
    for text in (claude_md, skill_md):
        for m in re.finditer(
            r"`((?:docs|examples|templates|skills|rules|research)/[A-Za-z0-9_./-]+)`", text
        ):
            referenced.add(m.group(1))

    missing = [r for r in sorted(referenced) if not (REPO_ROOT / r).exists()]
    assert not missing, f"plugin instructions reference paths that do not exist: {missing}"


def test_risk_score_weights_match_the_code(claude_md):
    """The plugin computes a risk score by hand; it must match the CLI's."""
    from mcp_redteam.models import SEVERITY_SCORES, Severity

    documented = dict(re.findall(r"^- (CRITICAL|HIGH|MEDIUM|LOW) [a-z ]*?:?\s*\+(\d+)",
                                 claude_md, re.MULTILINE))
    if not documented:
        pytest.skip("CLAUDE.md no longer documents risk score weights")

    for name, points in documented.items():
        expected = SEVERITY_SCORES[Severity(name)]
        assert int(points) == expected, (
            f"CLAUDE.md gives {name} +{points}, the code gives +{expected}"
        )


def test_every_severity_level_is_documented(claude_md):
    """A level the code can emit but the plugin cannot name has nowhere to go."""
    from mcp_redteam.models import Severity

    for severity in Severity:
        assert re.search(rf"^\|\s*{severity.value}\s*\|", claude_md, re.MULTILINE), (
            f"{severity.value} is missing from the severity table in CLAUDE.md — "
            "the plugin has no guidance for findings at that level"
        )


def test_plugin_and_cli_share_one_baseline_location(skill_md):
    """Two baselines in one project means neither can be trusted."""
    from mcp_redteam.engine.audit_history import get_baseline_dir

    baseline = get_baseline_dir()
    relative = f"~/{baseline.relative_to(Path.home())}"

    assert relative in skill_md, (
        f"SKILL.md must point at the CLI's baseline directory ({relative})"
    )
    assert "Desktop/redteam-results" not in skill_md, (
        "SKILL.md still writes audit history to the Desktop, diverging from the CLI"
    )


def test_documented_cli_commands_exist(claude_md, skill_md):
    """A command shown in the instructions has to be a real one."""
    from mcp_redteam.cli import app

    real = {c.name or c.callback.__name__.replace("_", "-") for c in app.registered_commands}
    shown = set()
    for text in (claude_md, skill_md):
        for m in re.finditer(r"`mcp-redteam ([a-z][a-z-]*)", text):
            shown.add(m.group(1))

    unknown = sorted(shown - real - {"active", "safe"})  # plugin modes, not CLI verbs
    assert not unknown, f"instructions show CLI commands that do not exist: {unknown}"


def test_safe_mode_forbids_state_modifying_tools(claude_md, skill_md):
    """The plugin's one hard safety property, in both documents."""
    for name, text in (("CLAUDE.md", claude_md), ("SKILL.md", skill_md)):
        assert re.search(r"create[,/ ]|update|delete", text, re.IGNORECASE), (
            f"{name} no longer enumerates state-modifying tools"
        )
    assert "NEVER" in claude_md, "CLAUDE.md lost its NEVER list"
    assert re.search(r"never call state-modifying tools|State-modifying tools.*NEVER",
                     claude_md, re.IGNORECASE | re.DOTALL), (
        "CLAUDE.md no longer forbids calling state-modifying tools"
    )


def test_active_mode_is_opt_in(claude_md, skill_md):
    """Active mode must stay opt-in: it sends payloads at live infrastructure."""
    assert re.search(r"Safe Mode is default|Safe Mode \(default\)", claude_md), (
        "CLAUDE.md no longer states that Safe Mode is the default"
    )
    assert re.search(r"consent|confirmation|Wait for confirmation", skill_md, re.IGNORECASE), (
        "SKILL.md no longer requires consent before Active Mode"
    )


def test_tool_surface_guidance_is_present(claude_md):
    """Without it the plugin reproduces the noise the CLI stopped producing.

    Measured: 96% of findings on a 56-server corpus were in files registering no
    MCP tools. Asserting only that the phrase "tool surface" appears is not
    enough — it also appears in the severity table, so this checks the actual
    instructions an agent has to follow.
    """
    required = {
        "the rule to scope by surface":
            r"[Rr]ate a finding on the MCP tool surface only",
        "what counts as on-surface":
            r"registers MCP tools.{0,40}or.{0,60}reachable",
        "reachability through imports":
            r"reachable from such a file through imports",
        "where off-surface findings go":
            r"[Oo]ff the surface\s*→\s*\*\*INFO\*\*",
        "keep them, do not delete":
            r"do not delete it",
        "helpers are still in scope":
            r"utils/files\.py|helper.{0,40}handler",
        "targets with no tools are left alone":
            r"registers no tools at all\s*→\s*[Rr]ate normally",
    }
    missing = [
        label for label, pattern in required.items()
        if not __import__("re").search(pattern, claude_md, __import__("re").DOTALL)
    ]
    assert not missing, (
        "CLAUDE.md is missing tool-surface guidance the plugin needs: " + ", ".join(missing)
    )
