"""Packaging regression tests.

Guards the failure that unit tests cannot see: every test passes `rules_dir`
explicitly or runs from an editable checkout, so a wheel that ships the rules
where the runtime never looks scans clean and reports 0 code findings.

Building a wheel is slow, so it happens once per session (module-scoped fixture).
"""
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
RULES_DIR = REPO_ROOT / "rules"


def _build_available() -> bool:
    try:
        import build  # noqa: F401
        return True
    except ImportError:
        return shutil.which("uv") is not None


@pytest.fixture(scope="module")
def wheel_path(tmp_path_factory) -> Path:
    """Build a wheel into a temp dir and return its path."""
    if not _build_available():
        pytest.skip("neither 'build' nor 'uv' available to build a wheel")

    outdir = tmp_path_factory.mktemp("wheel")
    try:
        import build  # noqa: F401
        cmd = [sys.executable, "-m", "build", "--wheel", "--outdir", str(outdir), str(REPO_ROOT)]
    except ImportError:
        cmd = ["uv", "build", "--wheel", "--out-dir", str(outdir), str(REPO_ROOT)]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        pytest.skip(f"wheel build failed: {result.stderr[-500:]}")

    wheels = list(outdir.glob("*.whl"))
    assert wheels, "build produced no wheel"
    return wheels[0]


def test_wheel_ships_rules_inside_package(wheel_path):
    """Rules must live under mcp_redteam/rules/ — where get_rules_dir() looks.

    A wheel that puts them in .data/data/ (shared-data) installs them under
    sys.prefix, which the package-relative lookup never reaches.
    """
    names = zipfile.ZipFile(wheel_path).namelist()
    packaged = [n for n in names if n.startswith("mcp_redteam/rules/") and n.endswith(".yaml")]

    assert packaged, (
        "wheel ships no rules under mcp_redteam/rules/ — get_rules_dir() will "
        f"find nothing and every scan reports 0 code findings. Wheel contains: "
        f"{[n for n in names if 'rules' in n][:5]}"
    )


def test_wheel_ships_every_rule_file(wheel_path):
    """No rule file may be dropped during packaging."""
    on_disk = {p.relative_to(RULES_DIR).as_posix() for p in RULES_DIR.rglob("*.yaml")}
    names = zipfile.ZipFile(wheel_path).namelist()
    in_wheel = {
        n[len("mcp_redteam/rules/"):]
        for n in names
        if n.startswith("mcp_redteam/rules/") and n.endswith(".yaml")
    }

    assert on_disk <= in_wheel, f"rules missing from wheel: {sorted(on_disk - in_wheel)}"


def test_installed_layout_resolves_rules(wheel_path, tmp_path, monkeypatch):
    """get_rules_dir() must resolve against the wheel's on-disk layout.

    Unpacks the wheel and points the module's __file__ at the unpacked copy —
    this is what a `pip install` tree looks like, without the cost of one.
    """
    from mcp_redteam.engine import semgrep_runner

    site_packages = tmp_path / "site-packages"
    zipfile.ZipFile(wheel_path).extractall(site_packages)

    monkeypatch.setattr(
        semgrep_runner, "__file__",
        str(site_packages / "mcp_redteam" / "engine" / "semgrep_runner.py"),
    )
    # sys.prefix fallback must not be what rescues this
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "empty-prefix"))

    rules_dir = semgrep_runner.get_rules_dir()

    assert rules_dir.is_dir(), f"rules not resolvable in installed layout: {rules_dir}"
    assert list(rules_dir.rglob("*.yaml")), f"resolved rules dir is empty: {rules_dir}"
