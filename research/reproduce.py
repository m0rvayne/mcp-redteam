#!/usr/bin/env python3
"""Reproduce the corpus scan from research/corpus-manifest.json.

The 106-server scan published in docs/research/scan-106-servers.md cannot be
reproduced: its corpus was never recorded. This script exists so the current
numbers can be — it clones every repository at the exact commit in the
manifest, re-runs the scanner, and diffs the result against the recorded one.

    python research/reproduce.py --workdir /tmp/mcp-corpus
    python research/reproduce.py --workdir /tmp/mcp-corpus --only oraios/serena

Needs git, semgrep, and roughly 5 GB of disk for the full corpus.
Exit code 1 if the totals do not match what the manifest records.
"""
import argparse
import json
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "research" / "corpus-manifest.json"

# Semgrep results drift slightly between runs on large targets, so an exact
# match is not a reachable bar. Anything past this is a genuine difference.
DRIFT_TOLERANCE = 0.02

sys.path.insert(0, str(REPO_ROOT))


def clone(entry: dict, workdir: Path) -> tuple[str, str]:
    """Clone one repository at its pinned commit. Returns (repo, status)."""
    repo, commit = entry["repo"], entry["commit"]
    dest = workdir / repo.replace("/", "__")
    if (dest / ".git").is_dir():
        return repo, "cached"
    dest.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["git", "init", "-q", str(dest)], check=True, timeout=60)
        subprocess.run(
            ["git", "-C", str(dest), "remote", "add", "origin",
             f"https://github.com/{repo}.git"], check=True, timeout=60)
        # Fetching one commit keeps this honest: the scan runs on exactly the
        # tree the manifest names, not on whatever HEAD happens to be today.
        subprocess.run(
            ["git", "-C", str(dest), "fetch", "-q", "--depth", "1", "origin", commit],
            check=True, timeout=600)
        subprocess.run(
            ["git", "-C", str(dest), "checkout", "-q", "FETCH_HEAD"],
            check=True, timeout=120)
        return repo, "ok"
    except subprocess.CalledProcessError as e:
        return repo, f"failed: {e}"
    except subprocess.TimeoutExpired:
        return repo, "failed: timeout"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workdir", type=Path, required=True,
                    help="where to clone the corpus (reused across runs)")
    ap.add_argument("--only", action="append", default=[],
                    help="limit to these repos (repeatable)")
    ap.add_argument("--jobs", type=int, default=8, help="parallel clones")
    ap.add_argument("--skip-clone", action="store_true",
                    help="assume the workdir is already populated")
    args = ap.parse_args()

    from mcp_redteam.engine.semgrep_runner import run_semgrep, is_semgrep_available
    if not is_semgrep_available():
        print("semgrep is not installed — install it with: pip install semgrep")
        return 2

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    servers = [s for s in manifest["servers"] if s.get("verified_mcp_server")]
    if args.only:
        wanted = set(args.only)
        servers = [s for s in servers if s["repo"] in wanted]
        if not servers:
            print(f"no verified servers matched {sorted(wanted)}")
            return 2

    args.workdir.mkdir(parents=True, exist_ok=True)

    if not args.skip_clone:
        print(f"cloning {len(servers)} repositories into {args.workdir}")
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            for repo, status in pool.map(lambda s: clone(s, args.workdir), servers):
                if status.startswith("failed"):
                    print(f"  {repo}: {status}")

    print(f"scanning with mcp-redteam {manifest['scanner_version']} rules")
    observed = Counter()
    mismatches = []
    for i, entry in enumerate(servers, 1):
        root = args.workdir / entry["repo"].replace("/", "__")
        if not root.is_dir():
            mismatches.append(f"{entry['repo']}: not cloned")
            continue
        findings = run_semgrep(root)
        sev = Counter(f.severity.value for f in findings)
        observed.update(sev)

        recorded = entry.get("severity_as_reported", {})
        # Semgrep is not bit-deterministic on large targets: repeated runs of
        # the same rules over the same tree differ by a handful of findings
        # (measured at 887/885/884 on the largest repository here, even with
        # per-file timeouts disabled). Drift beyond that is a real change.
        rec_total = sum(recorded.values()) or 1
        obs_total = sum(sev.values())
        drift = abs(obs_total - rec_total) / rec_total
        if drift > DRIFT_TOLERANCE:
            mismatches.append(
                f"{entry['repo']}: recorded {rec_total} findings, observed "
                f"{obs_total} ({drift:.1%} drift) — {recorded} vs {dict(sev)}")
        if i % 10 == 0:
            print(f"  {i}/{len(servers)}")

    print("\nobserved totals:", dict(observed))
    if not args.only:
        print("manifest totals:", manifest["totals"]["severity_as_reported"])

    if mismatches:
        print(f"\n{len(mismatches)} repositories differ from the manifest:")
        for m in mismatches[:20]:
            print("  " + m)
        if len(mismatches) > 20:
            print(f"  ... and {len(mismatches) - 20} more")
        print(f"\nDrift under {DRIFT_TOLERANCE:.0%} per repository is tolerated — semgrep "
              "is not bit-deterministic. Larger differences mean the rules changed; "
              "regenerate the manifest if that is intentional.")
        return 1

    print("\nmatches the manifest.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
