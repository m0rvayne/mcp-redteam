# Corpus and reproduction

The 106-server scan published in [`docs/research/scan-106-servers.md`](../docs/research/scan-106-servers.md)
**cannot be reproduced.** Its corpus was never recorded — only about a dozen of
the servers are named in the post, the rest are lost. Nobody can check those
numbers, including us.

This directory exists so the current ones can be checked.

## Files

| File | What it is |
|---|---|
| `corpus-manifest.json` | Every repository, pinned to an exact commit, with its per-rule and per-severity results |
| `reproduce.py` | Clones the corpus at those commits, re-scans, and diffs against the manifest |

## Reproducing

```bash
pip install semgrep
python research/reproduce.py --workdir /tmp/mcp-corpus
```

Needs about 5 GB of disk and takes roughly an hour. A single repository is much
faster:

```bash
python research/reproduce.py --workdir /tmp/mcp-corpus --only oraios/serena
```

Exit code 0 means the scan matches the manifest.

## How the corpus was selected

Selection is mechanical, so it can be repeated rather than trusted:

1. GitHub repository search, topics `mcp-server` and `mcp-servers`.
2. Language Python, TypeScript or JavaScript — what the rules cover.
3. Not archived; repository under 200 MB, which excludes platforms that merely
   ship an MCP integration.
4. MCP SDKs and frameworks themselves excluded — they are not servers under test.
5. **After cloning**, a repository counts only if it *both* declares an MCP SDK
   dependency in a manifest file *and* registers a tool or server in source.

Step 5 does most of the work: **56 of 112 topic-labelled repositories failed
it.** Half of what GitHub calls an MCP server does not depend on an MCP SDK at
all. A topic label is a claim, not evidence.

## What the numbers mean

`severity_as_reported` is what a user sees. `severity_before_surface_demotion`
is what the rules produced before findings outside the MCP tool surface were
lowered to INFO — see [`mcp_redteam/engine/tool_surface.py`](../mcp_redteam/engine/tool_surface.py).

Both are recorded because the gap between them is the point: the scanner used to
report every one of those as HIGH.

## Caveats, stated rather than buried

- **Semgrep is not bit-deterministic.** Repeated runs over the same tree differ
  by a few findings — measured at 887 / 885 / 884 on the largest repository
  here, even with per-file timeouts disabled. `reproduce.py` tolerates 2% drift
  per repository and flags anything larger. An exact match is not a reachable
  bar, and claiming one would be false.
- **26% of findings are unclassified.** In 12 of the 56 servers no tool
  registration matched the known SDK idioms, so nothing was reclassified there.
  Those findings keep the severity the rules gave them.
- **This measures finding volume, not a false positive rate.** Establishing the
  latter requires reviewing findings by hand; sampling suggests the remaining
  MRT002 and MRT006 volume is still largely noise. Claiming a measured FP rate
  from these totals would be an overstatement.
- **A different corpus gives different numbers.** These 56 servers are the
  most-starred self-labelled ones, which is not a random sample of anything.
