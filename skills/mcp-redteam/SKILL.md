---
name: mcp-redteam
description: Security audit of MCP servers. Safe mode (default) = source analysis + read-only probing. Active mode = controlled payload testing.
user_invocable: true
trigger: /mcp-redteam
---

# MCP Red Team

## Step 0 — Mode & Language

**If arguments provided** (e.g. `/mcp-redteam active ru`): parse first token as mode (safe/active), second as language (en/ru/ua). Skip interactive selection.

**Otherwise**, use AskUserQuestion for interactive selection:

1. Ask audit mode:
   - Use AskUserQuestion with options: `Safe Mode` (description: "Source analysis + read-only probing. Production-safe.") and `Active Mode` (description: "Safe Mode + controlled payloads on read-only tools.")

2. Ask report language:
   - Use AskUserQuestion with options: `English`, `Russian`, `Ukrainian`

Mapping: Safe Mode = default, Active Mode = opt-in. English = default language.
Also accept typed shortcuts: `en`, `eng`, `ru`, `рус`, `русский`, `ua`, `укр`, `українська`.

**Translation rules:**
- TRANSLATE: section headers, finding descriptions, remediation text, executive summary
- KEEP IN ENGLISH: severity levels (CRITICAL, HIGH, MEDIUM, LOW), technical terms (SSRF, Path Traversal, OAuth, RCE), tool names, file paths, code snippets

## Step 0.5 — Banner

Immediately after determining the mode and language, output the following banner as a fenced code block (for monospace rendering). Substitute `{MODE}` with the actual mode line:
- Safe Mode → `mode: Safe Mode (read-only)`
- Active Mode → `mode: Active Mode (controlled payloads)`

```
  ███  ████ ███  ███ ████  ██  █   █
  █  █ █    █  █  █  █    █  █ ██ ██
  ███  ███  █  █  █  ███  ████ █ █ █
  █ █  █    █  █  █  █    █  █ █   █
  █  █ ████ ███   █  ████ █  █ █   █
  ─────────────────────────────────────
     mcp-redteam v0.5.2 · m0rvayne
     {MODE} · Security · Health
```

Output this banner BEFORE reading CLAUDE.md or any other files. Then proceed to Step 1.

## Step 0.9 — Audit History

The CLI already keeps a baseline; the plugin uses the same one, so a finding
first seen by `mcp-redteam scan` is recognised here and vice versa. Two separate
histories in one project mean neither is trustworthy.

1. Baselines live in `~/.mcp-redteam/baselines/`, one JSONL file per target,
   named by the first 16 hex characters of the SHA-256 of the target path.
   The directory is created on demand — do not ask the user to make one, and do
   not write to the Desktop.

2. Read the most recent entry for this target, if any. Each line is one run:
   ```
   {"timestamp": "...", "target": "...", "mode": "plugin",
    "findings": [{"id": "MRT001", "rule_id": "MRT001", "file": "server.py",
                  "line": 42, "severity": "CRITICAL"}],
    "total": 1, "risk_score": 25}
   ```

3. Compare each finding of this audit against that entry, keyed on
   `(rule_id, file, line)`:
   - in both → **confirmed** (higher confidence, it survived a fix round)
   - in the baseline only → **fixed** (say so in the report)
   - in this audit only → **new**

4. Append one line for this run in the same shape, with `"mode": "plugin"`.
   Keep `severity` as the full word (`CRITICAL`, not `C`) — the CLI reads these
   files too, and a private abbreviation would break it.

**This log is for AI consumption only.** Minimal tokens, no descriptions, no evidence. The human reads the HTML report.

## Step 1 — Read instructions

Read from the plugin root:
1. `CLAUDE.md` — full architecture, agent prompts, safety rules, fix strategy
2. `docs/attack-playbook.md` — vulnerability patterns and code path examples

## Step 1.5 — Active Mode consent (only if active)

If Active Mode: tell the user:

"Active Mode runs controlled payloads on READ-ONLY tools to confirm vulnerabilities. It will NOT call create/update/delete/send tools. Still, I recommend committing your current state first: `git add -A && git commit -m 'pre-audit'`

Proceed with Active Mode?"

Wait for confirmation. If denied → fall back to Safe Mode.

## Step 1.6 — Claude Desktop servers

After discovery, if servers found in Claude Desktop but not Claude Code:

"I found {N} MCP servers in Claude Desktop not connected to Claude Code. I can read their source code but cannot probe their tools live.

For full probing, add them to Claude Code: `claude mcp add {name} -- {command} {args}`

Without this: source-code-only audit (still valuable)."

## Step 2 — Discover & audit

1. Discover MCP servers from ALL sources (Claude Code + Claude Desktop)
2. Classify: CONNECTED (can probe read-only tools) or SOURCE-ONLY (code analysis)
3. Classify by type (file, HTTP/API, browser, native, database)
4. **Phase 1** — spawn 1 agent per server (parallel). Pass the audit MODE (safe/active) to each agent.
5. **Phase 2** — spawn 1 coordinator. Receives all Phase 1 output. Maps cross-server chains (analytical). Generates HTML report.

**IMPORTANT: Pass the selected language AND mode to both Phase 1 agents and Phase 2 coordinator.**

## Step 3 — Report & Save

6. Generate HTML report DIRECTLY in the selected language
7. **All `<details>` blocks CLOSED by default — no `open` attribute**
8. Present findings, offer to fix
9. **Append the run** to the shared baseline in `~/.mcp-redteam/baselines/` (see Step 0.9 — same format the CLI uses)
10. If previous audit existed, mention in report summary: "X findings confirmed from previous audit, Y new, Z fixed since last run"
