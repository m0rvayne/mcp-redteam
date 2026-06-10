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
     mcp-redteam v0.1.0 · m0rvayne
     {MODE} · Security · Health
```

Output this banner BEFORE reading CLAUDE.md or any other files. Then proceed to Step 1.

## Step 0.9 — Results Directory & History

Before reading instructions, set up persistent results:

1. Check if `~/Desktop/redteam-results/` exists. If not, ask user:
   "I need a folder to store audit history between runs. Create `~/Desktop/redteam-results/`?"
   Wait for confirmation. Create the directory.

2. Check for previous audit files: `~/Desktop/redteam-results/*.jsonl`
   Files are named `audit-YYYY-MM-DD-HHMMSS.jsonl`.

3. If previous audits exist, read the MOST RECENT one. This is a compact machine log — one JSON object per line:
   ```
   {"r":"MRT001","f":"server.py","l":42,"s":"C","x":"fixed"}
   ```
   Fields: `r`=rule_id, `f`=file, `l`=line, `s`=severity(C/H/M/L), `x`=status(new/confirmed/fixed)

4. Keep this history in memory. During the audit, compare each finding against history:
   - Found before AND found again → status `confirmed` (higher confidence)
   - Found before but NOT found now → status `fixed` (mention in report: "previously found, now resolved")
   - NOT found before but found now → status `new`

5. After the audit completes, write a new `.jsonl` file to `~/Desktop/redteam-results/`:
   One line per finding, minimal format:
   ```
   {"r":"MRT001","f":"server.py","l":42,"s":"C","x":"new","t":"shell injection in tool handler"}
   ```
   Fields: `r`=rule, `f`=file, `l`=line, `s`=severity (C/H/M/L/I), `x`=status, `t`=title (short)

   Also write one summary line at the end:
   ```
   {"_":"summary","total":37,"C":5,"H":12,"M":14,"L":6,"new":3,"confirmed":30,"fixed":4,"date":"2026-06-11T22:00:00"}
   ```

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
9. **Write audit log** to `~/Desktop/redteam-results/audit-YYYY-MM-DD-HHMMSS.jsonl` (compact JSONL, one line per finding — see Step 0.9 format)
10. If previous audit existed, mention in report summary: "X findings confirmed from previous audit, Y new, Z fixed since last run"
