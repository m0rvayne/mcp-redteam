---
name: mcp-redteam
description: Security audit of MCP servers. Safe mode (default) = source analysis + read-only probing. Active mode = controlled payload testing.
user_invocable: true
trigger: /mcp-redteam
---

# MCP Red Team

## Step 0 — Mode & Language

Check the user's command:
- `/mcp-redteam` → **Safe Mode** (default). Source code analysis + read-only tools only. Production-safe.
- `/mcp-redteam active` → **Active Mode**. Safe Mode + controlled payloads on read-only tools. Requires consent.

Then ask language in plain text (do NOT use AskUserQuestion with options):

**"Report language? Type: en / ru / ua (default: en)"**

Accept: `en`, `eng`, `english`, `ru`, `рус`, `русский`, `ua`, `укр`, `українська`. Default to English if user skips or gives unsupported language.

**Translation rules:**
- TRANSLATE: section headers, finding descriptions, remediation text, executive summary
- KEEP IN ENGLISH: severity levels (CRITICAL, HIGH, MEDIUM, LOW), technical terms (SSRF, Path Traversal, OAuth, RCE), tool names, file paths, code snippets

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

## Step 3 — Report

6. Generate HTML report DIRECTLY in the selected language
7. **All `<details>` blocks CLOSED by default — no `open` attribute**
8. Present findings, offer to fix
