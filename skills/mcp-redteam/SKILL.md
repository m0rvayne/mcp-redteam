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
