---
name: mcp-redteam
description: Full audit and penetration test of all connected MCP servers. One agent per server + chain attacker coordinator. Health, architecture, completeness, security.
user_invocable: true
trigger: /mcp-redteam
---

# MCP Red Team

## Step 0 — Language

Before anything else, ask the user which language they want the report in. Use AskUserQuestion:

**"Which language for the audit report?"**
- English
- Русский
- Українська

Store the answer. Default: **English** (if user skips, says "go", or requests unsupported language).
If user requests a language not listed — respond: "Currently supported: English, Русский, Українська. Which one?" and wait for answer.

All findings, executive summary, remediation roadmap, and HTML report must be written in the selected language. Agent prompts stay in English (internal), but all user-facing output uses the selected language.

**Translation rules:**
- TRANSLATE: section headers, finding descriptions, remediation text, executive summary
- KEEP IN ENGLISH: severity levels (CRITICAL, HIGH, MEDIUM, LOW), technical terms (SSRF, Path Traversal, OAuth, RCE), tool names, file paths, code snippets

## Step 1 — Read instructions

Read from the plugin root:
1. `CLAUDE.md` — full architecture, agent prompts, fix strategy
2. `docs/attack-playbook.md` — all attack vectors with payloads

## Step 1.5 — Permissions advisory

Before starting the audit, tell the user:

"This audit will actively call your MCP tools with test payloads to prove vulnerabilities. You'll see permission prompts for tool calls. Options:
1. **Approve each call manually** (safest, slower)
2. **Auto-approve read-only tools** — add to your project's .claude/settings.json:
```json
{"permissions": {"allow": ["mcp__*__read_*", "mcp__*__get_*", "mcp__*__list_*", "mcp__*__search_*"]}}
```
3. **Full auto-approve** (fastest, use only on your own infrastructure)"

## Step 2 — Discover & audit

3. Discover MCP servers (Claude Code settings.json + Claude Desktop config + .mcp.json)
4. Classify each server by type (file, HTTP/API, browser, native, database)
5. **Phase 1** — spawn 1 agent per server (parallel). Each reads source code, audits all 4 categories, outputs findings + chainable assets
6. **Phase 2** — spawn 1 coordinator agent. Receives all Phase 1 output. Builds and TESTS cross-server attack chains. Generates HTML report.

## Step 3 — Report

7. Generate HTML report in the selected language
8. **IMPORTANT: All `<details>` blocks must be CLOSED by default — no `open` attribute anywhere**
9. Present findings, offer to fix
