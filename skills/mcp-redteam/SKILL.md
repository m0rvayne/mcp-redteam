---
name: mcp-redteam
description: Full audit and penetration test of all connected MCP servers. One agent per server + chain attacker coordinator. Health, architecture, completeness, security.
user_invocable: true
trigger: /mcp-redteam
---

# MCP Red Team

## Step 0 — Language

Before anything else, ask the user in plain text (do NOT use AskUserQuestion with options — just type the question):

**"Report language? Type: en / ru / ua (default: en)"**

Wait for reply. Accept: `en`, `eng`, `english`, `ru`, `рус`, `русский`, `ua`, `укр`, `українська`, or just the first answer from the user. Default to English if user says "go", skips, or gives unsupported language.

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

## Step 1.6 — Claude Desktop servers

After discovery, if servers are found in Claude Desktop config but NOT in Claude Code:

Tell the user:

"I found {N} MCP servers configured in Claude Desktop that are not connected to Claude Code. I can read their source code but cannot actively test their tools (different process).

For full active testing, add them to Claude Code:
```bash
claude mcp add {server_name} -- {command} {args}
```
Or copy the server config from `~/Library/Application Support/Claude/claude_desktop_config.json` to your project's `.mcp.json`.

Without this, these servers will get **source-code-only audit** (no live tool calls)."

List the servers and let the user decide. Proceed with whatever is available — do NOT skip servers just because they can't be live-tested. Source-only audit is still valuable.

## Step 2 — Discover & audit

3. Discover MCP servers from ALL sources:
   - Claude Code: `~/.claude/settings.json`, `.mcp.json`, `claude mcp list`
   - Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
   - For each server: classify as CONNECTED (can call tools) or SOURCE-ONLY (can read code, no live calls)
4. Classify each server by type (file, HTTP/API, browser, native, database)
5. **Phase 1** — spawn 1 agent per server (parallel). Connected servers: source + live tool calls. Source-only servers: static analysis.
6. **Phase 2** — spawn 1 coordinator. Receives all Phase 1 output. For connected servers: actively tests cross-server chains. For source-only: infers chains from code analysis. Generates HTML report.

**IMPORTANT: Pass the user's selected language to Phase 2 coordinator explicitly. The report MUST be in the language chosen in Step 0.**

## Step 3 — Report

7. Generate HTML report in the selected language
8. **IMPORTANT: All `<details>` blocks must be CLOSED by default — no `open` attribute anywhere**
9. Present findings, offer to fix
