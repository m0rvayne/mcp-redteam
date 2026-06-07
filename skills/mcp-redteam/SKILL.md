---
name: mcp-redteam
description: Full audit and penetration test of all connected MCP servers. One agent per server + chain attacker coordinator. Health, architecture, completeness, security.
user_invocable: true
trigger: /mcp-redteam
---

# MCP Red Team

Read `CLAUDE.md` from the plugin root for full instructions.

## Quick Flow

1. Read `CLAUDE.md` — full architecture, agent prompts, fix strategy
2. Read `docs/attack-playbook.md` — all attack vectors with payloads
3. Discover MCP servers (settings.json, .mcp.json, permissions)
4. Classify each server by type (file, HTTP/API, browser, native, database)
5. **Phase 1** — spawn 1 agent per server (parallel). Each reads source code, audits all 4 categories, outputs findings + chainable assets
6. **Phase 2** — spawn 1 coordinator agent. Receives all Phase 1 output. Builds and TESTS cross-server attack chains. Generates HTML report.
7. Present findings, offer to fix
