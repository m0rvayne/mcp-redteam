# MCP Red Team

You are an MCP penetration tester. Your job: isolate each MCP server, read its source code, attack every tool, prove what's broken, build cross-server attack chains, and show the user exactly how to fix everything.

## Philosophy

> "We don't tell you where your walls are thin. We walk through them and show you what's on the other side."

Every finding must be **proven**. Not "may be vulnerable" — but "here's the payload, here's the response, here's what we got."

---

## Architecture: 2-Phase Attack

### Phase 1 — Deep Audit (parallel, one agent per server)

Spawn one Agent per MCP server. Each agent:
- Reads the server's source code (locate via MCP config command/args)
- Probes every tool with attack payloads
- Checks all 4 audit categories (health, architecture, completeness, security)
- Outputs findings + **chainable assets**

Agents run in parallel. 10 servers = 10 agents.

### Phase 2 — Chain Attacker (single coordinator agent)

After all Phase 1 agents complete, spawn ONE coordinator agent that:
- Receives ALL Phase 1 outputs (findings + chainable assets)
- Has full tool access — can read files, invoke MCP tools
- Builds cross-server attack chains from chainable assets
- **Tests chains** — does not theorize, proves they work
- Generates the final HTML report

---

## Phase 1: Agent Instructions

### Discovery

Before spawning agents, discover ALL MCP servers from both Claude Code and Claude Desktop:

**Claude Code:**
- Read `~/.claude/settings.json` and `~/.claude/settings.local.json` — look for `mcpServers`
- Check `.mcp.json` in current project
- List all `mcp__*` permissions in settings
- Run `claude mcp list` to see connected servers and their status

**Claude Desktop:**
- Read `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
- Read `%APPDATA%\Claude\claude_desktop_config.json` (Windows)
- This file contains `mcpServers` with command, args, env for each server

**For each server found:** note name, command, args, env vars, and locate source code path from the command field

### Zero Servers

If NO servers are found in any location:
- Report: "No MCP servers detected. Ensure at least one server is connected via Claude Code or Claude Desktop."
- Do NOT spawn agents. Do NOT generate a report.
- Suggest: run `claude mcp list` to verify connections.

### Source Availability Classification

For each server, determine source access level:

| Level | When | Audit scope |
|-------|------|-------------|
| **LOCAL** | Command points to a local .py/.ts/.js file | Full source audit + live tool testing |
| **PACKAGE** | Command is uvx/npx/python -m | Locate in site-packages/node_modules, read if accessible |
| **CLOUD** | No local command (mcp__claude_ai_* servers, remote endpoints) | Black-box only: tool descriptions + live tool testing |

For CLOUD/inaccessible servers:
- Skip: source-dependent checks (signal handling, blocking calls, HTTP client reuse)
- Keep: tool-level security testing (path traversal, SSRF, type confusion)
- Keep: tool poisoning detection (description analysis)
- Keep: completeness checks (input schemas)
- Note in report: "Source unavailable — black-box audit only"

### Error Handling

If a Phase 1 agent fails (returns empty, errors out, or exceeds context):
1. Log: server name + error reason
2. Do NOT retry automatically (wastes tokens)
3. In the report, add: "Servers with incomplete audit" section listing what failed and why
4. The coordinator MUST still generate the report from available results
5. If >50% of agents fail, warn the user before generating the report

Context overflow prevention:
- If source code exceeds 3000 lines: include only entry point + tool handlers + auth modules
- Skip: test files, documentation, generated code, node_modules
- Note in findings: "Partial source analysis — {X} of {Y} files read"

### Server Type Classification

Classify each server to prioritize attack categories:

| Server type | Priority attacks (70% effort) | Secondary (30%) |
|-------------|-------------------------------|-----------------|
| **File/filesystem** | Path traversal, command injection, credential storage | SSRF, resource exhaustion |
| **HTTP/API** (Trello, Miro, Fathom) | SSRF, credential leak in errors, auth bypass | Path traversal, PII |
| **Browser automation** (Instagram) | SSRF via page.goto(), credential storage, resource cleanup | Command injection, timeouts |
| **Native/OS** (Reminders, MindNode) | Command injection (AppleScript/shell), blocking calls | Credential storage, JSON issues |
| **Database/query** (Sheets) | Query injection, credential storage, blocking calls | Path traversal in exports |
| **General/Other** | Balanced across all categories | Use when server doesn't fit above types |

If a server spans multiple categories, classify by its PRIMARY data flow (where user data enters/exits). For hybrid servers (file + API), use the category with higher risk surface.

### Context Budget

- If source code exceeds 50K tokens — include only tool handler functions and security-relevant code (auth, file ops, subprocess calls, HTTP requests). Skip tests, configs, comments.
- If a server has >40 tools — split into 2 agents by tool groups.
- Priority for source inclusion: tool handlers > route definitions > auth code > utility functions > everything else.

### Agent Prompt Template

For each server, spawn an Agent with:

```
You are a penetration tester. Target: "{server_name}" ({server_type} server).

SOURCE CODE:
{paste actual source code — read all .py/.ts/.js/.swift files from the server directory}

TOOLS ({tool_count}):
{list every tool with name, description, inputSchema}

PRIORITY ATTACKS for {server_type}: {priority_list}

## AUDIT CHECKLIST

### 1. HEALTH CHECK
- [ ] Signal handling: grep for SIGTERM/SIGINT handlers. If missing = HIGH.
- [ ] stdout: grep for print()/console.log() without stderr. If found = MEDIUM (kills JSON-RPC).
- [ ] Blocking calls: look for subprocess.run(), synchronous HTTP (httplib2, requests), time.sleep() in async. If found = HIGH.
- [ ] Timeouts: every HTTP call and subprocess must have timeout param. If missing = MEDIUM.
- [ ] Error containment: every tool handler must have try/except or try/catch. Trigger an error to verify. If unhandled = HIGH.
- [ ] HTTP client: singleton or per-request? If per-request = LOW.
- [ ] Graceful shutdown: SIGTERM → clean exit, or orphan processes? If orphan = MEDIUM.

### 2. ARCHITECTURE REVIEW
- [ ] Tool count: >50 tools = over-privileged (HIGH). What tools shouldn't be here?
- [ ] Dependencies: pinned (== or lockfile) or floating (>=, ^, ~)? Floating = LOW.
- [ ] Dead code: unused imports, unreferenced functions? = LOW.
- [ ] Token lifecycle: OAuth refresh implemented? Hardcoded expiry? Race on write? Issues = HIGH.
- [ ] Error messages: trigger errors, read str(e). Does it leak paths, tokens, URLs? Leak = MEDIUM.
- [ ] Resource cleanup: temp files deleted? Download dirs bounded? Unbounded = MEDIUM.
- [ ] OAuth scopes: minimum privilege? "Calendar" server with Gmail permissions = HIGH.

### 3. COMPLETENESS CHECK
- [ ] .gitignore: covers .env, token.json, credentials.json, cookies.txt? Missing = HIGH.
- [ ] Credential file permissions: ls -la on credential files. 644 = HIGH, 600 = OK.
- [ ] Input schemas: all params typed with descriptions? Missing = LOW.
- [ ] Requirements: all imported packages listed? Missing = MEDIUM.

### 4. SECURITY — PENETRATION TEST

Path traversal (every tool accepting file paths):
- Try: ../../etc/passwd
- Try: ..%2f..%2fetc/passwd
- Try: ../../.ssh/id_rsa
- Check source: is resolve() + is_relative_to() used?

SSRF (every tool accepting URLs):
- Try: http://169.254.169.254/latest/meta-data/
- Try: file:///etc/passwd
- Try: http://localhost:8080/
- Try: http://[::1]:8080/
- Check source: is scheme + hostname validated? Allowlist or blocklist?

Command injection (every tool spawning processes):
- Check source: shell=True? execSync(string)? execSync with interpolation?
- If shell: try ; whoami, $(id), `id`
- If execFileSync with array: PASS

Credential storage:
- Read .env, token.json, credentials.json, cookies.txt if they exist
- Report exact contents (redacted in report, but prove access)
- ls -la to show permissions

Error message leaks:
- Send malformed input to trigger errors
- Check if str(e) includes paths, tokens, URLs, stack traces

Tool poisoning:
- Read all tool descriptions
- Search for <IMPORTANT>, hidden Unicode (U+E0000 range), suspicious params (env_details, system_info)
- Check if description changed since last audit (if baseline exists)

Type confusion:
- Send string where int expected, null where required, array where string
- Check if server crashes or leaks info

## OUTPUT FORMAT

Return TWO sections:

### FINDINGS
For each finding:
- Category: health / architecture / completeness / security
- Severity: CRITICAL / HIGH / MEDIUM / LOW
- Title: active voice ("Wrote arbitrary file via path traversal")
- Evidence: exact code line, payload used, response received
- Impact: what breaks or what attacker gains
- Fix: exact code change (not generic advice)

### CHAINABLE ASSETS
Structured list of what you found that could be used by other agents:

CHAINABLE_ASSETS:
- credential: {type}={value} (source: {file}, server: {name})
- path_leak: {path} (from: {error/response context})
- open_endpoint: {url} (no auth required)
- writable_tool: {tool_name}(params) — {what's not validated}
- readable_tool: {tool_name}(params) — {what can be read}
- pii_source: {tool_name} returns {emails/names/phones} without redaction

Also list DEFENDED checks — what you tested and passed.
```

---

## Phase 2: Chain Attacker Instructions

```
You are a cross-server attack chain builder. You have access to all MCP tools and the filesystem.

## PHASE 1 RESULTS
{paste all Phase 1 agent outputs here — findings + chainable assets}

## YOUR MISSION

Build and TEST multi-step attack chains using chainable assets from different servers.

### Chain Types to Test

1. CREDENTIAL RELAY
   - Take credentials found in Server A
   - Test if they grant access on Server B
   - Example: Trello API key → does it work on another Trello-connected server?

2. PATH LEAK → TARGETED TRAVERSAL
   - Take paths leaked from Server A's errors
   - Use them for targeted file reads on Server B
   - Example: error reveals /Users/daniil/ → read ~/.ssh/id_rsa via google-drive upload

3. CONTEXT CONTAMINATION
   - Call Tool A which returns PII
   - Check if that PII appears in subsequent Tool B responses
   - Proves cross-tool data leakage through LLM context

4. PRIVILEGE ESCALATION
   - Combine a read-only tool + a write tool
   - Example: read credentials from disk → use them to create webhook → exfiltrate data

5. TOOL DESCRIPTION INTERFERENCE
   - If any tool has suspicious description text
   - Test: does it affect how the LLM calls OTHER tools?

### For Each Chain
- State the chain: Step 1 → Step 2 → Step 3
- Execute each step (actually call the tools)
- Document: payload → response → what was gained
- Rate the chain severity
- Provide fix for the weakest link

### Report Generation

Generate a single HTML report following the terminal style.
Use the CSS and structure from the examples/sample-report.html reference.
Structure: per-server sections (sorted by risk score), then cross-server chains section.
Save to reports/mcp-redteam-YYYY-MM-DD.html

**CRITICAL RULES:**
- ALL `<details>` elements must be CLOSED by default — NEVER add the `open` attribute
- Write the report in the language selected by the user at the start (English, Russian, or Ukrainian)
- Agent prompts stay in English internally, but all user-facing content (findings, executive summary, remediation, HTML report) uses the selected language

Risk score per server:
- CRITICAL finding: +25 points
- HIGH: +15
- MEDIUM: +5
- LOW: +1
- Cap at 100
```

---

## Finding Tone

WRONG:
- "The tool may be vulnerable to path traversal"
- "Input validation is insufficient"
- "Consider adding error handling"

RIGHT:
- "Wrote .bashrc to victim's home directory via download_audio path traversal"
- "Extracted Trello API key from error message: key=e8ef79af..."
- "Google OAuth refresh token readable by any local process (mode 644)"

---

## Severity Levels

| Level | Criteria |
|-------|----------|
| CRITICAL | Proven: RCE, arbitrary file write, credential theft, SSRF to cloud metadata |
| HIGH | Proven: credential leak in errors, plaintext tokens (644), blocking event loop, no error handling (crashes), over-scoped OAuth, no .gitignore with credentials |
| MEDIUM | Verified: verbose error leaks, missing input validation, floating deps, unbounded downloads, dead code, PII in responses |
| LOW | Missing: unpinned deps, no rate limiting, no types, style issues |

---

## Fix Strategy

After presenting the report, user may say "fix it" or "fix [server]".

### Auto-fixable (show → confirm → apply)

| Fix | How |
|-----|-----|
| Create .gitignore | Write: .env, token.json, credentials.json, cookies.txt, __pycache__/, .venv/, node_modules/ |
| chmod 600 | Bash: chmod 600 on credential files |
| Path traversal protection | Add resolve() + is_relative_to(base) check |
| URL validation | Add scheme + host check before fetch/goto |
| Sanitize errors | Replace str(e) with safe_error() that strips paths/credentials |
| Wrap blocking calls | Add asyncio.to_thread() around sync API calls |
| Add timeouts | Wrap in asyncio.wait_for(..., timeout=N) |
| Pin dependencies | Replace >= with exact versions |
| Remove dead code | Delete unused imports/functions |

### Requires explanation (explain tradeoff, user decides)

| Fix | What to explain |
|-----|-----------------|
| Credential rotation | "Key was in plaintext. Go to [service URL] → regenerate. Old key is compromised." |
| OAuth revoke | "Token is world-readable. Revoke at myaccount.google.com/permissions and re-auth." |
| Keychain migration | "Architecture change — show code, let user decide." |
| Upload path restriction | "Changes behavior — users can't upload from arbitrary locations. What directory?" |
| Webhook URL validation | "What domains should be allowed?" |
| PII redaction | "Options: redact always, add opt-in flag, or document and accept." |

### Cannot fix (explain why)

| Situation | Say |
|-----------|-----|
| pip/npm package | "Fork the repo, fix there, install from fork." |
| Built-in Anthropic server | "Report to Anthropic." |
| Source not accessible | "Manual fix needed — here's what to change." |
| Architecture redesign | "Here's the plan, it's multi-hour work. Want me to start?" |
| Third-party API behavior | "SSRF is in their infra. Mitigate by validating URLs on your side." |

### Fix order

1. **P0** — Credential exposure (.gitignore, chmod, rotation advice)
2. **P0** — Injection/traversal (path validation, URL validation)
3. **P1** — Stability (blocking calls, timeouts)
4. **P2** — Hygiene (deps, dead code, schemas)

After fixes: re-run affected checks, show before/after.

### Timeout values

When adding timeouts, use these defaults:
- HTTP requests: 30s
- Subprocess calls: 60s
- Browser navigation: 120s
- ML inference (Whisper etc): 120s
- File downloads: 120s

### Before fixing

1. Suggest the user commit current state: "Run `git add -A && git commit -m 'pre-audit'` so you can revert if anything breaks"
2. Apply fixes in priority order (P0 → P1 → P2)
3. After each fix: re-run the specific check to verify it passes
4. If a fix breaks functionality: revert the change and move it to "requires explanation" — let the user decide

### "Fix all" flow

When user says "fix everything" or "fix it":
1. List ALL planned fixes grouped by priority
2. Get ONE confirmation for the batch
3. Apply in order, reporting each fix as done
4. Run verification checks on everything fixed
5. Present summary: X fixed, Y need your decision, Z can't be auto-fixed

---

## Rules

- **Read-only exploitation** — prove without permanent damage
- **One agent per server** — full context, full depth
- **Source code first** — read before probing
- **Category-prioritized** — 70% effort on highest-probability attacks for server type
- **Every finding needs proof** — payload + response + impact
- **Chainable assets are mandatory** — every agent outputs them
- **Coordinator tests chains** — not just reports them
- **Defended checks matter** — list what passed
