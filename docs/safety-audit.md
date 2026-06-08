# Safety Audit: Can mcp-redteam Damage User's MCP Infrastructure?

**Auditor:** Independent safety review (Claude, acting as security engineer)
**Date:** 2026-06-08
**Scope:** All files in mcp-redteam/ -- CLAUDE.md, SKILL.md, all docs/
**Verdict:** YES, this tool can cause damage. Severity: MEDIUM-HIGH. See details below.

---

## Executive Summary

mcp-redteam instructs Claude to **actively call MCP tools with attack payloads** on the user's live infrastructure. Despite safety rules scattered throughout the docs, multiple instructions directly contradict the "read-only exploitation" claim. The tool has no code-level enforcement -- all safety depends on an LLM following prose instructions, which is inherently unreliable.

A meaningful security audit can be performed with ZERO state-modifying calls. The current design chooses "dramatic proof" over safety, which is the wrong trade-off for a tool running against production infrastructure.

---

## Part 1: Line-by-Line Dangerous Instructions

### CLAUDE.md

#### 1.1 State-Modifying Tool Calls with Attack Payloads (Section 4, lines 165-258)

**Exact text (line 167):**
> "IMPORTANT: You MUST actually CALL tools with attack payloads -- not just read source code."

**What could go wrong:**
- Path traversal probes (`../../etc/hostname`) against file-write tools could write files
- SSRF probes (`http://127.0.0.1:1`, `http://httpstat.us/200?sleep=5000`) cause real network requests from the server
- Command injection probes (`; echo REDTEAM_CANARY_12345`, `; sleep 5`) could execute if the vulnerability exists -- that's the point, but execution IS damage
- Type confusion payloads (`{"count": 99999999999999}`) could crash the MCP server
- Error message probing with `{"param": "A" * 10000}` (line 238) could cause memory exhaustion

**Likelihood:** HIGH. The instructions explicitly demand these calls happen.

**Specific dangerous payloads mandated by CLAUDE.md:**

| Line | Payload | Risk |
|------|---------|------|
| 182 | `{"path": "../../../etc/hostname"}` | If tool is a WRITE tool (upload, save), this writes outside sandbox |
| 183 | `{"path": "..%2F..%2Fetc%2Fhostname"}` | Same, encoded bypass |
| 196 | `{"url": "http://127.0.0.1:1"}` | Real network connection attempt from server |
| 199 | `{"url": "http://169.254.169.254/latest/meta-data/"}` | AWS metadata access on cloud-hosted servers |
| 200 | `{"url": "http://httpstat.us/200?sleep=5000"}` | External HTTP request to third-party service |
| 210 | `{"query": "test; echo REDTEAM_CANARY_12345"}` | If injection works, EXECUTES A COMMAND on the server |
| 213 | `{"query": "test; sleep 5"}` | Blocks server process for 5 seconds |
| 238 | `{"param": "A" * 10000}` | Memory/buffer stress on MCP server |
| 256 | `{"count": 99999999999999}` | Integer overflow, potential crash |

#### 1.2 The "State-Modifying Tools" Contradiction (line 264)

**Exact text:**
> "State-modifying tools (create, update, delete): test ONLY with canary data prefix `[SECTEST-{date}]` and clean up immediately after"

This says "test state-modifying tools" -- meaning CREATE, UPDATE operations WILL be called. Creating a Trello card, a Gmail draft, a Google Doc, a NotebookLM notebook -- these are real side effects. "Clean up immediately" assumes:
1. The cleanup call succeeds (it might not)
2. The agent remembers to do it (LLM reliability)
3. The delete/undo operation exists (not all APIs have undo)
4. External side effects (notifications, webhooks, audit logs) are reversible (they aren't)

**Likelihood of orphaned test data:** HIGH. LLMs forget cleanup steps, especially under context pressure with 10+ servers.

#### 1.3 Delete/Send Tools (line 265)

**Exact text:**
> "Delete/send tools: NEVER call live. Infer from source code + shared code paths with read tools"

This is the ONE correct safety instruction. But it contradicts line 167 ("You MUST actually CALL tools"). An LLM resolving this contradiction may choose the more emphatic instruction (the MUST).

#### 1.4 Phase 2: Cross-Server Chain Testing (lines 296-368)

**Exact text (line 340):**
> "Execute each step (actually call the tools)"

The chain examples include:
- **CREDENTIAL RELAY** (line 316): "Take credentials found in Server A, test if they grant access on Server B" -- this means USING stolen credentials against other services
- **PATH LEAK -> TARGETED TRAVERSAL** (line 322): "Use them for targeted file reads on Server B" -- using one vulnerability to exploit another
- **PRIVILEGE ESCALATION** (line 332): "read credentials from disk -> use them to create webhook -> exfiltrate data" -- this chain literally describes data exfiltration

**Likelihood of damage:** MEDIUM. Claude will likely hesitate on the most extreme chains, but the instruction is explicit.

#### 1.5 Fix Strategy: Automated File Modifications (lines 400-460)

**Exact text (line 406):**
> "Create .gitignore", "chmod 600", "Add resolve() + is_relative_to(base) check"

These auto-fix instructions modify the user's source code. While they require user confirmation ("show -> confirm -> apply"), the agent is instructed to batch fixes and get "ONE confirmation for the batch" (line 467). A single "yes" could modify multiple files across multiple servers.

**Risk:** LOW-MEDIUM if user reads the batch. HIGH if user rubber-stamps.

---

### SKILL.md

#### 1.6 Permissions Advisory (lines 36-39)

**Exact text:**
> "Auto-approve read-only tools -- add to your project's .claude/settings.json:
> `{"permissions": {"allow": ["mcp__*__read_*", "mcp__*__get_*", "mcp__*__list_*", "mcp__*__search_*"]}}`"

This is reasonable for read-only, but the SKILL.md also offers option 3:

> "Full auto-approve (fastest, use only on your own infrastructure)"

If a user enables full auto-approve, EVERY attack payload in CLAUDE.md fires without confirmation. This is the most dangerous path and it's presented as a valid option.

---

### docs/active-exploitation-playbook.md

#### 1.7 State Modification Strategy (lines 366-390)

**Exact text (line 373):**
> `create_*, add_*` -- MEDIUM risk -- "Use canary data, cleanup after"
> `update_*, edit_*` -- HIGH risk -- "Sandbox account only"
> `delete_*, remove_*` -- CRITICAL -- "Source code analysis only, never call live"
> `send_*` (email/message) -- CRITICAL -- "Use test channel/recipient only"

The problem: "sandbox account only" and "test channel only" REQUIRE the user to have set these up. There is NO check for whether a sandbox exists. The agent will attempt these operations on the user's REAL accounts.

#### 1.8 Resource Exhaustion Probes (lines 182-191)

**Exact text:**
> "String of 1MB", "Array with 10,000 elements", "Deeply nested JSON (100 levels)", "10 rapid sequential calls"

These are denial-of-service probes. Even "safe" DoS probes can crash poorly-written MCP servers, which is exactly the kind of server that needs auditing.

**Likelihood of server crash:** MEDIUM-HIGH for poorly-written servers (which are the primary audit targets).

---

### docs/attack-playbook.md

#### 1.9 Test Suite D: DoS Tests (lines 491-499)

**Exact text:**
> "D1. Send 1000 requests/second"
> "D2. Request recursive directory listing of /"
> "D3. Open 100 concurrent connections"

These WILL crash or destabilize MCP servers. The documentation-audit.md (line 92) correctly flags this as contradicting the "read-only" rule, but the playbook was never updated.

---

## Part 2: Analysis by Damage Category

### Can this tool CREATE data?

**YES.**
- CLAUDE.md line 264 explicitly instructs testing create/add tools with canary data
- Gmail: `mcp__claude_ai_Gmail__create_draft` -- could create email drafts
- Gmail: `mcp__claude_ai_Gmail__create_label` -- could create labels
- NotebookLM: `mcp__notebooklm-mcp__notebook_create`, `source_add`, `note`, `studio_create` -- could create notebooks, sources, notes, audio overviews
- Any MCP server with create operations will have test data created

### Can this tool MODIFY data?

**YES.**
- CLAUDE.md line 264 says test update tools with canary prefix
- Gmail: `mcp__claude_ai_Gmail__label_message`, `label_thread`, `update_label` -- modifies email labels
- NotebookLM: `mcp__notebooklm-mcp__notebook_rename`, `source_rename`, `studio_revise`, `chat_configure` -- modifies existing resources
- Fix strategy (lines 400-460) modifies source files: .gitignore, chmod, code patches

### Can this tool DELETE data?

**Theoretically no** (line 265 says "NEVER call live"), but:
- The "cleanup" step after canary creation DOES call delete operations
- NotebookLM: `notebook_delete`, `source_delete`, `studio_delete` could be called during cleanup
- If the LLM misinterprets cleanup scope, legitimate data could be deleted
- Gmail: `delete_label` -- a label deletion is irreversible

### Can this tool SEND messages?

**Theoretically no** (line 265), but:
- Gmail `create_draft` creates a draft (not sent, but visible in user's drafts)
- NotebookLM `notebook_share_invite`, `notebook_share_batch`, `notebook_share_public` could share notebooks with external parties
- If cross-server chain testing (line 332) follows through on "create webhook -> exfiltrate data", this sends data externally

### Can this tool crash/destabilize MCP servers?

**YES, very likely.**
- Type confusion payloads (line 250-258) are designed to find crashes -- finding them means causing them
- Memory exhaustion (`"A" * 10000`, line 238) on servers without input limits
- Resource exhaustion probes (playbook lines 182-191)
- Rapid sequential calls (10 per tool, line 266 -- but 10 x 40 tools = 400 calls)
- Integer overflow (`99999999999999`, line 256)
- Deeply nested JSON (100 levels)

### Can this tool leak data to external services?

**YES.**
- SSRF probe to `http://httpstat.us/200?sleep=5000` (line 200) -- sends request to external service
- SSRF probe to `http://169.254.169.254/latest/meta-data/` -- accesses cloud metadata
- Burp Collaborator/interact.sh mentions (playbook lines 117-118) -- OOB data exfiltration
- If NotebookLM `notebook_share_public` is called, data becomes publicly accessible
- `research_start` and `research_import` in NotebookLM could send queries to Google

### Can this tool fill up disk?

**LOW risk, but possible.**
- NotebookLM `download_artifact`, `export_artifact` could download files
- Report generation creates HTML files in reports/
- No explicit disk space checks

### Can this tool lock the user out?

**LOW risk, but possible.**
- NotebookLM `refresh_auth`, `save_auth_tokens` -- if called with malformed data, could corrupt auth state
- Gmail label operations don't affect access
- OAuth token manipulation in fix strategy could require re-authentication

---

## Part 3: The Core Question

### Can you do a meaningful security audit WITHOUT calling state-modifying tools?

**YES. Absolutely. This is how real security firms operate.**

Trail of Bits, Cure53, NCC Group, Bishop Fox -- none of them run `DELETE FROM users` on production databases. Their methodology:

1. **Source code review** -- read the code, find the vulnerability in logic
2. **Static analysis** -- grep for `shell=True`, missing `is_relative_to()`, `str(e)` in returns
3. **Read-only tool enumeration** -- list tools, read descriptions, analyze schemas
4. **Configuration review** -- read .env permissions, .gitignore, credential file permissions
5. **Proof by construction** -- "this code path reaches `os.system()` with unsanitized input, here is the exact line, here is a proof-of-concept that WOULD work"

The distinction is between:
- **"I proved this code is vulnerable by reading it"** (safe, professional)
- **"I proved this code is vulnerable by exploiting it on your live system"** (dangerous, unnecessary)

Both produce findings of equal quality. The second adds evidence ("here's the response"), but the evidence isn't worth the risk on production systems.

### What mcp-redteam gets RIGHT about read-only

The tool already contains excellent read-only audit capabilities:
- Source code analysis (CLAUDE.md Phase 1)
- Tool description poisoning detection (section 4F -- static analysis only)
- Credential file permission checks (section 4D -- filesystem only)
- .gitignore completeness checks (section 3)
- Error message analysis of returned errors (doesn't require attack payloads)
- Architecture and health reviews (sections 1-2)

These alone would produce a high-quality audit report.

---

## Part 4: Proposed Safety Model

### ALWAYS SAFE (auto-approve, no confirmation needed)

These tools are read-only and cannot cause damage:

```
# Filesystem
Read, Glob, Grep

# MCP tools -- read patterns
mcp__*__list_*
mcp__*__get_*
mcp__*__read_*
mcp__*__search_*
mcp__*__describe_*
mcp__*__status_*

# Specific safe tools from available MCP servers
mcp__claude_ai_Gmail__list_labels
mcp__claude_ai_Gmail__list_drafts
mcp__claude_ai_Gmail__search_threads
mcp__claude_ai_Gmail__get_thread
mcp__notebooklm-mcp__notebook_list
mcp__notebooklm-mcp__notebook_get
mcp__notebooklm-mcp__notebook_describe
mcp__notebooklm-mcp__source_list_drive
mcp__notebooklm-mcp__source_get_content
mcp__notebooklm-mcp__source_describe
mcp__notebooklm-mcp__studio_status
mcp__notebooklm-mcp__research_status
mcp__notebooklm-mcp__notebook_share_status
mcp__notebooklm-mcp__server_info
mcp__notebooklm-mcp__tag

# Bash -- read-only commands
Bash(ls *)
Bash(cat /etc/hostname)
Bash(stat *)
Bash(file *)
```

### NEVER CALL DURING AUDIT (hard deny)

These tools can cause irreversible damage:

```
# Delete operations
mcp__*__delete_*
mcp__*__remove_*
mcp__*__drop_*
mcp__claude_ai_Gmail__delete_label
mcp__notebooklm-mcp__notebook_delete
mcp__notebooklm-mcp__source_delete
mcp__notebooklm-mcp__studio_delete

# Send/share operations
mcp__*__send_*
mcp__*__share_*
mcp__*__invite_*
mcp__*__publish_*
mcp__notebooklm-mcp__notebook_share_invite
mcp__notebooklm-mcp__notebook_share_batch
mcp__notebooklm-mcp__notebook_share_public

# Auth-modifying operations
mcp__*__refresh_auth
mcp__*__save_auth_tokens
mcp__*__revoke_*

# External data transfer
mcp__*__export_*
mcp__*__download_*  (creates files)
mcp__*__upload_*
mcp__notebooklm-mcp__export_artifact
mcp__notebooklm-mcp__download_artifact
mcp__notebooklm-mcp__research_import
mcp__notebooklm-mcp__research_start

# Dangerous bash
Bash(rm *)
Bash(chmod *)
Bash(curl *)
Bash(wget *)
```

### REQUIRES PER-CALL USER CONFIRMATION (yellow zone)

These tools modify state but may be needed:

```
# Create operations (with canary prefix, cleanup required)
mcp__*__create_*
mcp__*__add_*
mcp__*__write_*
mcp__claude_ai_Gmail__create_draft
mcp__claude_ai_Gmail__create_label
mcp__notebooklm-mcp__notebook_create
mcp__notebooklm-mcp__source_add
mcp__notebooklm-mcp__note
mcp__notebooklm-mcp__studio_create

# Update operations
mcp__*__update_*
mcp__*__rename_*
mcp__*__edit_*
mcp__*__label_*
mcp__*__unlabel_*
mcp__claude_ai_Gmail__label_message
mcp__claude_ai_Gmail__label_thread
mcp__claude_ai_Gmail__unlabel_message
mcp__claude_ai_Gmail__unlabel_thread
mcp__claude_ai_Gmail__update_label
mcp__notebooklm-mcp__notebook_rename
mcp__notebooklm-mcp__source_rename
mcp__notebooklm-mcp__source_sync_drive
mcp__notebooklm-mcp__studio_revise
mcp__notebooklm-mcp__chat_configure

# Complex operations
mcp__notebooklm-mcp__batch
mcp__notebooklm-mcp__pipeline
mcp__notebooklm-mcp__cross_notebook_query
mcp__notebooklm-mcp__notebook_query

# Source code fixes
Edit, Write (for fix strategy)
Bash(git *)
```

---

## Part 5: How to Prove Vulnerabilities WITHOUT Exploiting Them

### Pattern: Code Path Analysis

Instead of calling `mcp__trello__create_card({"name": "; echo CANARY"})`, do this:

1. **Read server source**: find the `create_card` handler function
2. **Trace the input**: follow `name` parameter from handler to where it's used
3. **Identify the sink**: does it reach `os.system()`, `execSync()`, `subprocess.run(shell=True)`?
4. **Check for sanitization**: is there input validation between source and sink?
5. **Report**: "Parameter `name` in `create_card` (file: server.py, line 142) flows to `subprocess.run(f'notify {name}', shell=True)` on line 167 with no sanitization. Command injection is possible. Proof payload: `; echo CANARY`. Fix: use `subprocess.run(['notify', name])` without shell=True."

This is EXACTLY what a SAST tool does. It proves the vulnerability without executing it.

### Pattern: Schema Analysis

Instead of sending `{"count": 99999999999999}`, do this:

1. **Read input schema**: check if `count` has `maximum` constraint
2. **Read handler code**: check if there's a runtime bounds check
3. **Report**: "Parameter `count` in `list_items` accepts unbounded integers (no `maximum` in schema, no runtime check in handler at line 84). Sending `99999999999999` would cause [memory exhaustion / precision loss / crash]. Fix: add `"maximum": 1000` to schema and `min(count, 1000)` in handler."

### Pattern: Credential Audit (already correct in CLAUDE.md)

Section 4D (line 220) correctly uses filesystem-only checks:
- `ls -la .env token.json credentials.json` -- check existence and permissions
- Read .gitignore -- check coverage
- No MCP tool calls needed

### Pattern: Tool Description Analysis (already correct in CLAUDE.md)

Section 4F (line 241) correctly uses static analysis:
- Read descriptions for `<IMPORTANT>` tags
- Check for invisible Unicode
- Check for suspicious parameter names
- No MCP tool calls needed

### Pattern: Error Behavior via Read-Only Calls

Instead of sending malformed input to trigger errors, do this:

1. **Read error handling code**: find try/except blocks in handlers
2. **Check what's returned on error**: is it `str(e)` or a sanitized message?
3. **Report**: "Handler for `search` (line 92) catches Exception and returns `str(e)` directly. If an httpx.HTTPError occurs, the error message will contain the full URL including any API keys in query parameters. Fix: use `safe_error(e)` wrapper."

If you MUST trigger an error for evidence, use read-only tools with obviously invalid input (empty string, wrong type). Never use attack payloads.

---

## Part 6: Specific Recommendations for mcp-redteam

### 6.1 Change the Philosophy

**Current (CLAUDE.md line 9):**
> "Every finding must be proven. Not 'may be vulnerable' -- but 'here's the payload, here's the response, here's what we got.'"

**Proposed:**
> "Every finding must be proven. For read-only tools: actual payload + response. For state-modifying tools: source code trace showing the vulnerable path + proof-of-concept payload that WOULD work. We prove by analysis, not by exploitation on live systems."

### 6.2 Add an Explicit Safety Mode

Add to SKILL.md Step 1.5:

```
"Audit mode? Type: safe / active (default: safe)

- SAFE: Source code analysis + read-only tool calls only. No state-modifying
  calls. Recommended for production infrastructure.
- ACTIVE: Full exploitation including state-modifying tools with canary data.
  Use only on test/sandbox environments."
```

### 6.3 Add Tool Classification to Agent Prompt

Before spawning each agent, classify every tool as:
- READ (auto-approve)
- WRITE (requires confirmation in active mode, skip in safe mode)
- DELETE (never call)
- SEND (never call)

Pass this classification to the agent prompt explicitly.

### 6.4 Remove DoS Test Cases from Default Playbook

Test Suite D (resource exhaustion) should be opt-in only. A crashed MCP server during audit is itself a denial of service against the user.

### 6.5 Remove External SSRF Probes

`http://httpstat.us/200?sleep=5000` sends a real request to a third-party service. This is data leakage (the third party now knows the user's IP and that they're running an audit). Replace with analysis of whether the code validates URLs before fetching.

### 6.6 Fix the "MUST CALL" Language

CLAUDE.md line 167 should change from:
> "You MUST actually CALL tools with attack payloads"

To:
> "For read-only tools: CALL with attack payloads and record responses. For state-modifying tools: analyze source code to prove the same vulnerable code path exists, and note the proof-of-concept payload WITHOUT executing it."

### 6.7 Remove "Full Auto-Approve" Option

SKILL.md option 3 ("Full auto-approve") should be removed or require the user to type a confirmation phrase like "I understand this will modify my data". Presenting it as a casual option is dangerous.

---

## Part 7: Summary of Findings

| # | Risk | Source | Likelihood | Severity |
|---|------|--------|------------|----------|
| 1 | Command execution via injection probes | CLAUDE.md line 210-214 | HIGH (if vuln exists, probe triggers it) | CRITICAL |
| 2 | MCP server crash via type confusion/DoS probes | CLAUDE.md lines 250-258, playbook D1-D6 | MEDIUM-HIGH | HIGH |
| 3 | Orphaned test data from canary create/cleanup | CLAUDE.md line 264 | HIGH (LLM cleanup is unreliable) | MEDIUM |
| 4 | External data leakage via SSRF probes | CLAUDE.md line 200, playbook lines 117-118 | MEDIUM | MEDIUM |
| 5 | Unintended sharing/sending via cross-server chains | CLAUDE.md lines 316-334 | LOW-MEDIUM | HIGH |
| 6 | Source code modification via fix strategy | CLAUDE.md lines 400-460 | LOW (requires user confirm) | MEDIUM |
| 7 | Cloud metadata access via 169.254.169.254 probe | CLAUDE.md line 199 | MEDIUM | HIGH |
| 8 | Auth state corruption via token-related tools | NotebookLM refresh_auth, save_auth_tokens | LOW | HIGH |
| 9 | All protections are LLM-compliance-based, not enforced | Architectural | HIGH (LLMs are non-deterministic) | HIGH |

### Bottom Line

**Can mcp-redteam damage user's MCP infrastructure?** Yes. The tool explicitly instructs an LLM to fire attack payloads at live MCP servers. When those attacks succeed -- which is the goal -- the success IS the damage (command execution, server crashes, data creation, external requests).

**Is the damage intentional?** Partially. The tool tries to limit damage with safety rules, but those rules are prose instructions to a non-deterministic system, not code-level enforcement.

**Can the audit value be preserved without the risk?** Yes. 90%+ of the audit's value comes from source code analysis, schema review, configuration checks, and read-only tool enumeration. The remaining ~10% (live proof) can be achieved by calling only genuinely read-only tools with test payloads, never state-modifying ones.

**Recommendation:** Default to safe mode (source analysis + read-only calls). Make active exploitation opt-in with clear warnings. This matches industry practice and loses almost nothing in audit quality.
