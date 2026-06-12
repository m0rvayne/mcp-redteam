# We Scanned 106 MCP Servers. exec() Is Everywhere.

MCP (Model Context Protocol) lets AI agents call external tools — file systems, databases, browsers, smart homes, even reverse engineering tools. We ran automated static analysis on 106 MCP servers: Anthropic's official implementations plus the most popular community servers. Combined: 300K+ GitHub stars.

**Tool:** [mcp-redteam](https://github.com/m0rvayne/mcp-redteam) (`pip install redteam-mcp`)
**Mode:** Deterministic Semgrep rules + embedding-based tool poisoning detection.

---

## The headline

**4 servers have confirmed Remote Code Execution.** These aren't obscure repos — they have 10K-25K stars and real users.

| Server | Stars | Language | Vulnerability | Verified |
|--------|-------|----------|--------------|----------|
| **serena** | 25.2K | Python | `subprocess.Popen(command, shell=True)` — unsanitized LLM input | Confirmed, [disclosed](https://github.com/oraios/serena/issues/1569) |
| **mcp-chrome** | 11.8K | TypeScript | `new Function(code)()` in browser MAIN world — 7 injection points in 5 files | Confirmed |
| **mcp-use** | 10K | Python | `exec()` — "restricted namespace" bypassed via `asyncio.create_subprocess_shell()` | Confirmed, [disclosed](https://github.com/mcp-use/mcp-use/issues/1718) |
| **ida-pro-mcp** | 9.3K | Python | `exec()` + `eval()` with full `__builtins__` inside IDA Pro | Confirmed (has `@unsafe` opt-in flag) |

Two additional servers flagged by the scanner turned out to be less severe after manual review:
- **DesktopCommanderMCP** (6.1K) — terminal tool by design, `spawn()` is the intended behavior. Has blocklist but `node:local` bypasses it completely. By-design risk, not a vulnerability.
- **klavis** (5.7K) — shell=True exists but has multi-layer validation. 3 of 4 original claims (credential leaks, hardcoded secrets, eval injection) were false positives after deeper review. `ast.literal_eval` ≠ `eval()`.

We initially also reported ha-mcp (3.3K) but [closed the issue](https://github.com/homeassistant-ai/ha-mcp/issues/1583) after finding their `python_sandbox.py` has proper AST validation, dunder-attribute blocking, and method whitelisting. Not every `exec()` is a vulnerability.

---

## The pattern: "sandbox" that isn't

Three independent servers use `exec()`/`eval()`/`new Function()` and call it "sandboxed":

**mcp-use** (10K stars):
```python
exec(compiled_wrapped, namespace)  # "restricted namespace"
```
We verified: `asyncio` is passed into the namespace. `asyncio.create_subprocess_shell()` gives full RCE without any `__subclasses__` tricks. The "safety tests" in the repo only check three trivial cases (`import os`, `open()`, `eval()`) — none of the real bypass vectors.

**ida-pro-mcp** (9.3K stars):
```python
exec(code)  # inside IDA Pro process — access to binary analysis
```

**mcp-chrome** (11.8K stars):
```typescript
func: (code) => new Function(code)()  // browser MAIN world
```

**If you maintain an MCP server:** `grep -r "exec(\|eval(\|new Function(" your-server/`. If any of these execute agent-controlled input — you have RCE.

---

## Responsible disclosure

We reported two findings before publishing:

| Server | Issue | Status |
|--------|-------|--------|
| [serena #1569](https://github.com/oraios/serena/issues/1569) | shell=True with unsanitized LLM input | Open, confirmed |
| [mcp-use #1718](https://github.com/mcp-use/mcp-use/issues/1718) | exec() sandbox bypass via asyncio | Open, confirmed |

We also reported ha-mcp (3.3K stars) but after deeper review found their `python_sandbox.py` has proper AST validation, dunder-attribute blocking, and method whitelisting. We closed the issue with an apology — that's what honest scanning looks like. Not every `exec()` is a vulnerability.

---

## Credential leaks

**klavis** leaks credentials across 10+ sub-servers (Confluence, Freshdesk, Slack) — hardcoded secrets and tokens in responses.

**pipeboard-co/meta-ads-mcp** serializes Facebook access_token in tool response.

Combined with prompt injection: steal tokens, access external services.

---

## Remote MCP scanning

Most security scanners only check local servers — code you can read. But many MCP servers run remotely, connected via URL. You can't read their source code, but you can read their tool descriptions.

We built `scan-remote` to check remote servers via MCP protocol:

```bash
mcp-redteam scan-remote https://your-server.com/mcp --token <bearer>
```

What it does:
- Connects via MCP Streamable HTTP
- Fetches all tool descriptions (tools/list)
- Runs embedding-based poisoning detection (MiniLM-L6-v2 cosine similarity against known malicious patterns)
- Checks for dangerous parameter names, excessive tool count, missing TLS

We tested on a production Google Workspace MCP server with 246 tools — clean, no poisoning detected. The scan took 3 seconds.

---

## Embedding-based tool poisoning detection

Static regex can't catch rephrased attacks. "Ignore previous instructions" has a hundred variants. So we added an ML layer:

1. Encode known malicious patterns into vectors (MiniLM-L6-v2, 22M params, runs locally)
2. Encode each tool description
3. Cosine similarity — if description is semantically close to a malicious pattern, alert

This catches attacks that regex misses, without sending any data to external APIs. Fully local, fully private.

---

## Shell injection: the most starred vulnerable server

**serena** (25.2K stars) — the most starred server with direct shell injection:
```python
subprocess.Popen(command, shell=True)  # unsanitized
```
The only "protection" is a docstring telling the LLM "Never execute unsafe shell commands!" That's not a security boundary.

**DesktopCommanderMCP** (6.1K stars) — writes agent-supplied code to temp file and executes:
```typescript
const proc = spawn(process.execPath, [tempFile]);
```

---

## The good news

**Anthropic's official servers are clean.** The filesystem server has proper `validatePath()`. Sequential thinking and time servers: zero findings.

**GitHub's official MCP server (30.6K stars): zero findings.** Written in Go with proper input handling.

**Clean community servers exist:** apple-mcp, chart-server, perplexity MCP — minimal or zero findings.

---

## By the numbers

| Metric | Value |
|--------|-------|
| Servers scanned (local) | 106 |
| Servers scanned (remote) | 1 (246 tools) |
| Combined GitHub stars | 300K+ |
| Confirmed RCE | 4 (3.8%) |
| By-design risks | 2 (terminal tools with bypass vectors) |
| False positives caught by manual review | 3 (ha-mcp, klavis creds, klavis eval) |
| Servers with zero findings | 12 (11.3%) |
| Responsible disclosures sent | 3 (2 confirmed, 1 closed as FP) |

---

## What static analysis can't catch

This scan is pattern-matching on source code + embedding similarity on descriptions. It catches `exec()` and `shell=True` reliably, but misses:

- **Rug-pull attacks** — server changes behavior after approval
- **Behavioral mismatches** — description says "reads files", code also writes to network
- **Validated-but-flagged** — server validates input, but scanner can't trace through validation (this caused our ha-mcp false positive)
- **Multi-server attack chains** — credential from server A used to access server B

**False positive rate after test exclusion: ~40%.** For comparison: Cisco's MCP scanner has [78% FP rate on YARA rules](https://appsecsanta.com/research/mcp-server-security-audit-2026).

---

## Try it

```bash
pip install redteam-mcp

# Scan local MCP server source code
mcp-redteam scan ./your-mcp-server --no-llm

# Scan remote MCP server via URL
mcp-redteam scan-remote https://your-server.com/mcp --token <bearer>
```

14 Semgrep rules. Embedding-based poisoning detection. Config health checks. SARIF output for CI/CD.

Source: [github.com/m0rvayne/mcp-redteam](https://github.com/m0rvayne/mcp-redteam)

---

## How this was built

I build MCP connectors and AI automation for businesses. 70+ connectors deployed across client projects. Some started breaking silently — dead servers in configs, scope conflicts, unpinned packages. I looked for a scanner and found nothing that reads source code.

Built this in a week by orchestrating AI agents — same approach [Karpathy described](https://htek.dev/articles/karpathy-directs-ai-agents-december-shift): understand the problem deeply, specify precisely, let agents implement under strict quality gates (75+ tests, self-security audit, 3 independent architecture reviews).

---

*Scan performed with redteam-mcp v0.2.0. 106 local servers + 1 remote (246 tools). Static analysis + embedding detection. Responsible disclosure sent to affected maintainers before publication.*
