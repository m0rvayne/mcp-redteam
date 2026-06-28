# MCP Directory Submissions

Submission content for 10 MCP directories and tool registries.

**Package:** `pip install redteam-mcp`
**Repo:** https://github.com/m0rvayne/mcp-redteam
**License:** MIT

---

## 1. mcp.so

- **URL:** https://mcp.so
- **Submission method:** GitHub issue at [chatmcp/mcpso](https://github.com/chatmcp/mcpso/issues/new)
- **Category:** Security Tools

**Title:** mcp-redteam — MCP Security Scanner (Semgrep + Behavioral Analysis)

**Description:**
Security scanner for MCP servers. 25 Semgrep rules detect shell injection, path traversal, SSRF, eval, hardcoded secrets, and stdout pollution in Python and JS/TS servers. Config health checks catch dead servers, scope conflicts, credential exposure, and supply chain risks. Outputs SARIF for GitHub Security tab integration. Works standalone in CI/CD or as a Claude Code plugin for deep AI-driven audit with cross-server attack chain analysis.

**Install:**
```bash
pip install redteam-mcp
mcp-redteam scan ./your-mcp-server --no-llm
```

**Special requirements:** Submit as GitHub issue with server name, description, GitHub URL, and category.

---

## 2. Glama

- **URL:** https://glama.ai/mcp/servers
- **Submission method:** Auto-syncs from GitHub based on repository topics
- **Category:** Security / Developer Tools

**Action required:** Verify these GitHub topics are set on the repo:
- `mcp-server`
- `model-context-protocol`
- `security`
- `semgrep`
- `vulnerability-scanner`

Glama discovers servers automatically from GitHub. No manual submission needed if topics are correctly set. The repo should already appear at https://glama.ai/mcp/servers after indexing.

---

## 3. PulseMCP

- **URL:** https://www.pulsemcp.com
- **Submission method:** Web form at https://www.pulsemcp.com/submit
- **Category:** Security / Developer Tools

**Title:** mcp-redteam

**Description:**
MCP security scanner that reads server source code to find real vulnerabilities. 25 Semgrep rules cover injection, traversal, SSRF, eval, secrets, and stdout pollution across Python and JS/TS. Config health checks detect dead servers, scope conflicts, credential exposure (CVE-2025-59536), and supply chain risks. SARIF output for CI/CD, HTML reports, and audit history with cross-run comparison. Also works as a Claude Code plugin for AI-driven deep audit.

**Install:**
```bash
pip install redteam-mcp
```

---

## 4. Smithery

- **URL:** https://smithery.ai
- **Submission method:** Add `smithery.yaml` to repo root, then publish via Smithery dashboard at https://smithery.ai/new
- **Category:** Security Tools

**smithery.yaml** has been created at the repo root. See `/smithery.yaml`.

**Publishing steps:**
1. Push `smithery.yaml` to the repo
2. Go to https://smithery.ai/new
3. Enter the GitHub repo URL: `https://github.com/m0rvayne/mcp-redteam`
4. Complete the publishing workflow

**Title:** mcp-redteam

**Description:**
MCP security scanner with 25 Semgrep rules for Python and JS/TS servers. Detects shell injection, path traversal, SSRF, eval, hardcoded secrets, stdout pollution, and more. Includes config health checks, SARIF output for CI/CD, and optional LLM behavioral analysis.

---

## 5. MCP.directory

- **URL:** https://mcp.directory
- **Submission method:** Web form at https://mcp.directory/submit
- **Category:** Security / Developer Tools

**Title:** mcp-redteam

**URL:** https://github.com/m0rvayne/mcp-redteam

**Description:**
Security scanner for MCP servers that analyzes source code, not just tool descriptions. Uses 25 Semgrep rules to detect injection, traversal, SSRF, eval, and secrets in Python and JS/TS. Config health checks find dead servers, scope conflicts, and credential exposure. SARIF output integrates with GitHub Security tab. Works as standalone CLI for CI/CD or as a Claude Code plugin for AI-driven audit with cross-server attack chain detection.

**Install:**
```bash
pip install redteam-mcp
mcp-redteam scan ./your-mcp-server --no-llm
```

---

## 6. MCPServerHub

- **URL:** https://mcpserverhub.net
- **Submission method:** Web form at https://mcpserverhub.net/submit
- **Category:** Security Tools

**Title:** mcp-redteam — MCP Security Scanner

**URL:** https://github.com/m0rvayne/mcp-redteam

**Description:**
Scans MCP servers for security vulnerabilities using 25 Semgrep rules (Python + JS/TS). Detects shell injection, path traversal, SSRF, eval injection, hardcoded secrets, and stdout pollution. Config health checks catch dead servers, scope conflicts, and credential exposure. Outputs SARIF, JSON, HTML, or terminal. CI/CD ready with `--fail-on` exit codes. Optional LLM layer for behavioral mismatch detection.

**Install:**
```bash
pip install redteam-mcp
```

---

## 7. MCPServe

- **URL:** https://mcpserve.com
- **Submission method:** Web form at https://mcpserve.com/submit
- **Category:** Security / Developer Tools

**Title:** mcp-redteam

**URL:** https://github.com/m0rvayne/mcp-redteam

**Description:**
MCP security scanner that reads source code to find vulnerabilities other scanners miss. 25 Semgrep rules for Python and JS/TS cover injection, traversal, SSRF, eval, secrets, and stdout pollution. Config health scanner detects dead servers, scope conflicts, credential exposure, and unpinned packages. SARIF output for GitHub Security tab. 197 tests including fuzzing. Also runs as a Claude Code plugin for AI-driven deep audit with HTML reports.

**Install:**
```bash
pip install redteam-mcp
mcp-redteam scan ./server --no-llm
```

---

## 8. LobeHub

- **URL:** https://lobehub.com/mcp
- **Submission method:** Pull request to [lobehub/lobe-chat-agents](https://github.com/lobehub/lobe-chat-agents) or the MCP marketplace repo
- **Category:** Security Tools

**Steps:**
1. Fork the LobeHub marketplace repo
2. Add a server entry following their contribution template
3. Submit a PR

**Title:** mcp-redteam

**Description:**
MCP security scanner with source code analysis. 25 Semgrep rules detect shell injection, path traversal, SSRF, eval, hardcoded secrets, and stdout pollution in Python and JS/TS MCP servers. Includes config health checks, SARIF output for CI/CD, and optional LLM behavioral analysis for detecting description-vs-code mismatches.

**Install command:**
```bash
pip install redteam-mcp
```

**Special requirements:** Check LobeHub's contribution guidelines for the exact JSON/YAML format they require for marketplace entries.

---

## 9. Official MCP Registry

- **URL:** https://modelcontextprotocol.io
- **Submission method:** CLI via `mcp-publisher publish` (if available), or PR to [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers)
- **Category:** Security Tools

**Note:** The official MCP registry and `mcp-publisher` CLI may not yet be publicly available. As of now, the primary path is submitting a PR to the official servers repository or waiting for the registry to open submissions.

**Title:** mcp-redteam

**Description:**
Security scanner for MCP servers. Analyzes source code with 25 Semgrep rules to detect shell injection, path traversal, SSRF, eval injection, hardcoded secrets, and stdout pollution across Python and JS/TS. Config health checks detect dead servers, scope conflicts, credential exposure, and supply chain risks. SARIF output, CI/CD exit codes, audit history, and optional LLM behavioral analysis.

**Install:**
```bash
pip install redteam-mcp
```

**Special requirements:** Follow the contribution guidelines in the modelcontextprotocol/servers repo. The server must follow MCP specification standards.

---

## 10. mcpservers.org

- **URL:** https://mcpservers.org
- **Submission method:** Web form at https://mcpservers.org/submit
- **Category:** Security / Developer Tools

**Title:** mcp-redteam — MCP Security Scanner

**URL:** https://github.com/m0rvayne/mcp-redteam

**Description:**
Security scanner that audits MCP servers by analyzing source code, not just descriptions. 25 Semgrep rules for Python and JS/TS detect shell injection, path traversal, SSRF, eval, hardcoded secrets, and stdout pollution. Config health checks catch dead servers, scope conflicts, credential exposure (including CVE detection), and unpinned supply chain packages. Outputs SARIF for GitHub Security tab, plus JSON, HTML, and terminal formats. 197 tests with fuzzing. Also functions as a Claude Code plugin for AI-driven audit with cross-server attack chain analysis.

**Install:**
```bash
pip install redteam-mcp
mcp-redteam scan ./your-mcp-server --no-llm
```

---

## Submission Checklist

| Directory | Method | Status |
|-----------|--------|--------|
| mcp.so | GitHub issue | Pending |
| Glama | Auto-sync (GitHub topics) | Verify topics |
| PulseMCP | Web form | Pending |
| Smithery | smithery.yaml + dashboard | smithery.yaml created |
| MCP.directory | Web form | Pending |
| MCPServerHub | Web form | Pending |
| MCPServe | Web form | Pending |
| LobeHub | PR to marketplace repo | Pending |
| Official MCP Registry | CLI or PR | Pending (registry may not be open) |
| mcpservers.org | Web form | Pending |
