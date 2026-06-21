# Awesome List Submissions — mcp-redteam

Ready-to-submit entries and PR descriptions for 10 awesome lists.

---

## 1. awesome-mcp-security (Puliczek)

**Repo:** https://github.com/Puliczek/awesome-mcp-security
**Section:** Security Tools / Scanners
**Entry:**

```
- [mcp-redteam](https://github.com/m0rvayne/mcp-redteam) - MCP security scanner with Semgrep source code analysis (Python + JS/TS). 25 taint-tracking rules, config health checks, SARIF output for CI/CD, audit history with cross-run comparison. CLI + Claude Code plugin.
```

**PR Title:** Add mcp-redteam — source code security scanner for MCP servers
**PR Body:**

Hi! I'd like to add mcp-redteam to the security tools section.

**What it does:** Scans MCP server source code (Python + JS/TS) for injection, traversal, SSRF, credential leaks, and config issues using 25 Semgrep taint-tracking rules.

**How it differs from mcp-scan:** Reads source code, not just tool descriptions. Catches vulnerabilities that description-only scanners miss (e.g., hardcoded secrets, path traversal via Path operators, shell injection with unsanitized input).

**Key features:**
- 25 Semgrep rules covering OWASP MCP Top 10 (Python + JS/TS)
- Config health scanner (dead servers, scope conflicts, credential exposure, CVE-2025-59536 / CVE-2026-21852)
- SARIF output for GitHub Security tab integration
- Audit history with JSONL baselines and cross-run comparison (new/confirmed/fixed)
- 95+ tests including fuzzing and self-security audit
- Fully local in deterministic mode — no cloud dependency
- MIT licensed

[Link to repo](https://github.com/m0rvayne/mcp-redteam)

---

## 2. awesome-claude-code-security (efij)

**Repo:** https://github.com/efij/awesome-claude-code-security
**Section:** Security Tools
**Entry:**

```
- [mcp-redteam](https://github.com/m0rvayne/mcp-redteam) - Security scanner for MCP servers connected to Claude Code. Source code analysis with 25 Semgrep rules, config health checks (dead servers, scope conflicts, CVE detection), and a Claude Code plugin mode for deep AI-driven audits with HTML reports.
```

**PR Title:** Add mcp-redteam — MCP security scanner with Claude Code plugin
**PR Body:**

Hi! I'd like to add mcp-redteam to the security tools section.

**What it does:** Two-mode MCP security scanner designed for Claude Code environments:

1. **Claude Code plugin** — reads MCP server source code, probes tools, detects behavioral mismatches, maps cross-server attack chains. Generates interactive HTML reports.
2. **Standalone CLI** — deterministic scan with 25 Semgrep rules + 6 config health checks. SARIF output for CI/CD.

**Relevant to Claude Code security because:**
- Detects config issues specific to Claude Code: scope conflicts between `.mcp.json` / `settings.json` / `settings.local.json`, `enableAllProjectMcpServers` bypass (CVE-2026-21852), `ANTHROPIC_BASE_URL` override (CVE-2025-59536)
- Plugin activates via CLAUDE.md as a skill — runs `/mcp-redteam` from any project
- Audits all connected MCP servers in parallel (one agent per server)
- 95+ tests, MIT licensed

[Link to repo](https://github.com/m0rvayne/mcp-redteam)

---

## 3. awesome-claude-code (jqueryscript)

**Repo:** https://github.com/jqueryscript/awesome-claude-code
**Section:** Security / Plugins
**Entry:**

```
- [mcp-redteam](https://github.com/m0rvayne/mcp-redteam) - Security scanner for MCP servers. Claude Code plugin for AI-driven deep audits with HTML reports, plus standalone CLI with 25 Semgrep rules and SARIF output for CI/CD.
```

**PR Title:** Add mcp-redteam — MCP security scanner (Claude Code plugin + CLI)
**PR Body:**

Hi! I'd like to add mcp-redteam to the list.

**What it does:** Security scanner for MCP servers with two modes:

- **Claude Code plugin** — activates via CLAUDE.md, reads server source code, probes read-only tools, detects behavioral mismatches between descriptions and code, maps cross-server attack chains. Produces interactive HTML reports.
- **Standalone CLI** — 25 Semgrep taint-tracking rules (Python + JS/TS), config health checks, SARIF output, CI exit codes. Runs fully local without Claude.

**Key features:**
- Config health scanner detects dead servers, scope conflicts, credential exposure, CVEs
- Audit history with cross-run comparison (new/confirmed/fixed findings)
- GitHub Actions integration (`uses: m0rvayne/mcp-redteam@v0.4`)
- 95+ tests, MIT licensed

[Link to repo](https://github.com/m0rvayne/mcp-redteam)

---

## 4. awesome-claude-code-toolkit (rohitg00)

**Repo:** https://github.com/rohitg00/awesome-claude-code-toolkit
**Section:** Security / Testing Tools
**Entry:**

```
- [mcp-redteam](https://github.com/m0rvayne/mcp-redteam) - MCP server security scanner. Claude Code plugin for deep source code audits with cross-server chain analysis and HTML reports. Standalone CLI with 25 Semgrep rules and SARIF output for CI/CD pipelines.
```

**PR Title:** Add mcp-redteam — MCP security scanner for Claude Code
**PR Body:**

Hi! I'd like to add mcp-redteam to the toolkit list.

**What it does:** Audits MCP servers for security vulnerabilities through source code analysis, not just description scanning.

**Two modes:**
- **Claude Code plugin** — reads source, probes tools, detects behavioral mismatches, maps cross-server attack chains. HTML report output.
- **CLI** — 25 Semgrep rules (Python + JS/TS) covering injection, traversal, SSRF, eval, secrets, stdout pollution. SARIF output for GitHub Security tab.

**Also checks Claude Code config health:** dead servers, scope conflicts between `.mcp.json` / `settings.json`, credential exposure, unpinned npx/uvx packages, CVE-2025-59536 and CVE-2026-21852 vectors.

- GitHub Actions support: `uses: m0rvayne/mcp-redteam@v0.4`
- 95+ tests, MIT licensed

[Link to repo](https://github.com/m0rvayne/mcp-redteam)

---

## 5. awesome-claude-skills (travisvn)

**Repo:** https://github.com/travisvn/awesome-claude-skills
**Section:** Security / Development Tools
**Entry:**

```
- [mcp-redteam](https://github.com/m0rvayne/mcp-redteam) - MCP security auditor skill. Reads server source code, checks config health, detects injection/traversal/SSRF vulnerabilities, and generates HTML reports. Activates via `/mcp-redteam` command.
```

**PR Title:** Add mcp-redteam — MCP security auditor skill
**PR Body:**

Hi! I'd like to add mcp-redteam as a Claude Code skill.

**What it does:** CLAUDE.md-based skill that audits all connected MCP servers for security vulnerabilities. Activates with `/mcp-redteam` from any project.

**How it works:**
1. Phase 0 — validates MCP config health (dead servers, scope conflicts, credential exposure, CVE checks)
2. Phase 1 — spawns one agent per server, reads source code, runs 4 audit categories (health, architecture, completeness, security)
3. Phase 2 — maps cross-server attack chains, generates interactive HTML report

**Also available as standalone CLI** with 25 Semgrep rules and SARIF output for CI/CD — works without Claude.

- Safe mode (default): read-only analysis, zero state changes
- Active mode (opt-in): controlled read-only probing with malformed input for error analysis
- 95+ tests, MIT licensed

[Link to repo](https://github.com/m0rvayne/mcp-redteam)

---

## 6. awesome-mcp (korchasa)

**Repo:** https://github.com/korchasa/awesome-mcp
**Section:** Security / Tools
**Entry:**

```
- [mcp-redteam](https://github.com/m0rvayne/mcp-redteam) - Security scanner for MCP servers. 25 Semgrep taint-tracking rules (Python + JS/TS), config health checks, SARIF output, audit history. Reads source code to find injection, traversal, SSRF, and credential leaks.
```

**PR Title:** Add mcp-redteam — MCP server security scanner with source code analysis
**PR Body:**

Hi! I'd like to add mcp-redteam to the security section.

**What it does:** Scans MCP server source code for security vulnerabilities using 25 Semgrep taint-tracking rules (Python + JS/TS). Also validates MCP config health: dead servers, scope conflicts, credential exposure, unpinned packages, CVE detection.

**Key differentiator:** Reads source code, not just tool descriptions. Based on 48+ CVEs, OWASP MCP Top 10, and research from Invariant Labs, Trail of Bits, Palo Alto Unit 42, OX Security, and Snyk.

**Features:**
- 25 rules: shell injection, path traversal, SSRF, eval, hardcoded secrets, stdout pollution, missing error handling, credential in response, blocking sync calls, OAuth over-privilege, missing timeouts
- SARIF output for GitHub Security tab
- Audit history with cross-run comparison
- GitHub Actions integration
- Claude Code plugin mode for deep AI-driven audits
- 95+ tests, MIT licensed

[Link to repo](https://github.com/m0rvayne/mcp-redteam)

---

## 7. awesome-mcp-servers (appcypher)

**Repo:** https://github.com/appcypher/awesome-mcp-servers
**Section:** Security
**Entry:**

```
- [mcp-redteam](https://github.com/m0rvayne/mcp-redteam) - Security scanner for MCP servers. Source code analysis with 25 Semgrep rules (Python + JS/TS), config health checks, SARIF output for CI/CD, and audit history with cross-run comparison.
```

**PR Title:** Add mcp-redteam — MCP server security scanner
**PR Body:**

Hi! I'd like to add mcp-redteam to the security section.

**What it does:** Scans MCP server source code for security vulnerabilities — injection, path traversal, SSRF, eval, hardcoded secrets, credential leaks. Uses 25 Semgrep taint-tracking rules for Python + JS/TS.

**Also includes:**
- Config health scanner (dead servers, scope conflicts, credential exposure, CVE checks)
- SARIF output for GitHub Security tab integration
- GitHub Actions support (`uses: m0rvayne/mcp-redteam@v0.4`)
- Audit history with JSONL baselines — tracks new, confirmed, and fixed findings across runs
- Claude Code plugin mode for AI-driven deep audits with HTML reports
- 95+ tests, MIT licensed

Based on OWASP MCP Top 10 and 48+ real CVEs.

[Link to repo](https://github.com/m0rvayne/mcp-redteam)

---

## 8. awesome-ai-security (ottosulin)

**Repo:** https://github.com/ottosulin/awesome-ai-security
**Section:** Tools / AI Infrastructure Security
**Entry:**

```
- [mcp-redteam](https://github.com/m0rvayne/mcp-redteam) - Security scanner for Model Context Protocol (MCP) servers. 25 Semgrep taint-tracking rules detect injection, traversal, SSRF, and credential leaks in Python + JS/TS server code. Config health checks cover dead servers, scope conflicts, and supply chain risks. SARIF output for CI/CD.
```

**PR Title:** Add mcp-redteam — security scanner for MCP (Model Context Protocol) servers
**PR Body:**

Hi! I'd like to add mcp-redteam to the AI security tools section.

**Context:** MCP (Model Context Protocol) is Anthropic's standard for connecting AI models to external tools and data sources. MCP servers are high-value targets — they handle credentials, execute code, and access file systems on behalf of AI agents.

**What it does:** Static security analysis of MCP server source code using 25 Semgrep taint-tracking rules (Python + JS/TS). Detects:
- Shell injection (subprocess + shell=True with user input)
- Path traversal (open()/Path() without realpath validation)
- SSRF (HTTP requests with user-controlled URLs)
- Eval injection (eval/exec/new Function with user input)
- Hardcoded secrets and credential leaks
- Stdout pollution (breaks MCP stdio transport)
- Missing error handling, timeouts, signal handlers

**Also validates MCP config security:** credential exposure in config files, unpinned npm/pip packages (supply chain), scope conflicts, CVE-2025-59536 and CVE-2026-21852 detection.

Based on OWASP MCP Top 10 and 48+ real CVEs. Research references: Invariant Labs, Trail of Bits, Palo Alto Unit 42, OX Security, NSA MCP Security Guidance.

- SARIF output for GitHub Security tab
- GitHub Actions integration
- 95+ tests including fuzzing and self-security audit
- Fully local — no cloud dependency in deterministic mode
- MIT licensed

[Link to repo](https://github.com/m0rvayne/mcp-redteam)

---

## 9. awesome-mcp-servers (wong2)

**Repo:** https://github.com/wong2/awesome-mcp-servers
**Section:** Security / Developer Tools
**Entry:**

```
- [mcp-redteam](https://github.com/m0rvayne/mcp-redteam) - Security scanner for MCP servers. Source code analysis with 25 Semgrep rules (Python + JS/TS), config health checks, SARIF output, audit history.
```

**PR Title:** Add mcp-redteam — MCP server security scanner
**PR Body:**

Hi! I'd like to add mcp-redteam.

**What it does:** Scans MCP server source code for security vulnerabilities using 25 Semgrep taint-tracking rules. Covers Python + JS/TS. Detects shell injection, path traversal, SSRF, eval injection, hardcoded secrets, stdout pollution, missing error handling, credential leaks, and more.

**Features:**
- Config health scanner (dead servers, scope conflicts, credential exposure, CVE checks)
- SARIF output for GitHub Security tab
- CI/CD integration with GitHub Actions
- Audit history with cross-run comparison
- Claude Code plugin mode for AI-driven deep audits
- 95+ tests, MIT licensed

[Link to repo](https://github.com/m0rvayne/mcp-redteam)

---

## 10. awesome-cyber-security-mcp (MorDavid)

**Repo:** https://github.com/MorDavid/awesome-cyber-security-mcp
**Section:** Vulnerability Scanning / Security Testing
**Entry:**

```
- [mcp-redteam](https://github.com/m0rvayne/mcp-redteam) - Red team scanner for MCP servers. 25 Semgrep taint-tracking rules detect injection, traversal, SSRF, eval, and credential leaks in server source code (Python + JS/TS). Config health checks, SARIF output, audit history, and a Claude Code plugin for AI-driven deep audits with cross-server attack chain analysis.
```

**PR Title:** Add mcp-redteam — red team security scanner for MCP servers
**PR Body:**

Hi! I'd like to add mcp-redteam to the security tools section.

**What it does:** Red team-oriented security scanner for MCP servers. Reads server source code (not just descriptions) and traces vulnerability paths from user input to dangerous functions.

**Two modes:**
1. **CLI (deterministic)** — 25 Semgrep taint-tracking rules (Python + JS/TS), config health checks, SARIF output. Works in CI/CD without AI.
2. **Claude Code plugin (AI-driven)** — deep audit with behavioral mismatch detection and cross-server attack chain analysis. Spawns one agent per server, generates HTML reports.

**Detection coverage:**
- Shell injection, path traversal, SSRF, eval injection
- Hardcoded secrets, credential leaks in error handlers
- OAuth over-privilege, missing timeouts, blocking sync calls
- Config issues: dead servers, scope conflicts, credential exposure, supply chain (unpinned packages)
- CVE-2025-59536 and CVE-2026-21852 detection

Based on OWASP MCP Top 10, 48+ CVEs, and research from Invariant Labs, Trail of Bits, Palo Alto Unit 42, OX Security, NSA.

- Audit history with JSONL baselines — tracks new/confirmed/fixed findings across runs
- 95+ tests including fuzzing and self-security audit
- MIT licensed

[Link to repo](https://github.com/m0rvayne/mcp-redteam)
