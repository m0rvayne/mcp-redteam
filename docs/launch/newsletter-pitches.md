# Newsletter Pitches — mcp-redteam

---

## 1. tl;dr sec (Clint Gibler)

**Submit:** https://tldrsec.com/submit or email

**Subject:** Open-source tool reads MCP server source code to find RCE — found 7 across 106 public servers

Hi Clint,

mcp-redteam is an open-source MCP security scanner that does what existing tools don't: reads server source code. mcp-scan checks tool descriptions; Cisco's scanner has a 78% FP rate. This one runs 25 Semgrep taint-tracking rules across Python and JS/TS to trace user input to dangerous sinks.

Key facts:
- Scanned 106 public MCP servers, found 7 RCE (one had 25K GitHub stars)
- 25 Semgrep rules based on 48+ CVEs, OWASP MCP Top 10, and research from Invariant Labs, Trail of Bits, Unit 42
- SARIF output + GitHub Action for CI/CD integration
- Ran its own scanner on itself — published results (8 fixed, 1 mitigated, 1 accepted)

Link: https://github.com/m0rvayne/mcp-redteam
Install: `pip install redteam-mcp`

---

## 2. AI Security Newsletter / AISecHub

**Submit:** Medium comment or email

**Subject:** We scanned 106 MCP servers for code-level vulnerabilities — here's what broke

Hi,

MCP adoption is accelerating but server security tooling is stuck at description-level scanning. mcp-redteam is an open-source scanner that performs actual source code analysis on MCP servers using Semgrep taint tracking — not just reading what a server says about itself.

Key facts:
- 106 public MCP servers scanned, 7 had remote code execution
- Detects shell injection, path traversal, SSRF, credential exposure, tool poisoning — 25 rules total
- Config health checks catch CVE-2025-59536 (credential exfil) and CVE-2026-21852 (auto-enable bypass)
- Self-security audit published: tested its own code with its own scanner, fixed 8 of 10 findings

Link: https://github.com/m0rvayne/mcp-redteam
Install: `pip install redteam-mcp`

---

## 3. TLDR Newsletter

**Submit:** https://tldr.tech/submit (Open Source section)

**Subject:** mcp-redteam — open-source security scanner for MCP servers (v0.3.0)

Hi,

mcp-redteam is an open-source security scanner for Model Context Protocol servers. It uses 25 Semgrep rules to find injection, traversal, and credential leaks in MCP server source code — Python and JS/TS.

Key facts:
- CI/CD ready: SARIF output, GitHub Action, `--fail-on critical` exit codes
- Found 7 RCE vulnerabilities across 106 public MCP servers
- Works fully local in deterministic mode, no cloud dependency
- 177 tests including fuzzing; ran its own scanner on its own code

Link: https://github.com/m0rvayne/mcp-redteam
Install: `pip install redteam-mcp`

---

## 4. Practical DevSecOps

**Submit:** Contact form or email

**Subject:** CI/CD-ready MCP security scanner with SARIF output and GitHub Action

Hi,

You already track MCP security tools — mcp-redteam fills the CI/CD gap. It's an open-source scanner with a GitHub Action that runs 25 Semgrep rules against MCP server code, outputs SARIF for the GitHub Security tab, and returns exit codes for pipeline gating.

Key facts:
- GitHub Action: `uses: m0rvayne/mcp-redteam@v0.4.1` with `fail-on: critical`
- SARIF output integrates directly with GitHub Security tab
- 25 rules covering OWASP MCP Top 10: injection, traversal, SSRF, credential exposure, stdout pollution
- Config health checks detect dead servers, scope conflicts, unpinned supply chain packages
- Self-tested: 177 tests + published self-security audit

Link: https://github.com/m0rvayne/mcp-redteam
Install: `pip install redteam-mcp`

---

## 5. Gradient Flow

**Submit:** Reply to newsletter (Substack)

**Subject:** The security tooling gap for AI agents running MCP

Hi,

AI agents are connecting to external services through MCP, but security tooling hasn't caught up. Existing scanners read tool descriptions — the equivalent of trusting a package by its README. mcp-redteam reads the actual server source code using Semgrep taint tracking to trace user input to dangerous functions.

Key facts:
- Scanned 106 public MCP servers, found 7 with remote code execution
- Source code analysis (not description scanning) across Python and JS/TS
- Based on 48+ CVEs and research from Trail of Bits, Invariant Labs, Palo Alto Unit 42
- Unique angle: ran its own scanner on its own code and published the results — 8 of 10 findings fixed

Link: https://github.com/m0rvayne/mcp-redteam
Install: `pip install redteam-mcp`
