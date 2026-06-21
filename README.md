<div align="center">

<img src="assets/logo.svg" alt="mcp-redteam" width="700">

**It doesn't tell you where your walls are thin. It walks through them.**

[![Tests](https://github.com/m0rvayne/mcp-redteam/actions/workflows/test.yml/badge.svg)](https://github.com/m0rvayne/mcp-redteam/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/redteam-mcp)](https://pypi.org/project/redteam-mcp/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![OWASP MCP Top 10](https://img.shields.io/badge/OWASP-MCP%20Top%2010-orange)](https://owasp.org/www-project-mcp-top-10/)
[![Claude Code Plugin](https://img.shields.io/badge/Claude%20Code-plugin-7b61ff)](https://claude.ai/code)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Downloads](https://img.shields.io/pypi/dm/redteam-mcp)](https://pypi.org/project/redteam-mcp/)

</div>

---

I build MCP connectors and AI automation for businesses. 70+ connectors deployed across client projects. Some of them started acting up — dropping connections, config conflicts, servers I forgot to remove still sitting in config eating resources.

Went looking for something to audit this. Found mcp-scan — only reads tool descriptions, doesn't touch source code. Cisco's scanner — 78% false positives. Nothing that actually reads the server code and says "line 42, you have exec() with unsanitized input."

Built my own. Ran it on 106 public MCP servers. 7 had remote code execution. One of them had 25K GitHub stars.

Open-sourced because if my connectors had these problems, so do yours.

---

Two modes of operation:

- **Claude Code plugin** — reads source code, probes tools, detects behavioral mismatches, maps cross-server attack chains. Interactive HTML report.
- **Standalone CLI** — deterministic scan. 25 Semgrep rules + 6 config health checks, SARIF output. Works in CI/CD without Claude.

## What works today

| Feature | Status | How |
|---------|--------|-----|
| Config health scanner | Working | Dead servers, scope conflicts, credential exposure, supply chain, CVE checks |
| Semgrep code analysis | Working | 25 rules (Python + JS/TS): injection, traversal, SSRF, eval, secrets, stdout |
| SARIF output | Working | GitHub Security tab integration |
| JSON output | Working | Machine-readable for CI/CD |
| Terminal output | Working | Rich colored tables with risk scores |
| CI exit codes | Working | `--fail-on critical` returns exit 1 |
| LLM behavioral analysis | Working | Anthropic SDK, behavioral mismatch detection (optional) |
| Self-security audit | Working | 10 vulnerabilities audited — 8 fixed, 1 mitigated, 1 accepted |
| Claude Code plugin | Working | AI-driven deep audit with HTML report |
| HTML report output | Working | `--format html` generates self-contained terminal-styled report |
| 177 tests | Passing | Unit, security, stress, edge cases, Hypothesis fuzzing |
| Audit history | Working | JSONL baseline storage, cross-run comparison (new/confirmed/fixed) |

## What doesn't work yet

- Cross-server chain detection in CLI (exists in Claude Code plugin only)
- Auto-fix in CLI (exists in Claude Code plugin only)
- MCPTox benchmark validation
- Community rule contributions

## Install

**Claude Code plugin** (deep AI-native audit):
```bash
# Clone to your projects directory
git clone https://github.com/m0rvayne/mcp-redteam.git
cd mcp-redteam

# The CLAUDE.md file activates as a skill automatically
# From any project with MCP servers connected:
/mcp-redteam
```

**Standalone CLI** (deterministic, CI/CD ready):
```bash
pip install redteam-mcp
mcp-redteam scan ./your-mcp-server --no-llm
```

**Remote MCP server** (via URL, OAuth or token):
```bash
pip install 'redteam-mcp[remote]'
mcp-redteam scan-remote https://your-server.com/mcp --token <bearer>
```

Requires Python 3.10+. Semgrep installed separately for code analysis: `pip install semgrep`.

## CI/CD Integration

Add to your GitHub Actions workflow:

```yaml
# .github/workflows/mcp-security.yml
name: MCP Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: m0rvayne/mcp-redteam@v0.4.1
        with:
          path: ./your-mcp-server
          fail-on: critical
```

Results appear in GitHub's Security tab. See [action.yml](action.yml) for all options.

**More examples:**
```bash
# HTML report
mcp-redteam scan ./server --format html -o report.html

# Fail CI on critical findings
mcp-redteam scan ./server --fail-on critical --format sarif -o results.sarif

# Generate shields.io security badge
mcp-redteam badge ./your-server

# Use a different LLM model for behavioral analysis
MCP_REDTEAM_MODEL=claude-haiku-4-5 mcp-redteam scan ./server
```

## Example

```
$ mcp-redteam scan ./my-mcp-server --no-llm

Phase 0: Config validation...
  2 config issues found
Phase 1: Semgrep analysis...
  5 code findings

┌──────────┬────────┬───────────────────┬──────────────────────────────────┐
│ Severity │ Rule   │ File:Line         │ Title                            │
├──────────┼────────┼───────────────────┼──────────────────────────────────┤
│ CRITICAL │ MRT001 │ server.py:42      │ Shell Injection                  │
│ HIGH     │ MRT002 │ handlers.py:15    │ Path Traversal                   │
│ HIGH     │ MRT003 │ api.py:88         │ SSRF                             │
│ MEDIUM   │ MRT012 │ .mcp.json         │ Unpinned Package                 │
│ MEDIUM   │ MRT010 │ settings.json     │ Scope Conflict                   │
└──────────┴────────┴───────────────────┴──────────────────────────────────┘

7 findings (1 critical, 2 high, 2 medium, 0 low)
Risk score: 60/100
```

## What it checks

### Config Health (deterministic)

Dead/disconnected servers, scope conflicts (same server in multiple scopes), credentials in git-tracked config files (CVE-2025-59536), unpinned npx/uvx packages (supply chain), enableAllProjectMcpServers bypass (CVE-2026-21852), orphaned MCP processes.

### Code Security (Semgrep, 25 rules)

| Rule | What it detects | Languages |
|------|----------------|-----------|
| Shell injection | subprocess + shell=True with user input | Python |
| Path traversal | open()/Path() without realpath check | Python, JS/TS |
| SSRF | HTTP requests with user-controlled URL | Python, JS/TS |
| Eval injection | eval()/exec()/new Function() with user input | Python, JS/TS |
| Hardcoded secrets | API keys, tokens, passwords in source | Python, JS/TS |
| Stdout pollution | print()/console.log() in stdio handlers | Python, JS/TS |
| Missing error handling | Tool functions without try/catch | Python, JS/TS |
| Credential in response | API keys/tokens in tool return values | Python, JS/TS |
| Missing signal handler | Server without SIGTERM/SIGINT | Python |
| Blocking sync calls | requests.get() inside async functions | Python |
| OAuth over-privilege | Excessive OAuth scopes (gmail.modify, admin) | Python |
| No timeout on HTTP | httpx/requests/fetch without timeout | Python, JS/TS |
| No timeout on subprocess | subprocess/spawn without timeout | Python, JS/TS |
| Dangerous parameter names | Tool params named cmd, exec, eval, code | JS/TS |
| Env secrets without rotation | API keys from os.getenv used directly | Python |

Based on 48+ CVEs, OWASP MCP Top 10, and research from Invariant Labs, Trail of Bits, Palo Alto Unit 42, OX Security, and Snyk.

### LLM Behavioral Analysis (optional, requires API key)

- **Behavioral mismatch**: tool description claims X, code does Y
- **Hidden operations**: undeclared network requests, file writes, subprocess calls
- **Credential mishandling**: secrets logged, leaked in errors, stored insecurely

## How it compares

| | mcp-scan (Invariant Labs) | Cisco MCP Scanner | **mcp-redteam** |
|---|---|---|---|
| Approach | Static description scan | YARA + LLM-as-judge | **Semgrep taint + LLM behavioral** |
| Reads source code | No | Python only | **Yes — Python + JS/TS** |
| Config validation | No | Config discovery | **Yes — 6 checks, CVE detection** |
| Behavioral mismatch | No | No | **Yes (LLM layer)** |
| SARIF output | No | No | **Yes** |
| CI exit codes | Yes | No | **Yes** |
| Self-tested | Unknown | Unknown | **177 tests, self-security audit** |
| Cloud dependency | Invariant Labs API | Cisco API (optional) | **No — fully local in deterministic mode. LLM mode uses Anthropic API** |

### Why not just use mcp-scan?

mcp-scan reads what a server **says about itself** — tool descriptions. mcp-redteam checks what a server **actually does** — source code analysis + behavioral analysis.

A server with clean descriptions but leaky code: mcp-scan passes it. We catch it.

Real findings mcp-scan cannot detect (they live in code, not descriptions):
- Trello API keys in `.env` committed to git
- Instagram session cookies stored in plaintext
- AppleScript injection via unescaped clipboard input
- Google OAuth tokens with permissions `644`

## Audit History

Each scan saves a JSONL baseline to `~/.mcp-redteam/baselines/`. Subsequent runs compare results and classify findings as **new**, **confirmed**, or **fixed** — turning LLM non-determinism into an advantage.

## Architecture

```
 /mcp-redteam
      |
 +-----------------+
 | Phase 0: Config |
 +-----------------+
      |
 +-----------+
 | Discovery |
 +-----------+
      |
      |   1 server = 1 agent
      |
 +----------+ +----------+ +----------+ +----------+
 | Agent-01 | | Agent-02 | | Agent-03 | | Agent-N  |
 | youtube  | | trello   | | instagram| | server-N |
 | health   | | health   | | health   | | health   |
 | arch     | | arch     | | arch     | | arch     |
 | complete | | complete | | complete | | complete |
 | security | | security | | security | | security |
 +----+-----+ +----+-----+ +----+-----+ +----+-----+
      |            |            |            |
      +------+-----+-----+------+
             |
 +-------------------------+
 | Chain analysis + report |
 +-------------------------+
             |
    +----------------+
    | HTML + Fix     |
    +----------------+
```

## Tests

177 tests across 13 test files:

- **test_semgrep.py** — each vulnerable fixture detected, each benign fixture clean
- **test_self_security.py** — 21 tests: our own code audited for vulnerabilities
- **test_stress.py** — 1000/10000 findings, concurrent scans, unicode
- **test_fuzzing.py** — Hypothesis property-based: any input, no crash
- **test_edge_cases.py** — corrupt JSON, missing files, null bytes, timeouts
- **test_models.py** + **test_formatters.py** — unit tests for core logic
- **test_cli.py** — 11 tests: CLI argument parsing, output formats, exit codes
- **test_config_scanner.py** — 13 tests: config health checks, scope conflicts, credential detection

## Current Limitations

- Plugin requires Claude Code with connected MCP servers
- CLI requires semgrep for code analysis (graceful skip if not installed)
- LLM analysis requires ANTHROPIC_API_KEY
- Destructive tests intentionally skipped — read-only probing only
- Source code analysis works for local servers; pip/npm packages may have limited access
- Plugin report quality scales with model capability (Opus > Sonnet > Haiku)
- False positive rate not yet measured on production MCP servers

### Known False Positive Patterns

- SSRF rule triggers on `httpx.get()` with URL built from config, not user input
- Path traversal rule triggers on `open()` where path is validated but validation isn't recognized as sanitizer
- Stdout pollution flags `print()` in `__main__` block (safe, not in MCP handler)

## Docs

The `docs/` folder is useful independently:

- **[attack-playbook.md](docs/attack-playbook.md)** — 18 attack categories, 48+ CVEs, payloads and detection methods
- **[best-practices.md](docs/best-practices.md)** — MCP server security checklist
- **[reference-server.md](docs/reference-server.md)** — secure server templates (Python + Node.js)
- **[troubleshooting.md](docs/troubleshooting.md)** — common issues and fixes

## References

- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [Invariant Labs — Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [Trail of Bits — MCP Security Layer](https://blog.trailofbits.com/2025/07/28/we-built-the-security-layer-mcp-always-needed/)
- [Palo Alto Unit 42 — MCP Attack Vectors](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)
- [OX Security — STDIO Design Flaw](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/)
- [NSA — MCP Security Guidance](https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf)
- [Vulnerable MCP Project](https://vulnerablemcp.info/)

## License

[MIT](LICENSE)
