<div align="center">

<img src="assets/logo.svg" alt="mcp-redteam" width="700">

**It doesn't tell you where your walls are thin. It walks through them.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![OWASP MCP Top 10](https://img.shields.io/badge/OWASP-MCP%20Top%2010-orange)](https://owasp.org/www-project-mcp-top-10/)
[![Claude Code Plugin](https://img.shields.io/badge/Claude%20Code-plugin-7b61ff)](https://claude.ai/code)
[![Phase 0 Config](https://img.shields.io/badge/Phase%200-Config%20Validation-green)](#config-health-phase-0)

</div>

---

A Claude Code plugin + standalone CLI that audits and penetration-tests your MCP servers. Reads source code, probes every tool, finds what's broken — and shows you how to fix it.

Two modes: **AI-native deep audit** (Claude Code plugin — behavioral analysis, cross-server chains, rug-pull detection) and **deterministic scan** (standalone CLI — 30 Semgrep rules, SARIF output, CI/CD ready).

Not a static scanner. Not a config checker. An active red team that validates your configs, isolates each server, attacks it across five categories, and generates an interactive HTML report with proven findings.

## Install

**Claude Code plugin** (deep AI-native audit):
```bash
claude plugin marketplace add m0rvayne/mcp-redteam
claude plugin install mcp-redteam
/mcp-redteam
```

**Standalone CLI** (deterministic, CI/CD ready):
```bash
pip install mcp-redteam
mcp-redteam scan ./your-mcp-server --no-llm --format sarif
```

## What happens when you run it

0. **Config Validation** — checks config health before any audit starts: connection health, scope conflicts, credential exposure in config files, supply chain risks (unpinned npx/uvx), network exposure, orphaned processes. Catches problems no scanner looks for.
1. **Discovery** — finds all your connected MCP servers
2. **Isolation** — spawns one dedicated agent per server (10 servers = 10 agents)
3. **Source analysis** — each agent reads the server's source code
4. **Attack** — systematically tests every tool against every applicable vulnerability
5. **Report** — generates an interactive HTML report with findings, evidence, and fixes
6. **Fix** — offers to apply fixes with your confirmation

## What it checks

Each server gets a full audit across five categories:

### Config Health (Phase 0)

Dead/disconnected servers, scope conflicts (same server in multiple scopes), credentials in git-tracked config files (CVE-2025-59536), unpinned npx/uvx packages (supply chain), enableAllProjectMcpServers bypass (CVE-2026-21852), orphaned MCP processes.

### Health

Signal handling, stdout pollution, blocking sync calls in async context, HTTP timeouts, subprocess timeouts, error containment, HTTP client lifecycle, venv integrity, graceful shutdown.

### Architecture

Code structure and modularity, tool count sanity (230 tools = red flag), dependency pinning, OAuth token lifecycle, error message content analysis, resource cleanup and disk growth, framework choice assessment.

### Completeness

API coverage gaps, input schema validation, .gitignore for secrets, credential file permissions, type safety, compile/syntax checks.

### Security

Path traversal with real payloads (`../../etc/passwd` and variants). SSRF probing (`169.254.169.254`, `file://`, localhost). Command injection testing (`;`, `|`, `` ` ``, `$()`). Credential storage audit (plaintext tokens, world-readable files). Error message analysis (does `str(e)` leak API keys?). Tool poisoning detection (hidden `<IMPORTANT>` tags, Unicode smuggling). Type confusion, resource exhaustion, cross-tool exfiltration chains.

Based on 40+ CVEs, OWASP MCP Top 10, and research from Invariant Labs, Trail of Bits, Palo Alto Unit 42, OX Security, and Snyk.

## What you get

An interactive HTML report — not a PDF, not a dashboard. A document that opens in any browser, works on mobile, and lets you drill into each server:

- **Per-server breakdown** — click a server, see everything that's wrong with it
- **Proven findings** — "we wrote to ~/.bashrc via path traversal", not "may be vulnerable"
- **Risk score** — 0 to 100 per server, so you know where to start
- **Remediation roadmap** — prioritized fixes with exact code changes
- **Defended checks** — what your servers already do well (proves thoroughness)

Open `examples/sample-report.html` to see a real report from an audit of 11 MCP servers (161 findings, 5 critical).

## After the report

Say "fix it" and the plugin applies fixes — with your confirmation:

**Auto-fixable** — .gitignore, chmod 600, path validation, URL validation, error sanitization, asyncio.to_thread() wrappers, dependency pinning. Show → confirm → done.

**Requires your decision** — credential rotation (you need to regenerate keys), OAuth revoke, OS Keychain migration, PII redaction policy. The plugin explains the tradeoff and lets you decide.

**Can't fix automatically** — pip/npm-installed packages (fork instead), built-in Anthropic servers (report to Anthropic), architecture redesigns (provides a plan).

## How it compares

| | mcp-scan (Snyk) | Cisco MCP Scanner | Promptfoo | **mcp-redteam** |
|---|---|---|---|---|
| GitHub Stars | 2,500 | 956 | 6,000 (all) | New |
| Approach | Static description scan | YARA + LLM-as-judge | Red team framework | **Active red-teaming** |
| Reads source code | No (CLI) | Python only | No | **Yes -- all languages** |
| Active probing | No | No | Yes (YAML config) | **Yes -- built-in** |
| Config validation | No | Config discovery | No | **Yes -- Phase 0** |
| Cross-server chains | Basic (toxic flows) | No | No | **Yes -- validated chains** |
| Health + Arch audit | No | No | No | **Yes -- 4 categories** |
| Auto-fix | No | No | No | **Yes** |
| Cloud dependency | Snyk API required | Cisco API (optional) | No | **No -- fully local** |
| Report | Terminal / JSON | JSON | YAML output | **Interactive HTML** |
| Persistent history | No | No | No | **Yes — JSONL audit log, cross-run comparison** |
| Self-tested | Unknown | Unknown | Unknown | **62+ tests, self-security audit, Hypothesis fuzzing** |

### Why not just use mcp-scan?

mcp-scan reads what a server **says about itself** — tool descriptions, parameter schemas. mcp-redteam checks what a server **actually does** — source code analysis + active probing.

A server with clean descriptions but leaky code: mcp-scan passes it. We catch it.

Real findings mcp-scan cannot detect (they live in code, not descriptions):
- Trello API keys in `.env` committed to git
- Instagram session cookies stored in plaintext
- AppleScript injection via unescaped clipboard input
- Google OAuth tokens with permissions `644`

mcp-scan would flag zero of these.

## Architecture

```
/mcp-redteam
  |
  v
Phase 0: Config Validation
  |
  v
Discovery --> locate source code
  |
  v
Phase 1: 1 agent per server (parallel)
  Agent-01    Agent-02    Agent-03    Agent-N
  youtube     trello      instagram   server-N
  health      health      health      health
  arch        arch        arch        arch
  complete    complete    complete    complete
  security    security    security    security
  |           |           |           |
  v           v           v           v
Phase 2: Chain analysis + risk scoring
  |
  v
HTML Report + Fix engine
```

## What's inside

```
mcp-redteam/
├── mcp_redteam/                 # Python CLI package
│   ├── cli.py                   # typer CLI: scan, version
│   ├── models.py                # Pydantic models, 16-rule registry, severity scoring
│   ├── engine/
│   │   ├── semgrep_runner.py    # Run 30 Semgrep rules, map to Finding model
│   │   └── config_scanner.py    # Phase 0: 6 deterministic config checks
│   └── formatters/
│       ├── sarif.py             # SARIF 2.1.0 for GitHub Security tab
│       ├── json_fmt.py          # Machine-readable JSON
│       └── terminal.py          # Rich colored terminal output
├── rules/                       # 30 Semgrep YAML rules
│   ├── python/                  # 8 rules: injection, traversal, SSRF, secrets, ...
│   └── javascript/              # 22 patterns: exec, fs, fetch, eval, secrets, ...
├── tests/                       # 62+ tests
│   ├── test_semgrep.py          # Fixture-based: 6 vulnerable detected, 4 benign clean
│   ├── test_self_security.py    # Self-audit: 10 vulns found and fixed in our own code
│   ├── test_stress.py           # 1000/10000 findings, concurrent scans, unicode
│   ├── test_fuzzing.py          # Hypothesis property-based: any input → no crash
│   ├── test_edge_cases.py       # Corrupt JSON, missing files, null bytes, timeouts
│   └── fixtures/                # 8 vulnerable + 4 benign MCP servers
├── .claude-plugin/              # Claude Code plugin manifest
├── CLAUDE.md                    # AI audit instructions + fix strategy
├── skills/mcp-redteam/SKILL.md  # Plugin entry point + persistent audit history
├── docs/
│   ├── attack-playbook.md       # 700 lines — 12 categories, 40+ CVEs
│   ├── best-practices.md        # MCP server security checklist
│   └── reference-server.md      # Secure server templates (Python + Node.js)
└── examples/
    └── sample-report.html       # Real report: 11 servers, 161 findings
```

## Docs

The `docs/` folder is useful independently:

- **[attack-playbook.md](docs/attack-playbook.md)** — protocol attacks, tool poisoning, input fuzzing, credential theft, exfiltration chains. Every test case has a payload.
- **[best-practices.md](docs/best-practices.md)** — 10 golden rules, signal handling, HTTP client patterns, path/URL validation, error sanitization, pre-release checklist.
- **[reference-server.md](docs/reference-server.md)** — copy-paste server templates with security controls built in. Python (Raw SDK + FastMCP) and Node.js.

## Audit History

Each audit saves a compact JSONL log to `~/Desktop/redteam-results/`. On the next run, mcp-redteam reads previous results and compares:

- **confirmed** — found again, higher confidence
- **new** — first time seeing this
- **fixed** — was in previous audit, now gone

This turns LLM non-determinism into an advantage: each run is a new perspective, the intersection is ground truth.

## Limitations

- Plugin requires Claude Code with connected MCP servers
- CLI requires semgrep for code analysis (graceful skip if not installed)
- Destructive tests (file deletion, data modification) are intentionally skipped
- Source code analysis works for local servers; pip/npm packages may have limited access
- Plugin report quality scales with model capability — Opus produces deeper analysis than Haiku
- Tool poisoning detection is static (description analysis), not runtime monitoring

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
