# Security Policy

## Reporting Vulnerabilities

**DO NOT open a public GitHub issue for security vulnerabilities.**

Email: m0rvayne@proton.me
Subject: `[SECURITY] mcp-redteam: <brief description>`

Please include:
- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Suggested fix (if any)

Response time: 48 hours for acknowledgment, 7 days for initial assessment.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.5.x   | Yes       |
| < 0.5   | No        |

## Self-Security Audit

mcp-redteam audits itself. We maintain a self-security test suite in
`tests/test_self_security.py` that documents and tests for every
vulnerability found in our own code.

### Current Status (v0.5.2)

| ID | Status | Description |
|----|--------|-------------|
| VULN-01 | Fixed | Credential value leak in finding evidence -- values now redacted |
| VULN-02 | Fixed | Symlink following in config scanner -- `is_symlink()` check added |
| VULN-03 | Fixed | CWD rules directory substitution -- CWD fallback removed |
| VULN-04 | Fixed | Unlimited file read in config parsing -- 10MB cap on `_try_load` and `_raw_text` |
| VULN-05 | Fixed | File counting DoS via rglob -- excludes `.venv`/`node_modules`, caps at 10000 |
| VULN-06 | Fixed | Username leak in SARIF paths -- paths made relative to scan target |
| VULN-07 | Mitigated | XSS in findings -- SARIF and HTML formatters escape all fields |
| VULN-08 | Fixed | Path canonicalization in CLI -- `path.resolve()` added |
| VULN-09 | Fixed | Unbounded find subprocess results -- capped at 100 |
| VULN-10 | Accepted | Floor-pinned dependencies (`>=`, no upper bound) -- no known critical CVEs |

## Scanning Ourselves

`mcp-redteam scan .` on this repository, with the current rules:

```
41 findings — 2 CRITICAL, 3 HIGH, 7 MEDIUM, 29 INFO
```

**All 12 findings above INFO are in `assets/demo-server/server.py`**, an
intentionally vulnerable MCP server that exists to demonstrate detection. If
they ever stop being reported, the scanner has regressed. Nothing in the
product code is rated above INFO.

Reproduce it yourself:

```bash
pip install semgrep
mcp-redteam scan . --no-llm --no-config
```

### What the INFO findings are

They are reported rather than suppressed, because suppression hides the ones
that later turn out to matter:

| Finding | Why it stays INFO |
|---|---|
| MRT002 in `audit_history`, `config_scanner`, the formatters | Writing to a path the user passed on the command line. Off the MCP tool surface, and the paths are the user's own. |
| MRT003 in `remote_scanner` | `requests.post(url, ...)` where `url` is the scan target the user explicitly asked to scan. Fetching it is the command's purpose. |
| MRT006 in `research/reproduce.py` | `print()` in a standalone CLI script, which is not an MCP stdio server. |
| MRT021 in `llm/analyzer` | Reading `ANTHROPIC_API_KEY` from the environment — the recommended practice, reported as inventory of what the process holds. |

Three findings were fixed rather than accepted during this triage: the evidence
reader, the tool-surface reader and the LLM source reader each reached a file
open through a parameter with no `resolve()` + containment check — the same
check this scanner asks of every server it audits.

## Scope

The following are **in scope** for security reports:

- Path traversal in scan targets
- Credential leakage in output formats (SARIF, JSON, HTML, terminal)
- XSS in HTML reports
- DoS via crafted input (configs, source files, rule files)
- Supply chain attacks on bundled Semgrep rules
- Command injection in subprocess calls

The following are **out of scope**:

- LLM hallucinations (non-deterministic by design)
- Embedding model false positives/negatives
- Semgrep rule bypasses (report upstream to [Semgrep](https://github.com/semgrep/semgrep))
- Vulnerabilities in scanned MCP servers (report to the server maintainer)

## Responsible Disclosure

We practice responsible disclosure. If you find a vulnerability in an MCP
server using mcp-redteam, please contact the server maintainer directly
before publishing.
