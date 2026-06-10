# Security Policy

## Reporting Vulnerabilities

If you find a security vulnerability in mcp-redteam, please report it responsibly:

**Email:** m0rvayne@proton.me
**Subject:** `[SECURITY] mcp-redteam: <brief description>`

Please include:
- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Suggested fix (if any)

We will acknowledge within 48 hours and provide a fix timeline within 7 days.

## Self-Security

mcp-redteam audits its own code for vulnerabilities. See `tests/test_self_security.py` for documented findings and fixes.

Known accepted risks are documented in the test file with justification.

## Scope

This policy covers the mcp-redteam Python package and Semgrep rules. It does not cover:
- MCP servers being audited (those are the target, not our code)
- Third-party dependencies (report to their maintainers)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |
