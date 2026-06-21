# Changelog

All notable changes to mcp-redteam are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-06-21

### Added
- Audit history: JSONL baseline storage with cross-run comparison (new/confirmed/fixed)
- Quick-scan mode: `--quick` for config-only scan, CRITICAL+HIGH findings only
- HTML report formatter: `--format html`, self-contained dark terminal style
- 12 JS/TS test fixtures for all 11 JavaScript Semgrep rules
- Embedding patterns: 17 to 55 across 12 attack categories
- LLM description extraction from source code (FastMCP, dict literals, JS server.tool)
- Configurable LLM model via `MCP_REDTEAM_MODEL` env var
- Remote scanner rules: MRT029-031 (over-privileged, dangerous params, no TLS)
- MRT000 fallback rule for unknown Semgrep findings
- CI version matrix: Python 3.10-3.13
- Optional deps: `[embedding]`, `[all]`
- 52 new tests (total: 139 passing)

### Migration from v0.3.0
- Audit history enabled by default — baselines stored in `~/.mcp-redteam/baselines/`
- New CLI flags: `--quick` / `-q`, `--format html`
- No breaking changes to existing scan behavior

### Fixed
- Rule ID collision: MRT018-020 remapped to MRT029-031
- SARIF evidence HTML escaping (complete XSS prevention)
- SARIF path leak: fallback uses basename() (VULN-06)
- README: removed false "audit history working" claim, clarified LLM cloud dependency
- Self-security tests: hardcoded paths replaced with Path(__file__)
- Semgrep fallback mapping: 15 new keyword mappings for MRT018-028
- CLI output deduplication
- Embedding model caching

## [0.3.0] - 2026-06-13

### Added
- 25 Semgrep rules (14 Python + 11 JS/TS)
- Remote scanner with OAuth 2.1 DCR + PKCE
- Embedding-based tool poisoning detector (MiniLM-L6-v2)
- Self-security audit: 10 vulnerabilities audited, 5 fixed

## [0.2.0] - 2026-06-11

### Added
- Python CLI (`mcp-redteam scan`) with typer
- 30 Semgrep detection patterns (14 modules: 8 Python + 6 JS/TS)
- Config scanner: dead servers, scope conflicts, credential exposure, supply chain, CVE checks
- SARIF 2.1.0 output for GitHub Security tab
- JSON output for CI/CD integration
- Terminal output with rich colored tables
- LLM behavioral analyzer (Anthropic SDK, optional)
- Persistent audit history (`~/Desktop/redteam-results/` JSONL)
- 75+ tests: unit, security self-audit, stress, edge cases, Hypothesis fuzzing
- Self-security audit: 10 vulnerabilities found and fixed in own code
- GitHub Actions: test + self-audit workflows
- GitHub Action for `uses: m0rvayne/mcp-redteam@v1`
- Pydantic models with 16-rule registry (MRT001-MRT016)
- Attack playbook: 18 categories, 48+ CVEs

### Fixed
- Credential value leak in SARIF evidence (redacted)
- Symlink following in config scanner
- CWD rules directory substitution attack
- File size limit for config parsing (10MB cap)
- CLI path canonicalization

## [0.1.0] - 2026-06-07

### Added
- Claude Code plugin with SKILL.md entry point
- CLAUDE.md audit instructions (3-phase architecture)
- Attack playbook (12 categories, 40+ CVEs)
- Best practices guide
- Reference server templates
- Interactive HTML report (terminal style)
- Safe Mode / Active Mode
- Language selection (EN/RU/UA)
