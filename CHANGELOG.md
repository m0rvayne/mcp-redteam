# Changelog

All notable changes to mcp-redteam are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
