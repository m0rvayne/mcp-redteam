# Changelog

All notable changes to mcp-redteam are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.2] - 2026-09-08

### Fixed
- **Packaging: installed wheel found zero code issues.** Rules shipped via `shared-data`
  (installed to `<sys.prefix>/mcp_redteam/rules`) while `get_rules_dir()` looked in
  `<site-packages>/rules`. `run_semgrep()` hit `rules_dir.exists() == False` and returned
  `[]` silently, so every `pip install redteam-mcp` scan — including the GitHub Action —
  reported 0 code findings. Verified on the vulnerable fixtures: 0 before, 72 after.
  Rules are now force-included inside the package, `get_rules_dir()` tries three
  package-anchored candidates (never CWD, VULN-03 preserved), and a missing rules
  directory is now a loud error instead of a silent empty result.
- **GitHub Action: `--fail-on` never failed the build.** The scan step ended in `|| true`,
  discarding the exit code the flag exists to produce. The exit code is now recorded and
  enforced in a separate step that runs after the SARIF upload.
- **Version drift.** `plugin.json` reported 0.3.0 and the SKILL.md banner shown to every
  plugin user reported v0.1.0, against a 0.5.1 package. All version strings are synced and
  now guarded by tests.
- **README overstated the 106-server scan.** Claimed 7 RCE where the research doc
  (`docs/research/scan-106-servers.md`) reports 4 confirmed after manual review — two
  downgraded to by-design risk, one retracted. README and all launch materials corrected.
- **Config scan leaked unrelated findings.** The `$HOME` sweep for stray `.mcp.json` files
  fed the credential, supply-chain, and dangerous-settings checks, so scanning one project
  reported secrets from another. The sweep now feeds scope-conflict detection only.
- **LLM analyzer used a stale model and a rejected parameter.** Default model is now
  `claude-opus-5` (override with `MCP_REDTEAM_MODEL`); `temperature` is no longer sent, as
  current models reject sampling parameters. `max_tokens` raised 4000 → 16000 so a long
  findings array cannot truncate into unparseable JSON and vanish.
- `smithery.yaml` advertised `fail-on: medium|low`, which the CLI silently ignores.
- **MRT003 (SSRF) false positive, found by dogfooding.** The generic `$CLIENT.get($URL, ...)`
  sink matched any `.get()` on any object, so a plain `dict.get("key")` inside a function that
  happened to take a `url` parameter was reported as SSRF — a very common shape in MCP servers.
  The generic sinks now require an HTTP-client-looking receiver and reject literal arguments.
  Removed 2 false positives from this project's own `cli.py`; the vulnerable SSRF fixture is
  still detected. New benign fixture `url_param_dict_get.py` locks the regression.

### Added
- **MRT016 (Rug Pull Risk) is now implemented.** It was in `RULE_REGISTRY` but nothing ever
  emitted it. `scan-remote` baselines tool-description hashes and flags any description that
  changed since the last run. Digests only — descriptions are never written to the baseline.
- `tests/test_packaging.py` — builds a wheel and asserts the rules ship where the runtime
  looks. This is the class of bug unit tests cannot see, since they pass `rules_dir` directly.
- `tests/test_version_consistency.py` — pins all five version declarations together.
- `build` added to the `dev` extra. Without it `test_packaging.py` skipped in CI — the guard
  against the packaging regression would not have run on the release path.
- Tests for config-scan scoping, rug-pull detection, and LLM request shape.

### Changed
- **Writeup corrected before publication.** `docs/research/scan-106-servers.md` listed both
  disclosure issues as "Open, confirmed"; both are in fact closed as `not_planned` — serena #1569
  the same day it was filed, mcp-use #1718 on 2026-08-23 without a reply. Table now carries dates
  and outcomes. The v0.2.0 `~40%` FP figure is now explicitly scoped to that scan and separated
  from the 15,248 → 90 tuning result on a different corpus.
- Launch material no longer says "99.4% FP reduction", which conflated finding volume with false
  positive rate. It now states the measurement: 15,248 raw findings tuned to 90, all hand-confirmed.
- README links the 106-server writeup, which was previously unreachable from the repo.
- README embeds `assets/demo.gif`, which existed in the repo but was shown nowhere.
- Removed `templates/report-template.html` — byte-identical to `examples/sample-report.html`
  and referenced nowhere.
- `docs/reference-server.md` translated to English, matching the rest of the docs.

### Upgrade note
PyPI still resolves `pip install redteam-mcp` to **1.0.0** (uploaded 2026-06-21), because pip
selects the highest version — not the most recent upload. The 0.5.x rollback never reached
PyPI. Yank 1.0.0 so 0.5.x is served again.

## [0.5.1] - 2026-06-28

### Fixed
- **MRT003 (SSRF):** removed raw dict access sources (`$ARGS.get("url")`) that matched API responses as false positives; narrowed to function parameter sources only; added `response.json()` sanitizers
- **MRT002 (Path traversal):** added multi-level chain sanitizers for `Path.home() / x / y / z` (up to 4 levels), `Path.cwd()`, `os.path.expanduser()`
- **MRT026 (Error handling JS):** removed `mcp-js-missing-error-handling-fn` rule — Semgrep cannot see caller-level try/catch, causing false positives on helper function declarations
- **MRT018 (Signal handlers):** narrowed to `if __name__ == "__main__"` entry points only; added path excludes for test/fixture/cli files

### Changed
- FP rate: 222 → 90 findings on 15 production servers (59% further reduction)
- All 4 fixed rules now show 0 false positives on production servers
- 197 tests passing (was 196)

### Added
- Benign test fixture: `config_paths.py` (chained config paths + API response URLs)

## [0.5.0] - 2026-06-28

### Changed
- Rolled back from v1.0.0 to v0.5.0 — premature stable release without real-world validation
- Development Status: Production/Stable → Beta
- v1.0.0 will require: measured FP rate on production servers, beta tester feedback, validated findings

### Highlights from v0.4.x (consolidated)
- 177 tests across 13 test files (test:code ratio 1.02)
- 32 rules in RULE_REGISTRY (25 Semgrep + 6 config + 1 fallback)
- 55 embedding poisoning patterns across 12 attack categories
- 8/10 self-security vulnerabilities fixed, 1 mitigated, 1 accepted
- 4 output formats: terminal, JSON, SARIF, HTML
- GitHub Action for CI/CD: `uses: m0rvayne/mcp-redteam@v0.5.1`
- Audit history with cross-run comparison
- Quick-scan mode for <30s triage

## [0.4.1] - 2026-06-21

### Added
- GitHub Action for CI/CD integration
- Badge command (`mcp-redteam badge`)
- Demo server for showcasing detections
- CLAUDE.md cleanup with fallback handling
- Awesome-list submission templates

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
