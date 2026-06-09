# v2 Execution Plan — Day-by-Day

> Created: 2026-06-10
> Status: READY TO EXECUTE
> Architect approval: received
> Start: 2026-06-11

---

## Pre-work (done tonight)

- [x] Architecture proposal approved
- [x] Critics synthesis completed
- [x] Research: Semgrep rules, AST, SARIF, MCPTox, Pipelock, MCPSpy
- [x] Sub-agents prepared (see below)

---

## Day 1: Project Scaffold + Models + CLI

### What we build
- Python project structure with pyproject.toml
- Pydantic models (Finding, Severity, Rule, ScanResult)
- typer CLI with `scan` command
- Basic terminal output (rich)

### Sub-agents needed

**Agent A: Scaffold builder**
- Create `pyproject.toml` (deps: typer, rich, pydantic, anthropic, instructor)
- Create package structure `mcp_redteam/`
- Create `cli.py`, `models.py`, `__init__.py`
- Working `mcp-redteam scan ./path` that prints "scanning..."

**Agent B: Models designer**
- `models.py` with Pydantic:
  - `Severity` enum (CRITICAL, HIGH, MEDIUM, LOW, INFO)
  - `FindingCategory` enum (security, health, architecture, completeness, config)
  - `Finding` model (id, title, severity, category, evidence, location, fix, confidence)
  - `ScanResult` model (findings, metadata, timing)
  - `Rule` model (id, name, description, severity, pattern)
  - Severity scoring as Python function (CRITICAL=25, HIGH=15, MEDIUM=5, LOW=1)

**No other agents needed.** Day 1 is small, focused, testable.

### Definition of Done
- `pip install -e .` works
- `mcp-redteam --help` shows commands
- `mcp-redteam scan ./some-path` runs without error
- Models importable: `from mcp_redteam.models import Finding, Severity`

---

## Day 2: Semgrep Rules (MCP-specific)

### What we build
- 10-15 YAML rules for MCP security patterns
- Semgrep runner that executes rules and maps to Finding model
- Rules work on Python AND TypeScript

### Sub-agents needed

**Agent C: Semgrep rule writer (Python)**
Write YAML rules for Python MCP servers:
1. `mcp-shell-injection.yaml` — taint: tool arg → subprocess(shell=True)
2. `mcp-path-traversal.yaml` — taint: tool arg → open()/Path() without realpath
3. `mcp-ssrf.yaml` — taint: tool arg → httpx.get()/requests.get() without URL validation
4. `mcp-eval-injection.yaml` — taint: tool arg → eval()/exec()
5. `mcp-credential-in-code.yaml` — hardcoded API keys, tokens (regex patterns)
6. `mcp-stdout-pollution.yaml` — print() in server context
7. `mcp-missing-error-handling.yaml` — tool function without try/except
8. `mcp-credential-in-response.yaml` — return dict with "api_key"/"password"/"token"

**Agent D: Semgrep rule writer (JavaScript/TypeScript)**
Same patterns for JS/TS MCP servers:
1. `mcp-js-command-injection.yaml` — exec/execSync with template literal
2. `mcp-js-path-traversal.yaml` — fs.readFile with non-literal path
3. `mcp-js-ssrf.yaml` — fetch/axios with user-controlled URL
4. `mcp-js-eval.yaml` — eval() with non-literal
5. `mcp-js-stdout.yaml` — console.log in MCP handler
6. `mcp-js-secrets.yaml` — hardcoded keys

**Agent E: Semgrep runner**
- `mcp_redteam/engine/semgrep_runner.py`
- Check if semgrep installed, graceful skip if not
- Run semgrep with our rules dir, parse JSON output
- Map semgrep results to Finding model
- Handle: multiple files, multiple rules, dedup

### Definition of Done
- `mcp-redteam scan ./test-server` finds shell injection in test fixture
- 10+ rules pass `semgrep --validate`
- Runner maps findings to Pydantic model correctly

---

## Day 3: Config Scanner (Phase 0 in code)

### What we build
- Port Phase 0 from CLAUDE.md prompts to Python code
- Deterministic config checks, no LLM

### Sub-agents needed

**Agent F: Config scanner implementation**
- `mcp_redteam/engine/config_scanner.py`
- Parse: `~/.claude.json`, `.mcp.json`, `claude_desktop_config.json`
- Check: dead servers (run `claude mcp list`, parse output)
- Check: scope conflicts (same server name in multiple config files)
- Check: plaintext secrets in configs (regex patterns)
- Check: unpinned npx/uvx (regex on command args)
- Check: `enableAllProjectMcpServers` (CVE-2026-21852)
- Check: `ANTHROPIC_BASE_URL` override (CVE-2025-59536)
- Check: orphaned .mcp.json files (find + check if project exists)
- All findings as Finding model with proper severity

### Definition of Done
- Config scanner finds unpinned npx in test config
- Config scanner finds plaintext secret in test config
- All findings are proper Pydantic Finding objects

---

## Day 4: SARIF + JSON Formatters

### Sub-agents needed

**Agent G: SARIF formatter**
- `mcp_redteam/formatters/sarif.py`
- Generate valid SARIF 2.1.0 JSON from list of Finding
- Rule IDs: MRT001 (shell injection), MRT002 (path traversal), etc.
- Required fields: tool.driver with rules, results with locations
- Test: output accepted by `sarif-tools validate`

**Agent H: JSON formatter**
- `mcp_redteam/formatters/json_fmt.py`
- Simple JSON output of ScanResult
- Machine-readable, parseable by Claude Code Read tool

### Definition of Done
- `mcp-redteam scan . --format sarif` produces valid SARIF
- `mcp-redteam scan . --format json` produces valid JSON
- SARIF can be uploaded to GitHub Security tab

---

## Day 5: Test Fixtures + Regression Tests

### Sub-agents needed

**Agent I: Fixture builder**
- `tests/fixtures/vulnerable/` — 8 known-vulnerable MCP servers (Python)
  - shell_injection.py, path_traversal.py, ssrf.py, secrets.py
  - stdout_pollution.py, missing_error_handling.py, eval_injection.py
  - tool_poisoning.json (description with hidden instructions)
- `tests/fixtures/benign/` — 4 clean servers
  - calculator.py, weather_api.py, file_reader_safe.py, echo_server.py
- Each fixture has metadata: expected_findings list

**Agent J: Test writer**
- `tests/test_semgrep.py` — parametrize over fixtures, assert findings
- `tests/test_config_scanner.py` — mock configs, assert detections
- `tests/test_formatters.py` — SARIF and JSON output validity
- `tests/test_models.py` — severity scoring, model validation

### Definition of Done
- `pytest tests/` passes
- All vulnerable fixtures detected
- All benign fixtures produce zero critical/high
- <5 second total test time

---

## Day 6: LLM Behavioral Layer

### Sub-agents needed

**Agent K: LLM analyzer**
- `mcp_redteam/engine/llm_analyzer.py`
- Uses Anthropic SDK + Instructor for structured output
- Three analysis modes:
  1. `behavioral_mismatch` — description vs code comparison
  2. `rug_pull_check` — hash tool descriptions, compare with stored baseline
  3. `chain_analysis` — cross-server attack path validation
- Logprobs-based confidence if available, fallback to self-reported confidence
- Structured output via Pydantic (Finding model)
- Respects `--no-llm` flag (skip entirely)

**Agent L: Prompts migrator**
- `mcp_redteam/llm/prompts/` directory
- Migrate analysis prompts from CLAUDE.md to structured prompt files
- Each prompt = focused task, not 500-line mega-prompt
- Prompts reference Pydantic schema for output format

### Definition of Done
- `mcp-redteam scan . --no-llm` works (skips LLM, deterministic only)
- `mcp-redteam scan .` adds LLM findings on top of Semgrep findings
- LLM findings have confidence score
- Behavioral mismatch detected on test fixture

---

## Day 7: MCPTox Validation + Metrics

### Sub-agents needed

**Agent M: MCPTox benchmark runner**
- Download/setup MCPTox dataset (353 tools, 1312 test cases)
- Run mcp-redteam against dataset
- Compute TPR, FPR, per-category detection rate
- Compare with published baselines (mcp-sec-audit: 74.7%)
- Generate validation report

### Definition of Done
- Published TPR/FPR numbers on MCPTox
- Comparison with at least one competitor's published metrics
- Numbers in README

---

## Day 8: Claude Code Skill Update

### Sub-agents needed

**Agent N: Skill wrapper rewrite**
- Update SKILL.md: run CLI via Bash, read JSON output via Read tool
- Keep AskUserQuestion for mode/language
- Keep pixel art banner
- Keep interactive HTML report for deep audit mode
- Test: `/mcp-redteam` in Claude Code triggers CLI scan

### Definition of Done
- `/mcp-redteam` works in Claude Code
- Findings displayed from JSON (not stdout)
- `--no-llm` mode accessible via `/mcp-redteam fast`

---

## Day 9: Distribution

### Sub-agents needed

**Agent O: PyPI + GitHub Action**
- Finalize pyproject.toml for PyPI publish
- `action.yml` for GitHub Action
- Dockerfile for Docker distribution
- Test: `pip install mcp-redteam && mcp-redteam scan .`

### Definition of Done
- Package on PyPI
- `uses: m0rvayne/mcp-redteam@v1` works
- Docker image builds and runs

---

## Day 10: README + Launch

### Sub-agents needed

**Agent P: README rewrite**
- Update README for v2: real CLI, deterministic engine, SARIF, MCPTox metrics
- Comparison table with published numbers
- Quick start: `pip install mcp-redteam && mcp-redteam scan .`
- Community rules section (contributing Semgrep YAML)

### Launch checklist
- [ ] README updated with v2 features
- [ ] MCPTox metrics published
- [ ] PyPI package live
- [ ] GitHub Action working
- [ ] Re-submit to awesome lists: "now with deterministic engine + SARIF"
- [ ] Blog post draft: "What we found scanning 353 real MCP servers"
- [ ] HN Show HN post prepared

---

## Agent Registry (quick reference)

| Agent | Task | Day | Parallelizable |
|-------|------|-----|----------------|
| A | Project scaffold | 1 | Yes (with B) |
| B | Pydantic models | 1 | Yes (with A) |
| C | Semgrep rules Python | 2 | Yes (with D, E) |
| D | Semgrep rules JS/TS | 2 | Yes (with C, E) |
| E | Semgrep runner | 2 | Yes (with C, D) |
| F | Config scanner | 3 | Solo |
| G | SARIF formatter | 4 | Yes (with H) |
| H | JSON formatter | 4 | Yes (with G) |
| I | Test fixtures | 5 | Yes (with J) |
| J | Test writer | 5 | Yes (with I) |
| K | LLM analyzer | 6 | Yes (with L) |
| L | Prompts migrator | 6 | Yes (with K) |
| M | MCPTox benchmark | 7 | Solo |
| N | Skill wrapper | 8 | Solo |
| O | PyPI + GH Action | 9 | Solo |
| P | README rewrite | 10 | Solo |

**Max parallelism per day: 3 agents** (Days 2 and 5)

---

## Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| Semgrep not installed on user machine | Graceful skip + message "install semgrep for deterministic checks" |
| Anthropic SDK logprobs unavailable | Fallback: structured output with confidence field |
| MCPTox dataset format changed | Pin specific commit/version of dataset |
| 10 days too tight | Days 7-10 can slide to week 3 without blocking core functionality |
| Semgrep rules have false positives | MCPTox benchmark catches this; iterate rules |

---

## What's ready when you wake up

1. This execution plan (you're reading it)
2. v2-architecture-proposal.md (architect approved)
3. v2-critics-synthesis.md (what we changed and why)
4. All research saved in agent outputs (deterministic analysis, testing, CLI, playbook gaps, critics)
5. Agent prompts pre-written above — just launch them

Tomorrow morning: start Day 1. Two agents in parallel (scaffold + models). Should take 1 session.
