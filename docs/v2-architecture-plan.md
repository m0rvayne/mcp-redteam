# mcp-redteam v2 Architecture Plan

> Created: 2026-06-10
> Based on: architect review feedback + 4-block research (deterministic analysis, testing/reproducibility, CLI architecture, playbook gaps)
> Status: PLAN — not yet implemented

---

## Problem Statement

Architect feedback (verbatim): "This is not software. It's a very well-written prompt framework masquerading as a tool."

Core issues:
1. Zero lines of executable code — everything is markdown prompts
2. Reproducibility = 0 — LLM inference is non-deterministic
3. No tests, no CI, no validation
4. Vendor lock-in — 100% Claude Code
5. No programmatic API
6. No machine-readable output (SARIF/JSON)
7. Scalability limited by LLM context window

---

## Target Architecture

```
mcp-redteam CLI (Python + typer)
├── Deterministic Engine (no LLM, works in CI)
│   ├── Layer 1: Regex — credentials, obvious patterns (0 deps, ~25 lines)
│   ├── Layer 2: AST — Python ast + babel/ts-morph for JS/TS (~100 lines per lang)
│   ├── Layer 3: Semgrep — taint tracking with YAML rules (optional dep)
│   └── Layer 4: Bandit — 300+ Python security checks (optional dep)
├── LLM Adapter (optional, for deep analysis)
│   ├── Claude API (anthropic SDK)
│   ├── OpenAI API
│   ├── Ollama (local, free)
│   └── LiteLLM (unified interface)
├── Config Scanner (deterministic)
│   ├── Connection health (claude mcp list)
│   ├── Scope conflicts (multi-config detection)
│   ├── Credential exposure in configs
│   ├── Supply chain (unpinned npx/uvx)
│   └── CVE checks (CVE-2025-59536, CVE-2026-21852)
├── Output Formatters
│   ├── Terminal (rich tables)
│   ├── JSON
│   ├── SARIF 2.1.0 (GitHub Security tab)
│   └── HTML (current interactive report)
└── Test Suite
    ├── Deterministic regression tests (pytest)
    ├── DVMCP ground truth fixtures
    ├── Benign server fixtures (FP testing)
    └── LLM consensus tests (3 runs, majority vote)
```

### Distribution

```
Claude Code Plugin ──→ thin wrapper over CLI
VS Code / Cursor   ──→ thin wrapper over CLI
CI/CD Pipeline     ──→ mcp-redteam scan --no-llm --format sarif
Docker             ──→ docker run ghcr.io/m0rvayne/mcp-redteam scan .
PyPI               ──→ pip install mcp-redteam / uv tool install mcp-redteam
GitHub Action      ──→ uses: m0rvayne/mcp-redteam@v1
```

---

## Implementation Plan

### Phase 1: Deterministic Core (week 1-2)

**Goal:** Real executable code. Deterministic, reproducible, testable.

#### 1.1 Project scaffolding
- [ ] `pyproject.toml` with typer, rich, pydantic
- [ ] `mcp_redteam/cli.py` — typer app with `scan` command
- [ ] `mcp_redteam/models.py` — Finding, Severity, Rule dataclasses (Pydantic)
- [ ] Basic CLI: `mcp-redteam scan ./path --format terminal`

#### 1.2 Regex detectors (Layer 1, zero deps)
- [ ] `detectors/secrets.py` — hardcoded API keys, tokens, passwords (~15 patterns)
  - OpenAI `sk-`, GitHub `ghp_`, AWS `AKIA`, generic `api_key=`, `password=`
  - Exclude: `os.environ`, `getenv`, test/example files
  - ~25 lines
- [ ] `detectors/obvious_patterns.py` — `eval()`, `exec()`, `shell=True` without shlex
  - Simple regex on source, not AST
  - ~15 lines

#### 1.3 AST detectors (Layer 2)
- [ ] `detectors/python_ast.py` — Python ast module, zero deps
  - `MCPSecurityVisitor` class (~60 lines):
    - `shell_injection`: subprocess.run(shell=True) with non-literal arg
    - `stdout_pollution`: print() in MCP tool functions
    - `missing_error_handling`: tool functions without try/except
    - `missing_signal_handler`: server without SIGTERM/SIGINT handlers
    - `path_traversal_risk`: open() with non-literal path, no realpath
- [ ] `detectors/js_ast.py` — @babel/parser or ts-morph (~50 lines):
    - `command_injection`: exec/execSync with template literal or concatenation
    - `stdout_pollution`: console.log in MCP handlers
    - `non_literal_fs`: fs.readFile with variable path

#### 1.4 Config scanner (deterministic)
- [ ] `detectors/config_health.py` — port Phase 0 from prompts to code:
  - Parse `~/.claude.json`, `.mcp.json`, `claude_desktop_config.json`
  - Detect: dead servers, scope conflicts, duplicate configs
  - Detect: plaintext secrets in config files (grep patterns)
  - Detect: unpinned npx/uvx (regex on command args)
  - Detect: `enableAllProjectMcpServers` (CVE-2026-21852)
  - Detect: `ANTHROPIC_BASE_URL` override (CVE-2025-59536)

#### 1.5 SARIF formatter
- [ ] `formatters/sarif.py` — generate SARIF 2.1.0 JSON
  - Required fields: tool.driver.name/version/rules, results with locations
  - Each detector rule gets an ID: MRT001 (shell injection), MRT002 (secrets), etc.
  - ~80 lines

#### 1.6 Terminal formatter
- [ ] `formatters/terminal.py` — rich tables output
  - Colored severity (red CRITICAL, yellow HIGH)
  - Per-file grouping
  - Summary line

### Phase 2: Testing & CI (week 2-3)

**Goal:** Provable quality. Regression tests. CI pipeline.

#### 2.1 Test fixtures
- [ ] `tests/fixtures/vulnerable/` — known-vulnerable MCP servers:
  - `shell_injection.py` — subprocess.run(shell=True, cmd=args["cmd"])
  - `path_traversal.py` — open(args["path"]) without validation
  - `ssrf.py` — httpx.get(args["url"]) without allowlist
  - `secrets_in_code.py` — API_KEY = "sk-..."
  - `stdout_pollution.py` — print() in tool handler
  - `missing_error_handling.py` — tool without try/except
  - `tool_poisoning.json` — tool description with hidden instructions
  - Each fixture has `expected_findings` metadata
- [ ] `tests/fixtures/benign/` — clean servers (zero findings expected):
  - `calculator.py` — safe arithmetic tool
  - `weather_api.py` — proper URL validation, error handling
  - `file_reader.py` — realpath + startswith check

#### 2.2 Regression tests
- [ ] `tests/test_deterministic.py`:
  - Parametrize over vulnerable fixtures → assert expected findings found
  - Parametrize over benign fixtures → assert zero critical/high findings
  - These tests are 100% deterministic, run in <1 second
- [ ] `tests/test_config_scanner.py`:
  - Mock config files with known issues
  - Assert scope conflicts, dead servers, secrets detected

#### 2.3 CI pipeline
- [ ] `.github/workflows/test.yml`:
  - Run `pytest tests/test_deterministic.py` on every push/PR
  - Upload SARIF to GitHub Security tab
  - Fail on test regression
- [ ] `.github/workflows/self-audit.yml`:
  - Run mcp-redteam on its own codebase
  - Upload results as artifact

#### 2.4 Metrics
- [ ] Track: True Positive Rate, False Positive Rate per detector
- [ ] Target: TPR > 90% on fixtures, FPR < 10% on benign

### Phase 3: LLM Hybrid Layer (week 3-4)

**Goal:** Add LLM for what deterministic can't catch. Keep it optional.

#### 3.1 LLM adapter
- [ ] `llm/adapter.py` — LiteLLM wrapper
  - `analyze(code_snippet, provider, model) -> str`
  - Supports: claude, openai, ollama (local)
  - Structured output via Pydantic schema
- [ ] `llm/prompts/` — analysis prompts (migrate from current CLAUDE.md)
  - `semantic_analysis.md` — tool poisoning, behavioral mismatch
  - `chain_analysis.md` — cross-server attack chains
  - `verify_finding.md` — confirm/reject MEDIUM deterministic findings

#### 3.2 Hybrid analyzer
- [ ] `engine/hybrid.py`:
  ```
  Deterministic findings (HIGH confidence) → report as-is
  Deterministic findings (MEDIUM) → LLM confirms/rejects
  No deterministic finding → LLM deep analysis (catches logic bugs)
  ```
- [ ] Consensus mode: run LLM N times (default 3), take majority vote
  - Finding found in 2/3 runs = confirmed
  - Finding found in 1/3 = noise, excluded

#### 3.3 CLI flags
- [ ] `--no-llm` — deterministic only (CI mode, fast, reproducible)
- [ ] `--llm-provider claude|openai|ollama` — which LLM to use
- [ ] `--llm-model <model-id>` — specific model
- [ ] `--consensus <N>` — number of LLM runs for voting (default 3)

### Phase 4: Semgrep Rules (week 4-5)

**Goal:** Taint tracking for data flow analysis.

#### 4.1 Semgrep rule files
- [ ] `rules/mcp-shell-injection.yaml` — taint: tool arg → subprocess(shell=True)
- [ ] `rules/mcp-path-traversal.yaml` — taint: tool arg → open() without realpath
- [ ] `rules/mcp-ssrf.yaml` — taint: tool arg → httpx.get() without URL validation
- [ ] `rules/mcp-credential-in-response.yaml` — return {..., "api_key": ...}
- [ ] `rules/mcp-eval-injection.yaml` — taint: tool arg → eval()

#### 4.2 Integration
- [ ] `detectors/semgrep_runner.py`:
  - Check if semgrep installed, skip gracefully if not
  - Run semgrep with custom rules, parse JSON output
  - Map semgrep findings to mcp-redteam Finding model

### Phase 5: Claude Code Plugin Wrapper (week 5)

**Goal:** Keep current UX, but backed by real CLI.

- [ ] Update `SKILL.md`: instead of inline prompts, run `!mcp-redteam scan`
- [ ] Update `CLAUDE.md`: reference CLI for deterministic checks
- [ ] Keep LLM-driven analysis as `--llm-provider claude` mode
- [ ] Keep interactive HTML report generation
- [ ] Keep AskUserQuestion for mode/language selection

### Phase 6: Distribution (week 5-6)

- [ ] PyPI: `pip install mcp-redteam`
- [ ] GitHub Action: `uses: m0rvayne/mcp-redteam@v1`
- [ ] Docker: `ghcr.io/m0rvayne/mcp-redteam`
- [ ] Re-submit to awesome lists with "now with deterministic engine"

---

## Playbook Gaps to Fix

Based on architect review. 6 missing attack categories:

### Gap 1: OAuth 2.1 / Dynamic Client Registration
- DCR abuse: register malicious client with attacker redirect_uri
- Token endpoint SSRF via redirect_uri / client_manifest_uri / logo_uri / jwks_uri
- PKCE downgrade: AS accepts code without code_challenge
- Authorization server impersonation via discovery endpoint
- Key CVE: CVE-2025-6514 (CVSS 9.6) — mcp-remote RCE via authorization_endpoint injection
- Add to playbook: section "OAuth 2.1 Attack Surface" with payloads and detection

### Gap 2: Streamable HTTP Transport
- Session hijacking via predictable session IDs (CVE-2025-6515: pointer as ID)
- DNS rebinding: CVE-2026-42559 (Rust SDK), CVE-2025-64443 (Docker), CVE-2025-66414 (TS SDK)
- HTTP request smuggling through reverse proxy (CL.TE / TE.CL)
- Reconnection race conditions (two clients on same session)
- Add to playbook: section "Streamable HTTP Transport Attacks"

### Gap 3: Multi-Tenant / Shared Hosting
- Tenant ID injection (from query param instead of JWT)
- Context window contamination between tenants
- Resource quota exhaustion (no per-tenant rate limiting)
- Privilege escalation via shared cache without namespace
- Inter-server provenance confusion in LLM context
- Add to playbook: section "Multi-Tenant MCP Attacks"

### Gap 4: Sampling / Roots Capabilities
- Sampling abuse: resource theft (billing drain via maxTokens)
- Sampling abuse: conversation hijacking (hidden prompt injection)
- Sampling abuse: covert tool invocation via LLM completion
- Roots escape: path traversal CVE-2025-53110 (prefix bypass before normalize)
- Roots escape: symlink traversal CVE-2025-53109 (sandbox escape)
- Add to playbook: section "Sampling & Roots Attack Surface"

### Gap 5: Runtime Monitoring & Detection
- Anomaly detection patterns (burst calls, rare tool activation, off-hours usage)
- Mandatory logging fields for forensics
- Incident response playbook for compromised MCP server
- Tools: OpenTelemetry, Datadog MCP rules, ARMO eBPF
- Add to playbook: section "Detection & Response"

### Gap 6: Indirect Prompt Injection via MCP
- Data-in-tool-result injection (malicious instructions in files/emails/DB)
- Chained tool exfiltration (read credentials → send via email tool)
- Confused deputy via user instruction (legit tools, malicious intent)
- Cross-server injection (server X poisons context for server Y)
- Turing Trap: tool description changes post-approval
- Add to playbook: section "Indirect Prompt Injection Chains"

### New CVEs to add to playbook

| CVE | CVSS | Category | Description |
|-----|------|----------|-------------|
| CVE-2025-6514 | 9.6 | OAuth | mcp-remote RCE via authorization_endpoint |
| CVE-2025-6515 | — | HTTP Transport | oatpp-mcp predictable session ID |
| CVE-2026-42559 | 8.8 | HTTP Transport | Rust SDK DNS rebinding |
| CVE-2025-64443 | High | HTTP Transport | Docker MCP Gateway DNS rebinding |
| CVE-2025-66414 | High | HTTP Transport | TypeScript SDK DNS rebinding default off |
| CVE-2025-53109 | 7.3 | Roots | Filesystem MCP symlink traversal |
| CVE-2025-53110 | 8.4 | Roots | Filesystem MCP path prefix bypass |
| CVE-2025-49596 | Critical | HTTP Transport | MCP Inspector browser RCE |

---

## Technology Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | Python + typer | All competitors use Python; LiteLLM, tree-sitter, YARA native |
| Package manager | uv | Isolated install, no system conflicts |
| LLM integration | LiteLLM | One interface for Claude/OpenAI/Ollama |
| AST (Python) | stdlib `ast` | Zero deps, covers 80% of Python MCP servers |
| AST (JS/TS) | @babel/parser or tree-sitter | Called via subprocess from Python |
| Taint tracking | Semgrep (optional) | Best open-source taint engine, YAML rules |
| Output | SARIF 2.1.0 | GitHub Security tab integration standard |
| Testing | pytest + parametrize | Fixtures-based regression, fast |
| CI | GitHub Actions | Standard, free for open source |
| Benchmark | DVMCP + MCPSecBench | Ground truth for TPR/FPR measurement |

---

## Success Criteria

Before declaring v2 "production-ready":

- [ ] `mcp-redteam scan --no-llm` finds 100% of fixtures/vulnerable/ issues
- [ ] `mcp-redteam scan --no-llm` produces 0 critical/high on fixtures/benign/
- [ ] SARIF output accepted by GitHub Code Scanning
- [ ] `pip install mcp-redteam && mcp-redteam scan .` works from zero
- [ ] CI green on every PR
- [ ] At least 5 deterministic detectors passing regression
- [ ] At least 3 Semgrep taint rules for MCP patterns
- [ ] Playbook updated with all 6 gaps + 8 new CVEs
- [ ] README states: "Deterministic engine + optional LLM analysis"
- [ ] Architect re-review: "This is software"

---

## Order of Work

```
Week 1: scaffolding + models + regex detectors + config scanner
Week 2: AST detectors + SARIF formatter + test fixtures
Week 3: regression tests + CI pipeline + LLM adapter
Week 4: semgrep rules + hybrid analyzer + consensus
Week 5: Claude Code wrapper update + playbook gaps
Week 6: PyPI + GitHub Action + Docker + re-launch
```

Each week produces a shippable increment. No week depends on LLM — deterministic path is always functional.
