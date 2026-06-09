# Roadmap

> Last updated: 2026-06-09
> Based on: competitive analysis of 13 tools, OWASP MCP Top 10, MCP-DPT taxonomy (49 attack classes), 75-point audit checklist, 6 academic papers, real-world CVE data.

---

## Positioning

**What we are:** The only MCP security tool that reads source code + actively probes servers from inside Claude Code. Red team depth, not scanner breadth.

**UVP:** "Scanners read descriptions. We break servers."

**Competitive landscape:**

| Tool | Approach | Stars | Weakness we exploit |
|------|----------|-------|---------------------|
| mcp-scan (Snyk) | Static description analysis + cloud API | 2,500 | No source code analysis, no active probing, cloud-dependent |
| Cisco MCP Scanner | YARA + LLM-as-judge | 956 | 78% false positive rate on YARA, no chain analysis |
| Promptfoo | Red team framework (YAML) | 6,000 | Not MCP-specialized, bought by OpenAI, complex setup |
| Proximity | LLM semantic scan | 295 | GPL, no runtime testing, single developer |
| mcp-watch | Pattern matching + rug pull detection | 132 | No LLM-driven analysis, no source code |
| MCP Audit (APIsec) | Config + secret scan + AI-BOM | 280 | No active testing, narrow scope |
| dr-mcp | Config cleanup | 96 | Not a security tool |
| mcpserver-audit (CSA) | LLM-guided prompts | 45 | No automation, results vary by model |

**Our gap:** adoption (0 stars), CI/CD integration, multi-client support, skill scanning.

---

## v0.1.0 (current) — Foundation

- [x] 3-phase architecture: Config Validation + Deep Audit + Chain Analyzer
- [x] Phase 0: config health, scope conflicts, credential exposure, supply chain, orphaned processes
- [x] Phase 1: 4 audit categories (health, architecture, completeness, security)
- [x] Phase 1: source code path analysis (path traversal, SSRF, command injection, credential storage, tool poisoning, type safety)
- [x] Phase 2: cross-server chain analysis with false positive prevention
- [x] Safe Mode (default) + Active Mode (opt-in)
- [x] Interactive HTML report (terminal style)
- [x] Fix strategy (auto-fix / requires decision / cannot fix)
- [x] Language selection (EN/RU/UK)
- [x] Claude Code skill with marketplace install

---

## v0.2.0 — Reliability & Real-World Validation

**Goal:** Make the tool trustworthy. Fix known issues, document real audits, reduce false positives.

### Bug fixes
- [ ] Fix false positive chains (chain validation rules from session 2)
- [ ] Fix report language (timeout on translation — generate directly in target language)
- [ ] Handle Claude Desktop "Source only" servers gracefully

### Validation
- [ ] Run audit on own MCP servers (10+), document every finding
- [ ] Compare findings with mcp-scan output on same servers — show what we catch that they miss
- [ ] Run audit on 5 popular public MCP servers (filesystem, github, slack, postgres, puppeteer)
- [ ] Document false positive rate (target: <10%)

### Quality of life
- [ ] Single-server mode: `/mcp-redteam --server trello`
- [ ] Quick scan mode: security-only (skip health/arch/completeness)
- [ ] `--verbose` flag for debugging agent behavior
- [ ] Better error messages when agent fails (context overflow, server unreachable)

### Deliverable
- [ ] 10+ documented real-world audits with findings
- [ ] Comparison blog post: "mcp-redteam vs mcp-scan: what each catches on the same 10 servers"

---

## v0.3.0 — OWASP MCP Top 10 Coverage

**Goal:** Map every check to OWASP MCP Top 10 (MCP01-MCP10). Become the reference implementation.

### New checks by OWASP category

**MCP01 — Token Mismanagement & Secret Exposure:**
- [ ] Detect hardcoded credentials in source (regex + semantic: API keys, tokens, passwords)
- [ ] Check token expiry logic (short-lived vs long-lived)
- [ ] Detect secrets in tool responses (error handlers leaking tokens)
- [ ] Check credential rotation capability

**MCP02 — Privilege Escalation via Scope Creep:**
- [ ] OAuth scope analysis: minimum privilege check
- [ ] Tool permission matrix: what each tool can actually do vs what it declares
- [ ] Detect `isDestructive` metadata presence/absence on state-mutating tools

**MCP03 — Tool Poisoning:**
- [ ] Tool description analysis: hidden instructions, Unicode tricks (U+E0000 range, zero-width chars)
- [ ] Parameter name analysis: suspicious names (env_details, system_info, context_summary)
- [ ] Cross-server tool shadowing detection (same tool name, different behavior)
- [ ] Tool hash computation + storage for rug pull detection between audits

**MCP04 — Supply Chain:**
- [ ] npm/PyPI package verification: does package exist? Is it the right one?
- [ ] Typosquat detection: compare package name against known-good list
- [ ] Dependency CVE check (integrate with OSV.dev API — read-only, free)
- [ ] Version pinning check (already in Phase 0, extend to source-level)

**MCP05 — Command Injection:**
- [ ] Already covered in Phase 1. Add: AppleScript injection patterns, PowerShell injection
- [ ] shell=True + unsanitized input = CRITICAL (already done, refine detection)

**MCP06 — Intent Flow Subversion (Prompt Injection):**
- [ ] Detect untrusted content markers in tool responses
- [ ] Check if tool responses are length-capped
- [ ] Detect instruction-like patterns in tool output (imperatives, "you must", "ignore previous")

**MCP07 — Insufficient Auth:**
- [ ] Check if server requires credentials on every request
- [ ] Check transport security (TLS, hostname verification)
- [ ] Detect anonymous fallthrough in auth logic

**MCP08 — Lack of Audit & Telemetry:**
- [ ] Check for logging in tool handlers
- [ ] Detect PII in log statements
- [ ] Check for correlation ID propagation

**MCP09 — Shadow MCP Servers:**
- [ ] Already in Phase 0 (orphaned configs). Extend: detect servers not in any allowlist
- [ ] Check for `enableAllProjectMcpServers` (CVE-2026-21852)

**MCP10 — Context Injection & Over-Sharing:**
- [ ] Detect PII in tool responses (emails, phones, names without redaction)
- [ ] Check context isolation between tools

### Report enhancement
- [ ] OWASP MCP Top 10 coverage badge in report header
- [ ] Per-finding OWASP category mapping (e.g., "MCP01: Token in error handler")

### Deliverable
- [ ] README badge: "Covers OWASP MCP Top 10"
- [ ] Mapping document: which checks cover which OWASP categories

---

## v1.0.0 — Production-Ready

**Goal:** Stable, documented, community-ready. This is the version for public launch and marketing.

### Output formats
- [ ] JSON report alongside HTML (machine-readable for CI/CD)
- [ ] SARIF output (GitHub Security tab integration)
- [ ] Markdown summary (for PR comments)

### Baseline & comparison
- [ ] Baseline storage: save audit results locally (JSON)
- [ ] Report diff: compare two audits, show improvements/regressions
- [ ] Tool hash pinning: store tool description hashes, detect changes between audits (rug pull detection)

### Documentation
- [ ] CONTRIBUTING.md with clear contribution guide
- [ ] Architecture docs: how phases work, how to add new checks
- [ ] "Getting Started" guide with screenshots
- [ ] Video demo (screen recording of full audit)

### Distribution
- [ ] Submit to anthropics/claude-plugins-official marketplace
- [ ] npm package for easy installation
- [ ] Docker image (for CI/CD environments)

### Testing
- [ ] Test with Sonnet/Haiku — document quality differences per model
- [ ] Test with 20+ servers simultaneously (stress test)
- [ ] Benchmark: time and token usage per server

### Deliverable
- [ ] GitHub release v1.0.0 with changelog
- [ ] Launch blog post
- [ ] Product Hunt / Hacker News launch

---

## v1.1.0 — Developer Experience

**Goal:** Make it fast and ergonomic for daily use.

### Speed
- [ ] Incremental audit: only re-test changed servers (detect via git diff or file hash)
- [ ] Cache source code reads between runs
- [ ] Parallel Phase 0 checks (currently sequential)

### Filtering
- [ ] Severity filtering: `--min-severity high` (skip MEDIUM/LOW)
- [ ] Category filtering: `--categories security,health`
- [ ] Server exclusion: `--exclude cloud-servers`

### Custom rules
- [ ] Custom check injection: user adds own test cases via YAML
- [ ] Custom severity overrides: "credential in .env is LOW for my setup"
- [ ] Ignore list: suppress specific findings by ID

### Integration
- [ ] Pre-commit hook: run quick scan before commit
- [ ] GitHub Action: run audit on PR, comment with findings
- [ ] VS Code extension: show findings inline (stretch goal)

---

## v1.2.0 — Advanced Detection

**Goal:** Catch attacks that no other tool catches.

### Rug pull detection
- [ ] TOCTOU testing: connect twice with delay, compare tool descriptions
- [ ] Tool hash drift monitoring: persistent hash store, alert on change
- [ ] Description mutation classifier: benign update vs malicious change

### Runtime behavior analysis
- [ ] Response analysis: call read-only tools, analyze responses for hidden instructions
- [ ] Timing analysis: detect unusually slow responses (potential C2 callback)
- [ ] Error response fingerprinting: categorize error types across servers

### Cross-server intelligence
- [ ] Active chain testing (Active Mode): call tool A, feed output to tool B, check for escalation
- [ ] Credential relay detection: find credentials from server A usable in server B
- [ ] PII flow mapping: trace sensitive data across tool boundaries

### Supply chain deep scan
- [ ] npm/PyPI registry verification: package exists, correct publisher, not typosquat
- [ ] Dependency tree analysis: transitive dependencies with known CVEs
- [ ] Binary hash verification for pre-built MCP servers

---

## v2.0.0 — Enterprise & Ecosystem

**Goal:** Enterprise features, multi-client support, community ecosystem.

### Multi-client support
- [ ] Cursor config discovery and audit
- [ ] VS Code + Copilot config discovery
- [ ] Windsurf config discovery
- [ ] Generic MCP client config parser (any .mcp.json)

### Enterprise features
- [ ] CI/CD mode: `mcp-redteam --ci --fail-on critical` (exit code based)
- [ ] Scheduled audits: cron-based re-audit with drift detection
- [ ] Team dashboard: aggregate findings across projects (stretch)
- [ ] RBAC audit: check if MCP servers enforce role-based access
- [ ] SOC2 mapping: map findings to CC6/CC7/CC8 controls

### Compliance
- [ ] AI-BOM generation (CycloneDX 1.6 format)
- [ ] OWASP MCP Top 10 compliance report
- [ ] Remediation SLA tracking (time from finding to fix)

### Community
- [ ] Public audit database: community-contributed findings (anonymized)
- [ ] Plugin system: third-party check modules
- [ ] Leaderboard: most secure public MCP servers

### Sandbox
- [ ] Sandboxed tool execution: run tools in isolated Docker container
- [ ] Network monitoring: detect unexpected outbound connections during audit
- [ ] Filesystem monitoring: detect unexpected file writes during tool execution

---

## Coverage Matrix

How mcp-redteam maps to the 75-point audit checklist and OWASP MCP Top 10:

| Domain | 75-Point Checks | OWASP Category | v0.1 | v0.3 | v1.0 | v2.0 |
|--------|----------------|----------------|------|------|------|------|
| Auth | AUTH-01 to AUTH-10 | MCP07 | Partial | Full | Full | Full |
| Secrets | SECRETS-01 to SECRETS-10 | MCP01 | Partial | Full | Full | Full |
| Tool Scoping | SCOPE-01 to SCOPE-10 | MCP02, MCP03 | Partial | Full | Full | Full |
| Audit Logging | LOG-01 to LOG-10 | MCP08 | No | Partial | Full | Full |
| Prompt Injection | PI-01 to PI-15 | MCP06, MCP10 | Partial | Full | Full | Full |
| Rate & Abuse | RATE-01 to RATE-10 | MCP02 | No | Partial | Partial | Full |
| Config Health | Phase 0 | MCP09 | Full | Full | Full | Full |
| Supply Chain | Phase 0D + v1.2 | MCP04 | Partial | Full | Full | Full |

---

## Attack Coverage vs Competition

| Attack Class (MCP-DPT) | mcp-redteam | mcp-scan | Cisco | Promptfoo |
|------------------------|-------------|----------|-------|-----------|
| Tool Poisoning | v0.1 (source) + v0.3 (hash) | Yes (description) | Yes (YARA) | Yes (red team) |
| Rug Pull | v1.2 (TOCTOU) | Yes (hash pinning) | No | No |
| Command Injection | v0.1 (source path analysis) | No | No | No |
| Path Traversal | v0.1 (source + active probe) | No | No | No |
| SSRF | v0.1 (source + active probe) | No | No | No |
| Credential Storage | v0.1 (file checks + source) | No | No | No |
| Cross-Server Chains | v0.1 (analytical) + v1.2 (active) | Toxic flows (basic) | No | No |
| Config Health | v0.1 (Phase 0) | No | Config discovery | No |
| Scope Conflicts | v0.1 (Phase 0B) | No | No | No |
| Supply Chain | v0.1 (version pinning) + v1.2 (deep) | No | CVE check | No |
| Tool Shadowing | v0.3 | Yes | No | Yes |
| Network Exposure | v0.1 (Phase 0E) | No | No | No |
| Auth Bypass | v0.3 | No | No | No |

**Key insight:** We are the ONLY tool that does source code path analysis for injection vulnerabilities. Every other tool works at the description/metadata level.

---

## Metrics for Launch

Before taking ads:
- [ ] 10+ documented real-world audits
- [ ] <10% false positive rate (verified)
- [ ] Comparison post with mcp-scan (concrete findings they miss)
- [ ] GitHub README with screenshots, demo GIF
- [ ] v1.0.0 release with SARIF + JSON output
- [ ] At least 1 video demo

Growth targets (first 3 months):
- 100 GitHub stars
- 5 external contributors
- 3 blog posts / tweets from security community
- 1 conference talk submission (BSides, DEF CON Village, OWASP AppSec)
