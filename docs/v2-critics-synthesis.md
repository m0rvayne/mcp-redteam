# v2 Critics Synthesis: что меняем в плане

> Created: 2026-06-10
> Based on: 4 isolated critic agents attacking v2-architecture-plan.md
> Status: SYNTHESIS — input for revised plan

---

## Critic Verdicts Summary

| Critic | Core Attack | Verdict |
|--------|-------------|---------|
| #1 Architecture | 4 layers = overengineering, Python = herd instinct, 6 weeks unrealistic | Semgrep alone > 4 layers. MVP in 2 weeks, not 6. |
| #2 Product Strategy | Switching to static = losing UVP, market already has 10 static scanners | Keep LLM-driven behavioral testing. Rug-pull detector = unique niche. Nuclei model for community. |
| #3 QA Skeptic | Fixtures = self-confirming, consensus 3x = expensive, LLM regression impossible | MCPTox as independent benchmark. Logprobs instead of consensus. Behavioral contracts. |
| #4 Radical Alternatives | Pipelock (proxy), MCPSpy (eBPF), Socket (supply chain), CodeQL | Pipelock + supply chain = highest value, easiest integration |

---

## Key Insights That Change The Plan

### 1. DON'T abandon LLM-driven approach — it IS the UVP

Original architect said "this is not software." Critics 1 & 2 say: if you make it "software" (static analyzer), you become the 10th scanner in a crowded market. AgentAuditKit already exists with 217 rules, SARIF, OWASP 10/10.

**What nobody else does: LLM-driven behavioral testing that catches rug-pulls and semantic mismatches.** This is what made mcp-redteam unique. Keep it.

**New framing:** Not "prompt framework pretending to be a tool" but "AI-native security tool" — like how GitHub Copilot is AI-native coding, mcp-redteam is AI-native auditing. The LLM isn't a crutch — it's the engine. Add deterministic layer as COMPLEMENT, not replacement.

### 2. Semgrep alone > 4 layers

Critic 1 proved: Regex + AST + Semgrep + Bandit = redundant. Semgrep does regex + AST + taint in one tool. Bandit is Python-only subset of Semgrep.

**Decision: One deterministic engine (Semgrep) with MCP-specific YAML rules.** Not 4 layers. 10-15 rules, SARIF output, done.

### 3. Rug-pull / behavioral detector = the niche

Critic 2 found: "Why security scanning isn't enough for MCP servers" (DZone) — the industry acknowledges static scanners can't catch rug-pulls. Nobody fills this gap.

**Decision: Position as "the tool that catches what static scanners miss" — not as "yet another static scanner."**

### 4. Pipelock + MCPSpy = runtime layer without building from scratch

Critic 4 found ready tools:
- **Pipelock** (Go, Apache 2.0) — MCP proxy, rug-pull detection via hash comparison, DLP
- **MCPSpy** (Go, eBPF) — kernel-level syscall observation, Linux-only

Both exist and are open source. Integration > building from scratch.

### 5. MCPTox = independent validation, not self-crafted fixtures

Critic 3 proved: testing on your own fixtures = confirmation bias. MCPTox has 353 real tools with ground truth labels.

**Decision: MCPTox as primary benchmark.** Own fixtures for regression only.

### 6. Logprobs > 3x consensus

Critic 3: one API call with logprobs gives confidence score. Threshold: >0.85 = flag, 0.4-0.85 = human review, <0.4 = benign. 1x cost instead of 3x.

### 7. 2-week MVP, not 6-week architecture

Critic 1: 60 hours total (1-2h/evening). Plan for 200+ hours. Unrealistic.

**Week 1:** Semgrep with 10 MCP rules + SARIF output + basic CLI
**Week 2:** LLM behavioral analysis (keep current approach) + Pipelock integration docs + MCPTox validation

### 8. Nuclei model for community growth

Critic 2: ProjectDiscovery (Nuclei) won against Nessus/Qualys as solo developers through template engine + community rules. 50K+ stars.

**Decision: Make rules/templates easily contributable.** Semgrep YAML rules that anyone can write. Community submits MCP-specific rules like nuclei-templates.

### 9. TypeScript deserves consideration for native MCP AST

Critic 1: Most MCP servers are TypeScript. Python tool parsing TS through subprocess = matryoshka. TS gives native AST.

**Counter-argument:** Semgrep already supports TS natively. Python CLI + Semgrep TS rules = no subprocess needed. Python stays for ecosystem (LiteLLM/Anthropic SDK).

**Decision: Keep Python. Semgrep handles TS natively.**

### 10. Claude Code skill wrapper IS broken

Critic 1 detailed: 30K char truncation, 2min timeout, env scrubbing. "Thin wrapper" doesn't work.

**Decision: Standalone CLI primary. Claude Code skill calls CLI and reads JSON output file (not stdout).** Skill uses Read tool on `findings.json`, not Bash stdout.

---

## Revised Architecture

```
mcp-redteam (Python CLI)
├── Deterministic Layer
│   └── Semgrep with MCP-specific YAML rules (10-15 rules)
│       - tool poisoning patterns
│       - shell injection taint (source → sink)
│       - path traversal taint
│       - SSRF taint
│       - credential exposure
│       - stdout pollution
│       - missing error handling
├── LLM Layer (THE differentiator)
│   ├── Behavioral mismatch: description vs code reality
│   ├── Rug-pull detection: hash + semantic comparison
│   ├── Chain analysis: cross-server attack paths
│   ├── Logprobs-based confidence (not 3x consensus)
│   └── Anthropic SDK direct (not LiteLLM)
├── Runtime Layer (integration, not built)
│   ├── Pipelock proxy: rug-pull detection, DLP, response injection
│   └── MCPSpy eBPF: syscall observation (Linux)
├── Supply Chain
│   └── pip-audit / npm audit / osv-scanner (free, existing tools)
├── Config Scanner
│   └── Port Phase 0 from prompts to code (deterministic)
├── Output
│   ├── SARIF 2.1.0 (GitHub Security)
│   ├── JSON (machine-readable)
│   ├── Terminal (rich)
│   └── HTML (interactive report, keep current)
└── Validation
    ├── MCPTox benchmark (353 real tools, independent)
    ├── Own fixtures (regression only)
    ├── Hypothesis property-based tests
    └── Behavioral contracts (not snapshots)
```

### Distribution
```
PyPI: pip install mcp-redteam
Claude Code: skill reads CLI output from JSON file
GitHub Action: uses: m0rvayne/mcp-redteam@v1
Docker: for CI without Python
```

---

## Revised Timeline (2 weeks, not 6)

### Week 1: Deterministic + CLI
- [ ] Python CLI scaffold (typer, pydantic models)
- [ ] 10 Semgrep YAML rules for MCP patterns
- [ ] Semgrep runner (check installed, run, parse JSON, map to Finding)
- [ ] Config scanner (port Phase 0 to code)
- [ ] SARIF formatter
- [ ] Terminal formatter (rich)
- [ ] Supply chain: pip-audit/npm-audit wrapper
- [ ] Basic tests on own fixtures

### Week 2: LLM + Validation + Ship
- [ ] LLM behavioral analyzer (Anthropic SDK + Instructor)
- [ ] Logprobs confidence scoring
- [ ] Rug-pull detector (hash tool descriptions, compare between runs)
- [ ] MCPTox benchmark run → publish independent TPR/FPR
- [ ] Hypothesis property-based tests for detectors
- [ ] Claude Code skill update (reads JSON file, not Bash stdout)
- [ ] Pipelock integration docs (how to use together)
- [ ] PyPI publish
- [ ] GitHub Action
- [ ] README update: "Deterministic engine + AI-native behavioral analysis"

---

## Positioning (revised)

**OLD:** "Yet another static scanner but with LLM"
**NEW:** "AI-native MCP auditor — catches what static scanners miss"

Comparison table:

| | Static scanners (mcp-scan, Cisco) | **mcp-redteam** |
|---|---|---|
| Tool description analysis | Yes | Yes (via Semgrep) |
| Source code patterns | Some (Cisco behavioral) | Yes (Semgrep taint) |
| Rug-pull detection | Hash only (mcp-scan) | **Hash + semantic comparison via LLM** |
| Behavioral mismatch | No | **Yes — description says X, code does Y** |
| Cross-server chains | No | **Yes — validated attack paths** |
| Runtime observation | No | **Pipelock + MCPSpy integration** |
| Config health | No | **Yes — Phase 0** |
| Supply chain | Cisco (pip-audit) | **pip-audit + npm-audit + osv** |
| Independent validation | Unknown | **MCPTox benchmark published** |

**UVP: "Scanners read descriptions. We test behavior."**

---

## What we DON'T build

- Custom regex layer (Semgrep handles it)
- Custom AST parser (Semgrep handles it)
- Bandit integration (Semgrep covers Python)
- LiteLLM (direct Anthropic SDK)
- 4-layer detection engine (one Semgrep layer)
- WASM sandbox (too complex for solo)
- Symbolic execution (academic, not practical)
- Browser sandbox (manual, not automated)

---

## Community Strategy (Nuclei model)

1. Semgrep YAML rules as community-contributable templates
2. `rules/community/` directory with contributing guide
3. OWASP MCP Top 10 reference implementation PR
4. Blog post: "What we found scanning X real MCP servers with MCPTox"
5. Comparison post: "mcp-redteam vs mcp-scan: what each catches on 353 real servers"
