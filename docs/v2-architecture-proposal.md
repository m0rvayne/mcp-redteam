# mcp-redteam v2: Architecture Proposal for Review

> For: Architect review
> From: Daniil Solovyov (m0rvayne)
> Date: 2026-06-10
> Status: PROPOSAL — awaiting feedback before implementation

---

## Context

You reviewed mcp-redteam v0.1 and correctly identified: zero executable code, zero reproducibility, vendor lock-in, no tests. All valid.

We ran a full research cycle — competitive analysis (13 tools), 4 academic papers, OWASP MCP Top 10, MCP-DPT taxonomy (49 attack classes), 75-point audit checklist. Then we ran 4 isolated critic agents against our own plan. Here's where we landed.

---

## The Core Insight: Don't Become Scanner #10

The first instinct after your review was "add deterministic engine, become real software." We planned: Python CLI, 4-layer detection (Regex → AST → Semgrep → Bandit), SARIF output, 6-week timeline.

Then the critics destroyed it:

1. **AgentAuditKit** already exists in GitHub Marketplace — 217 rules, SARIF, OWASP MCP 10/10, MIT license. Shipping another static scanner = arriving late to a crowded party.

2. **mcp-scan (Snyk)** has 2,500 stars and corporate backing. **Cisco MCP Scanner** has 956 stars and enterprise API. **Proximity** has 295 stars. We can't out-feature them as one person.

3. **The original UVP was the LLM-driven approach** — reading source code semantically, probing tools actively, understanding behavioral mismatches between what a server says and what it does. No competitor does this. Switching to static analysis means abandoning the only differentiator.

4. **Rug-pull detection** — every industry report (DZone, Cisco, Snyk, OWASP) acknowledges this as a critical unsolved problem. Static scanners can't catch it by definition: the server changes behavior after the scanner approves it. Only runtime + semantic comparison can.

**Conclusion: don't replace LLM with deterministic. Add deterministic as a complement layer. Keep LLM-driven behavioral analysis as the core differentiator.**

---

## Proposed Architecture

```
mcp-redteam (Python CLI, pip install mcp-redteam)

┌─────────────────────────────────────────────────────────┐
│                    CLI (typer)                           │
│  mcp-redteam scan ./server [--no-llm] [--format sarif]  │
└────────────────────┬────────────────────────────────────┘
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
┌───────────────┐      ┌─────────────────────┐
│ Deterministic │      │   LLM Behavioral    │
│    Layer      │      │     Layer           │
│               │      │                     │
│ Semgrep with  │      │ Semantic mismatch:  │
│ 10-15 MCP     │      │ description vs code │
│ YAML rules    │      │                     │
│               │      │ Rug-pull detection: │
│ - injection   │      │ hash + semantic diff│
│   taint       │      │                     │
│ - path trav.  │      │ Chain analysis:     │
│ - SSRF taint  │      │ cross-server paths  │
│ - secrets     │      │                     │
│ - poisoning   │      │ Confidence via      │
│   patterns    │      │ logprobs (1 call)   │
│               │      │                     │
│ Works in CI   │      │ Anthropic SDK       │
│ --no-llm mode │      │ + Instructor        │
└───────┬───────┘      └──────────┬──────────┘
        │                         │
        └────────────┬────────────┘
                     ▼
          ┌─────────────────┐
          │  Config Scanner  │  (deterministic, no LLM)
          │  Phase 0 in code │
          │  - dead servers  │
          │  - scope conflicts│
          │  - CVE checks    │
          │  - supply chain  │
          └────────┬─────────┘
                   ▼
          ┌─────────────────┐
          │ Output Formatter │
          │ - SARIF 2.1.0   │
          │ - JSON           │
          │ - Terminal (rich)│
          │ - HTML report    │
          └─────────────────┘
```

### Why this architecture

**Why Semgrep alone (not 4 layers):**
Semgrep does regex + AST + taint tracking in one tool. Adding Bandit = Python-only duplicate. Adding custom regex = what Semgrep already does. Adding custom AST = what Semgrep already does. One engine, community-contributable YAML rules, covers Python + JS/TS natively.

**Why keep LLM as core (not optional nice-to-have):**
Static analysis catches patterns. LLM catches meaning. A server with clean code patterns but semantically deceptive behavior (description says "reads files", code also writes to network) — Semgrep passes, LLM catches. This is the gap every industry report identifies.

**Why Anthropic SDK direct (not LiteLLM):**
Users already have Claude access (they're using Claude Code). LiteLLM adds latency, deps, and solves a problem we don't have (multi-provider routing). Direct SDK + Instructor for structured output = simpler, faster, fewer deps.

**Why logprobs instead of 3x consensus:**
One API call returns confidence. Threshold: >0.85 = confirmed finding, 0.4-0.85 = needs review, <0.4 = noise. 1x cost instead of 3x. Research shows logprobs correlate well with actual accuracy for classification tasks.

**Why Config Scanner in code (not prompts):**
Phase 0 checks are deterministic by nature: parse JSON configs, grep for patterns, compare paths. These should be code, not LLM prompts. This directly addresses your "zero executable code" criticism while keeping LLM for what it's good at.

---

## Runtime Integration (not built, integrated)

Two existing open-source tools complement our analysis:

**Pipelock** (Go, Apache 2.0) — MCP proxy that sits between client and server:
- Hashes tool descriptions on first connection
- Detects rug-pull: hash changed = alert
- 48 DLP patterns for credential exfiltration in arguments
- Response injection detection ("IGNORE PREVIOUS INSTRUCTIONS" in server output)

**MCPSpy** (Go, eBPF) — kernel-level observation (Linux only):
- Hooks vfs_read/vfs_write for stdio transport
- Hooks SSL_read/SSL_write for HTTPS transport
- Sees actual syscalls: what files opened, what network connections made
- Ground truth that code analysis can't provide

We don't rebuild these. We document how to use them together and optionally parse their output into our SARIF report.

---

## Validation Strategy

**Primary benchmark: MCPTox** (353 real MCP tools, 1312 test cases, 11 risk categories, AAAI 2026). Independent academic dataset — not our fixtures. Published TPR/FPR against this = credible metric.

**Regression: own fixtures** — known-vulnerable and benign servers, pytest parametrized. For catching regressions in our detectors, not for marketing metrics.

**Property-based: Hypothesis** — generate random MCP tool schemas, verify invariants:
- Empty description → never CRITICAL
- Any input → detector never crashes
- Severity ∈ {NONE, LOW, MEDIUM, HIGH, CRITICAL}

**LLM regression: behavioral contracts, not snapshots:**
```python
# NOT this (breaks on model update):
assert result.text == "CRITICAL: tool poisoning found at line 42"

# THIS (survives model updates):
assert result.severity in ["HIGH", "CRITICAL"]
assert "tool_poisoning" in result.finding_types
assert result.confidence > 0.7
```

---

## Distribution

```
pip install mcp-redteam          # PyPI, isolated via uv
mcp-redteam scan ./server        # standalone CLI
mcp-redteam scan . --no-llm      # CI mode, deterministic only
mcp-redteam scan . --format sarif # GitHub Security tab
```

**Claude Code skill** = thin wrapper that:
1. Runs `mcp-redteam scan` via Bash
2. Reads `findings.json` output via Read tool (not stdout — avoids 30K char truncation)
3. Presents findings interactively
4. Offers fix engine

**GitHub Action:**
```yaml
uses: m0rvayne/mcp-redteam@v1
with:
  path: .
  format: sarif
  no-llm: true  # deterministic for CI
```

---

## What Makes This Different From Every Other Scanner

| Capability | Static scanners | **mcp-redteam** |
|---|---|---|
| Pattern matching | Yes | Yes (Semgrep) |
| Behavioral mismatch | No | **"Description says X, code does Y"** |
| Rug-pull detection | Hash-only (mcp-scan) | **Hash + semantic diff via LLM** |
| Cross-server chains | No (or basic) | **Validated multi-step attack paths** |
| Config health | Some | **Full Phase 0 (CVE-2025-59536, etc.)** |
| Runtime observation | No | **Pipelock + MCPSpy integration** |
| Independent validation | Unknown | **MCPTox 353 real tools, published metrics** |
| Community rules | No | **Semgrep YAML templates, contributable** |
| CI mode | Yes | **Yes (--no-llm --format sarif)** |
| Deep audit mode | No | **Yes (LLM behavioral + active probing)** |

**One-liner: "Static scanners check what servers say. We check what they do."**

---

## Timeline (2 weeks)

**Week 1:** CLI + Semgrep rules + Config scanner + SARIF + terminal output
**Week 2:** LLM behavioral layer + MCPTox validation + Claude Code skill update + PyPI + GitHub Action

Each day produces testable progress. No day depends on "finish the architecture first."

---

## What We're NOT Building

- Custom regex engine (Semgrep does it)
- Custom AST parser (Semgrep does it)
- Bandit integration (Semgrep covers Python)
- LiteLLM (direct Anthropic SDK)
- WASM sandbox (too complex for solo)
- Symbolic execution (academic)
- Our own MCP proxy (Pipelock exists)
- Our own eBPF tool (MCPSpy exists)

---

## Questions for You

1. Does the "deterministic complement + LLM core" framing address your "zero executable code" concern? We'll have real Python code (CLI, config scanner, Semgrep runner, SARIF formatter, test suite) — but the deep analysis stays LLM-driven by design.

2. Is Semgrep as the sole deterministic engine sufficient, or do you see value in a custom AST layer for MCP-specific patterns that Semgrep can't express?

3. The Pipelock + MCPSpy integration strategy — document and parse output vs. build our own runtime layer. Does "integration over building" feel like the right tradeoff for a solo project?

4. MCPTox as primary validation benchmark — is this credible enough, or do you want to see testing against live public MCP servers as well?
