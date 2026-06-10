# v2 Final Plan — After 3 Research Iterations + Critics

> Created: 2026-06-11
> Research: 4 agents → synthesis → critic → this plan
> Status: FINAL — ready to execute

---

## The ONE thing that matters

Critic said: "Define one concrete pain that mcp-redteam solves better than `grep -r 'eval('`."

**Answer: Semantic understanding of MCP server code.**

Static scanners (mcp-scan, Cisco, AgentAuditKit) read patterns. They can't answer:
- "This tool description says 'reads files' but the code also writes to network" → behavioral mismatch
- "This server changed its tool description since last scan" → rug pull
- "Credential from server A can be used to access server B" → cross-server chain

**This is the LLM layer. This is our UVP. Everything else is table stakes.**

---

## What to fix NOW (based on architect feedback + critic synthesis)

### 1. README: honest, not alpha-badged

No alpha badge (critic: "it signals unstable API, not maturity"). Instead:

**Replace** current marketing-heavy README with:
- "What it does TODAY" section with honest feature list
- "Current Limitations" section (not hidden in footer)
- "14 detection rules covering 30 patterns" (not "30 Semgrep rules")
- Remove claims about features that exist only in CLAUDE.md prompts

### 2. Dependencies: revert ceiling pins, add lock file

Critic proved: upper bounds (`<1.0`) are antipattern for CLI tools. They break downstream resolution.

**Action:**
- Revert pyproject.toml to floor-only (`>=0.12`)
- Generate and commit `uv.lock` for reproducibility
- Lock file = reproducible installs, pyproject.toml = flexible for users

### 3. CLAUDE.md: 2 modes, not 3

Critic: 3 modes = decision fatigue. Binary question: "will this break my server?"

**Keep:** PASSIVE (default) / ACTIVE (opt-in)
**Add:** explicit "NEVER" list inside Active Mode (169.254.169.254, timing probes on live, state-modifying tools)
**Remove:** INVASIVE as separate mode — it's just the "NEVER" list

### 4. Rule count: be honest

14 YAML files. Some JS files have multiple sub-rules (patterns inside one rule ID).
Semgrep counts by rule ID → we have 14 rules.

**Say:** "14 detection rules" or "14 security checks across Python and JavaScript"
**Don't say:** "30 rules" or "30 Semgrep rules"

### 5. FP measurement: qualitative, not quantitative

Critic: FP rate on GitHub repos = metric on unrepresentative sample.

**Instead:** publish "Known False Positive Patterns" document:
- Pattern X triggers on Y code, but it's safe because Z
- How to suppress: `# nosemgrep: mcp-python-ssrf`
- This is what Semgrep does in their rule registry

### 6. Focus: one pain, nail it

Don't build trust infrastructure before product-market fit. Gitleaks had no SARIF at v1.0.

**Our one pain:** "I run MCP servers and I don't know if they're safe."
**Our one answer:** `mcp-redteam scan ./my-server` → here are the problems, here's how to fix them.

Everything else (benchmarks, community rules, enterprise features) comes after this works reliably.

---

## Immediate actions (this session)

1. [ ] Rewrite README — honest "What works today" / "Limitations" / "Planned"
2. [ ] Revert dep ceilings, generate uv.lock
3. [ ] Fix rule count in README (14 rules, not 30)
4. [ ] Add "Known False Positive Patterns" to docs/
5. [ ] Push and send to architect for re-review

---

## What we DON'T do (critic validated)

- No alpha badge (signals instability, not honesty)
- No 3-mode system (2 + explicit NEVER list)
- No upper-bound dependency pinning (lock file instead)
- No FP rate number (qualitative patterns doc instead)
- No enterprise checklist features before product-market fit
- No benchmark against MCPTox (synthetic dataset, not representative)

---

## What architect wants to see for 10/10

Based on all 3 reviews, the gap is:

1. **Code matches claims** — README says X, code does X. Period.
2. **Tested on real servers** — not just fixtures. Run on 5 public MCP servers, document findings.
3. **LLM layer works** — the thing that makes us different actually exists in code, not just CLAUDE.md.
4. **Professional packaging** — CHANGELOG, SECURITY.md, proper versioning, CI green.

Items 3 and 4 are done (analyzer.py exists, CHANGELOG/SECURITY pushed).
Items 1 and 2 are what we fix now.
