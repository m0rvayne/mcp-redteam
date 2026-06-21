# Show HN Launch Variants

Optimal posting time: Tuesday-Thursday, 9:00-10:30 AM ET (13:00-14:30 UTC).
Tuesday and Wednesday historically perform best for security/devtool posts.

---

## Variant A: The Personal Story Angle

**Title:** Show HN: I audit MCP servers for clients. 7 of 106 had RCE. So I open-sourced the tool

**Body:**

I build MCP connectors and AI automation for businesses -- 70+ connectors deployed across client projects. A few months ago some started acting up: dropping connections, config conflicts, servers I forgot to remove sitting in config eating resources.

Went looking for something to audit them. Found mcp-scan (Invariant/Snyk) -- it reads tool descriptions but never touches source code. A server with clean descriptions and exec(user_input) on line 42 sails right through. Cisco's scanner uses YARA + LLM-as-judge but also doesn't read code.

So I built mcp-redteam. It has two modes:

1. **Standalone CLI** -- 25 Semgrep rules (Python + JS/TS), config health checks, SARIF output for GitHub Security tab. Deterministic, no API key needed, runs in CI/CD. `pip install redteam-mcp && mcp-redteam scan ./your-server --no-llm`

2. **Claude Code plugin** -- reads source code, maps cross-server attack chains, generates HTML reports with fix suggestions. Uses the CLAUDE.md file as a structured audit playbook.

Ran it on 106 public MCP servers. 7 had remote code execution -- subprocess with shell=True and unsanitized input, eval() on user parameters, AppleScript injection via unescaped strings. One of those servers had 25K GitHub stars.

Real findings that description-only scanners cannot detect:
- Trello API keys in .env committed to git
- Instagram session cookies stored 644 (world-readable)
- Google OAuth tokens with excessive permissions
- AppleScript injection via unescaped clipboard input

The tool audits itself too: 177 tests including self-security checks, Hypothesis fuzzing, and a documented self-audit (10 vulnerabilities found, 8 fixed, 1 mitigated, 1 accepted with rationale).

Limitations I should be honest about: false positive rate isn't formally measured yet. LLM mode requires Anthropic API key. Plugin needs Claude Code. Code analysis only covers Python and JS/TS -- no Go, Rust, or Java MCP servers yet.

https://github.com/m0rvayne/mcp-redteam

**Expected engagement:** 150-300 points. Personal narrative + concrete data (7/106 RCE) + self-honesty about limitations plays well on HN. Security tool posts with real findings consistently outperform those with only feature lists. Risk: commenters will ask about the 25K-star server name.

---

## Variant B: The Comparison Angle

**Title:** Show HN: MCP-Redteam -- security scanner that reads source code, not just descriptions

**Body:**

MCP security scanners today read what a server says about itself. mcp-redteam reads what a server actually does.

The difference matters. A server can have perfectly clean tool descriptions while running exec(user_input) in its handler. Description scanners (mcp-scan, Proximity) will pass it. Code scanners won't.

mcp-redteam works two ways:

**CLI mode** (deterministic, CI/CD ready): 25 Semgrep taint-tracking rules for Python and JS/TS. Detects shell injection, path traversal, SSRF, eval, hardcoded secrets, stdout pollution, missing error handling, credential leaks in responses, blocking calls in async, and more. Outputs SARIF for GitHub Security tab. `pip install redteam-mcp && mcp-redteam scan ./server --no-llm`

**Plugin mode** (Claude Code): reads full source, probes read-only tools with controlled input, detects behavioral mismatches (description says X, code does Y), maps cross-server attack chains, generates HTML reports.

How it compares to what exists:

- mcp-scan (Snyk): scans descriptions + proxy mode for runtime. Does not read source. Good for what it does, but misses code-level bugs entirely.
- Cisco mcp-scanner: YARA + LLM-as-judge. Does not read source code either. Requires Cisco API for full functionality.
- Ramparts (Javelin): Rust-based, fast, but also pre-deploy description scanning.

What mcp-redteam does NOT do (yet): no runtime proxy, no dependency CVE scanning, no Go/Rust/Java support, no OWASP/MITRE mapping.

I tested it on 106 public MCP servers. 7 had remote code execution in their source code that no description scanner would catch.

177 tests. Self-security audit included. MIT license.

https://github.com/m0rvayne/mcp-redteam

**Expected engagement:** 100-200 points. Comparison posts get engagement from defenders of competing tools, which drives discussion. Risk: can feel like a takedown piece if tone isn't right. The "what we don't do" section is critical for credibility.

---

## Variant C: The Data Angle

**Title:** Show HN: We scanned 106 MCP servers -- 7 had remote code execution

**Body:**

MCP (Model Context Protocol) is how AI agents talk to tools. There are now thousands of MCP servers on GitHub. We scanned 106 of the most popular ones for security issues.

Results:
- 7 servers had remote code execution (subprocess with shell=True + user input, eval() on parameters, AppleScript injection)
- One of those had 25,000+ GitHub stars
- Multiple servers had API keys committed to git, session cookies stored world-readable (644), OAuth tokens with excessive scopes
- None of these were detectable by scanning tool descriptions alone -- they all lived in the source code

The tool: mcp-redteam. Two modes:

**CLI** (`pip install redteam-mcp`): 25 Semgrep rules covering shell injection, path traversal, SSRF, eval, hardcoded secrets, and 10 more categories. Works on Python and JS/TS servers. SARIF output for CI/CD. No cloud dependency in deterministic mode.

**Claude Code plugin**: AI-driven deep audit that reads source, traces code paths from input to dangerous functions, maps cross-server attack chains, generates HTML report with fixes. Uses a structured CLAUDE.md playbook (not freeform prompting).

The methodology: Semgrep taint tracking for code-level issues + 6 config health checks (dead servers, scope conflicts, credential exposure in config files, unpinned packages, CVE-2025-59536 / CVE-2026-21852 detection).

We eat our own dogfood: 177 tests including a self-security audit. Found 10 vulnerabilities in our own code. Fixed 8, mitigated 1, accepted 1 with documented rationale.

What we don't cover yet: Go/Rust/Java servers, runtime monitoring, dependency CVE scanning. False positive rate not formally benchmarked.

https://github.com/m0rvayne/mcp-redteam

**Expected engagement:** 200-400 points. Data-led posts perform best on HN for security content. "We scanned X, found Y" is the format that got upvotes for Snyk's early blog posts and similar security research. The "25K stars" detail will drive clicks. Risk: people will demand you name the servers.

---

## Recommendation

**Lead with Variant C** (data angle). It has the strongest hook and the format HN security posts perform best with. Variant A is the fallback if you want a more personal tone.

Do NOT lead with Variant B -- comparison posts risk appearing adversarial, and the mcp-scan team is active on HN.

---

# Anticipated Q&A

Prepare these answers before posting. On HN, the first 2 hours of comments determine the post's trajectory.

---

### 1. "How is this different from mcp-scan?"

mcp-scan reads tool descriptions -- what a server says about itself. mcp-redteam reads source code -- what a server actually does. They catch different classes of bugs.

mcp-scan is good at detecting tool poisoning (malicious descriptions), prompt injection patterns, and with its proxy mode, runtime policy violations.

mcp-redteam catches code-level issues that never appear in descriptions: shell injection via subprocess, path traversal in file handlers, hardcoded API keys, world-readable credential files, blocking calls in async handlers. These are the findings from our 106-server scan -- none were detectable from descriptions.

They're complementary. Run mcp-scan for description-level checks and runtime monitoring, run mcp-redteam for code-level analysis. We're not competing with them.

---

### 2. "Why not just use Semgrep directly?"

You can. Our 25 rules are open source Semgrep YAML -- you could copy them into your own Semgrep config.

What mcp-redteam adds on top: (a) MCP-specific config health checks that Semgrep can't do (dead servers, scope conflicts, credential exposure in .mcp.json, CVE detection in config patterns), (b) structured CLI with SARIF output and CI exit codes tuned for MCP, (c) the Claude Code plugin mode that reads source + probes tools + maps cross-server chains, which is an entirely different layer.

If you already have Semgrep in CI, you can grab our rules from the rules/ directory and skip the CLI entirely. No lock-in.

---

### 3. "The LLM mode seems unreliable"

It's optional. The CLI's deterministic mode (--no-llm) uses only Semgrep rules and config checks. Zero non-determinism, zero API calls, runs offline.

The LLM mode adds behavioral mismatch detection (description says read-only, code writes files) and cross-server chain analysis. These are inherently judgment calls that benefit from an LLM. We mitigate non-determinism with audit history -- each scan saves a JSONL baseline, subsequent runs classify findings as new/confirmed/fixed. After 2-3 runs, signal stabilizes.

The LLM mode is best thought of as an additional layer on top of deterministic scanning, not a replacement for it.

---

### 4. "Bus factor = 1, why should I trust this?"

Fair. It's a solo project today. Here's what mitigates that:

- 177 tests with CI (GitHub Actions), so regressions are caught automatically
- Semgrep rules are plain YAML -- anyone can read, modify, or fork them
- The CLAUDE.md plugin is a structured prompt, not compiled code -- fully auditable
- MIT license, no telemetry, no cloud dependency in deterministic mode
- The self-security audit is documented -- you can see exactly what we found in our own code and how we handled it

I'd welcome contributors. The rules/ directory is the easiest place to start -- adding detection patterns for new vulnerability classes.

---

### 5. "What's the false positive rate?"

Honestly: not formally measured yet. It's listed in our limitations section.

Anecdotally from the 106-server scan and internal use: the Semgrep rules produce false positives when (a) SSRF rule triggers on URLs built from config rather than user input, (b) path traversal rule triggers on open() where validation exists but isn't recognized as a sanitizer, (c) stdout pollution flags print() in __main__ blocks. These are documented in the README.

Measuring FP rate properly requires a labeled benchmark corpus, which we don't have yet. If someone wants to collaborate on that, I'd be glad to.

---

### 6. "Does this send my code to Anthropic?"

In CLI deterministic mode (--no-llm): no. Everything runs locally. Semgrep runs locally. No network calls.

In LLM mode: yes, source code snippets are sent to the Anthropic API for behavioral analysis. This is the same as using Claude Code on your codebase. If that's not acceptable, use --no-llm.

In Claude Code plugin mode: your code is already in Claude's context (you're running Claude Code). The plugin doesn't add new data exfiltration -- it structures the analysis Claude is already doing.

---

### 7. "Why Python and not Rust/Go?"

Pragmatism. The core value is in the Semgrep rules (YAML) and the CLAUDE.md audit playbook (structured prompt). The Python CLI is glue code -- it runs Semgrep, parses results, checks configs, formats output.

Rust would make the CLI faster, but the bottleneck is Semgrep execution (which is already written in OCaml/Rust) and LLM API calls. The Python wrapper adds negligible overhead.

If someone wants to rewrite the CLI in Rust, the rules and playbook are portable. The architecture is intentionally language-agnostic at the detection layer.

---

### 8. "Can I add custom rules?"

Yes. Drop Semgrep YAML files in the rules/ directory. The CLI picks up everything in that folder automatically. Follow the existing rule format -- examples in rules/python/ and rules/javascript/.

For the Claude Code plugin: the CLAUDE.md is the audit playbook. You can add checks to the audit checklist, add new server type classifications, or modify severity criteria. It's a markdown file, not compiled code.

---

### 9. "How does the embedding detector actually work?"

The embedding detector checks tool descriptions for hidden Unicode characters -- zero-width spaces (U+200B), zero-width joiners (U+200D), tags block characters (U+E0000 range), and similar invisible characters that can be used to hide instructions in tool descriptions.

It's a character-level scan, not ML-based. It looks for characters that have no visible rendering but could carry hidden payloads. Simple, deterministic, and fast. This catches the tool poisoning attack vector where malicious instructions are embedded in descriptions using invisible Unicode.

---

### 10. "What about Go/Java/Rust MCP servers?"

Not supported for code analysis yet. The Semgrep rules only cover Python and JavaScript/TypeScript.

Config health checks still work regardless of server language -- dead server detection, scope conflicts, credential exposure in config files, unpinned packages. These checks operate on the config layer, not the code.

Adding Go support is the most requested feature since the mcp-go SDK is popular. The Semgrep rule format supports Go, so it's a matter of writing Go-specific detection patterns for the same vulnerability classes. Contributions welcome.

For now, if you have a Go/Rust/Java MCP server, you can use the Claude Code plugin mode which reads any language (the LLM understands the code regardless), or run your language's own SAST tools alongside mcp-redteam's config checks.
