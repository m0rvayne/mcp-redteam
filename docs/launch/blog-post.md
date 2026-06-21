---
title: "I Scanned 106 MCP Servers for Security Vulnerabilities. Here's What I Found."
published: false
description: "Built an MCP security scanner after finding RCE in popular servers. 25+ Semgrep rules, config checks, SARIF output."
tags: security, mcp, python, opensource
---

I build MCP connectors for businesses. 70+ deployed across client projects. When some started acting up -- dropping connections, config conflicts, servers I forgot to remove still sitting in config -- I went looking for a security scanner. Couldn't find one that actually reads source code.

## The problem: scanners that don't read code

The most popular MCP scanner, [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan), reads what a server *says about itself* -- tool descriptions. It checks for tool poisoning in descriptions and prompt injection patterns. That's useful, but it misses an entire class of vulnerabilities.

Here's a server that mcp-scan passes with a clean bill of health:

```python
from mcp.server.fastmcp import FastMCP
import subprocess

server = FastMCP("shell-runner")

@server.tool("run_command")
async def run_command(cmd: str) -> str:
    """Execute a shell command and return its output."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
```

The description is clean. No poisoning. No suspicious text. But the code takes a user-controlled `cmd` argument and passes it straight to `subprocess.run` with `shell=True`. That's remote code execution.

In MCP context, "user input" means LLM-controlled input. And LLM output can be manipulated via prompt injection embedded in files, emails, or any data the model processes. A docstring that says "Never execute unsafe commands" is not a security boundary.

Description-only scanners cannot catch this. You have to read the code.

## What I built

[mcp-redteam](https://github.com/m0rvayne/mcp-redteam) -- an MCP security scanner that reads source code. Two modes:

- **Standalone CLI**: 25 Semgrep taint-tracking rules + 6 config health checks. Deterministic. SARIF output. Works in CI/CD without an LLM.
- **Claude Code plugin**: AI-driven deep audit with behavioral mismatch detection, cross-server chain analysis, and interactive HTML reports.

Install and scan in two commands:

```bash
pip install redteam-mcp
mcp-redteam scan ./your-mcp-server --no-llm
```

## The 106-server scan

I cloned 106 public MCP servers -- Anthropic's official implementations plus the most popular community servers. Combined: 300K+ GitHub stars. Ran all 25 Semgrep rules against every one of them.

### 4 confirmed RCE

Not 7 -- I initially reported more, but manual review knocked three down. Honest numbers matter more than impressive ones.

| Server | Stars | Vulnerability |
|--------|-------|---------------|
| **serena** | 25.2K | `subprocess.Popen(command, shell=True)` with LLM-controlled input |
| **mcp-chrome** | 11.8K | `new Function(code)()` in browser MAIN world -- 7 injection points |
| **mcp-use** | 10K | `exec()` with "restricted namespace" bypassed via `asyncio.create_subprocess_shell()` |
| **ida-pro-mcp** | 9.3K | `exec()` + `eval()` with full `__builtins__` inside IDA Pro |

Two additional servers (DesktopCommanderMCP, klavis) turned out to be by-design risks or false positives after deeper review. I also reported ha-mcp but [closed the issue](https://github.com/homeassistant-ai/ha-mcp/issues/1583) after finding their `python_sandbox.py` has proper AST validation. Not every `exec()` is a vulnerability.

### The pattern: "sandbox" that isn't

Three independent servers use `exec()`/`eval()`/`new Function()` and call it "sandboxed." The mcp-use case is instructive:

```python
exec(compiled_wrapped, namespace)  # "restricted namespace"
```

I verified: `asyncio` is passed into the namespace. `asyncio.create_subprocess_shell()` gives full RCE without any `__subclasses__` tricks. The "safety tests" in the repo only check three trivial cases (`import os`, `open()`, `eval()`) -- none of the real bypass vectors.

### The good news

Anthropic's official servers are clean. GitHub's official MCP server (30.6K stars): zero findings. Clean community servers exist too -- apple-mcp, chart-server, perplexity MCP all had minimal or zero findings.

## Code examples: what the rules catch

### Shell injection (MRT001)

Vulnerable pattern:

```python
@server.tool("system_info")
async def system_info(query: str) -> str:
    command = f"uname -{query}"
    proc = subprocess.run(command, shell=True, capture_output=True, text=True)
    return proc.stdout.strip()
```

The Semgrep rule uses taint tracking -- it follows data from the tool parameter (`query`) through the f-string into the `subprocess.run` sink with `shell=True`:

```yaml
rules:
  - id: mcp-python-shell-injection
    severity: ERROR
    languages: [python]
    mode: taint
    pattern-sources:
      - patterns:
          - pattern: |
              async def $FUNC(..., $ARG: str, ...):
                  ...
          - focus-metavariable: $ARG
    pattern-sinks:
      - pattern: subprocess.run($CMD, ..., shell=True, ...)
        focus-metavariable: $CMD
    pattern-sanitizers:
      - pattern: shlex.quote(...)
```

### Path traversal (MRT002)

Vulnerable pattern:

```python
@server.tool("read_file")
async def read_file(path: str) -> str:
    with open(path, "r") as f:  # no realpath check
        return f.read()
```

An attacker-controlled path like `../../etc/passwd` walks right out of the intended directory. The fix is two lines:

```python
real = Path(path).resolve()
if not real.is_relative_to(BASE_DIR):
    raise ValueError("Path outside allowed directory")
```

### SSRF (MRT003)

Vulnerable pattern:

```python
@server.tool("fetch_url")
async def fetch_url(url: str) -> str:
    response = httpx.get(url, timeout=10)  # no scheme/host validation
    return response.text
```

Pass `http://169.254.169.254/latest/meta-data/` and you get cloud instance credentials. Pass `http://127.0.0.1:6379/` and you're talking to internal Redis.

## What the tool checks

25 Semgrep rules across Python and JavaScript/TypeScript:

| Rule ID | What it detects | Severity |
|---------|----------------|----------|
| MRT001 | Shell injection -- subprocess + shell=True with user input | CRITICAL |
| MRT002 | Path traversal -- open()/Path() without realpath check | HIGH |
| MRT003 | SSRF -- HTTP requests with user-controlled URL | HIGH |
| MRT004 | Eval injection -- eval()/exec()/new Function() with user input | CRITICAL |
| MRT005 | Hardcoded secrets -- API keys, tokens, passwords in source | CRITICAL |
| MRT006 | Stdout pollution -- print()/console.log() in stdio handlers | INFO |
| MRT007 | Missing error handling -- tool functions without try/catch | HIGH |
| MRT008 | Credential in response -- API keys/tokens in tool return values | HIGH |
| MRT009 | Dead server -- configured but not connected | HIGH |
| MRT010 | Scope conflict -- same server in multiple config scopes | MEDIUM |
| MRT011 | Credential in config -- plaintext secret in git-tracked config | CRITICAL |
| MRT012 | Unpinned package -- npx/uvx without pinned version | HIGH |
| MRT013 | Auto-enable bypass -- CVE-2026-21852 | CRITICAL |
| MRT014 | API exfiltration -- ANTHROPIC_BASE_URL override (CVE-2025-59536) | CRITICAL |
| MRT018 | Missing signal handler -- no SIGTERM/SIGINT for graceful shutdown | MEDIUM |
| MRT019 | Blocking sync call -- synchronous HTTP inside async function | HIGH |
| MRT020 | OAuth overprivilege -- dangerous scopes like gmail.modify | MEDIUM |
| MRT021 | Env secret no rotation -- secrets from env vars without expiry check | MEDIUM |
| MRT022 | No timeout HTTP -- HTTP request without timeout parameter | MEDIUM |
| MRT023 | No timeout subprocess -- subprocess without timeout | MEDIUM |
| MRT024 | No timeout fetch -- fetch() without AbortSignal | MEDIUM |
| MRT025 | Dangerous params -- tool params named cmd, exec, eval, code | HIGH |
| MRT026 | JS missing error handling -- async function without try/catch | HIGH |
| MRT027 | JS credential in response -- return objects with credential fields | HIGH |
| MRT028 | No timeout spawn -- spawn()/execFile() without timeout | MEDIUM |

Plus 6 config health checks (dead servers, scope conflicts, credential exposure, supply chain, CVE detection, orphaned processes).

## I ran it on itself

This is the part that builds trust. I pointed mcp-redteam at its own source code and found 10 vulnerabilities:

| ID | Status | What was found |
|----|--------|----------------|
| VULN-01 | Fixed | Credential values leaked in finding evidence -- now redacted |
| VULN-02 | Fixed | Symlink following in config scanner -- `is_symlink()` check added |
| VULN-03 | Fixed | CWD rules directory substitution -- CWD fallback removed |
| VULN-04 | Fixed | Unlimited file read in config parsing -- 10MB cap added |
| VULN-05 | Fixed | File counting DoS via rglob -- excludes `.venv`/`node_modules`, caps at 10,000 |
| VULN-06 | Fixed | Username leak in SARIF paths -- paths made relative to scan target |
| VULN-07 | Mitigated | XSS in findings -- SARIF and HTML formatters escape all fields |
| VULN-08 | Fixed | Path canonicalization in CLI -- `path.resolve()` added |
| VULN-09 | Fixed | Unbounded find subprocess results -- capped at 100 |
| VULN-10 | Accepted | Floor-pinned dependencies (`>=`, no upper bound) -- no known critical CVEs |

8 fixed, 1 mitigated, 1 accepted with justification. Every fix has a corresponding test in `test_self_security.py`. A security tool that hasn't audited itself isn't a security tool -- it's a liability.

## How it compares

| | mcp-scan | Cisco MCP Scanner | **mcp-redteam** |
|---|---|---|---|
| **Reads source code** | No | Python only | Python + JS/TS |
| **Analysis method** | LLM on descriptions | YARA + LLM-as-judge | Semgrep taint tracking + LLM behavioral |
| **Config validation** | No | Config discovery | 6 checks, CVE detection |
| **Behavioral mismatch** | No | No | Yes (LLM layer) |
| **SARIF / CI output** | Yes | No | Yes |
| **Self-tested** | Unknown | Unknown | 177 tests, self-security audit |
| **Cloud dependency** | Invariant Labs API | Cisco API (optional) | Fully local in deterministic mode |
| **False positive rate** | Not published | ~78% on YARA rules | ~40% (manual review validated) |

Honest caveat: FP rate was measured on the 106-server scan, not on a standardized benchmark. I haven't found a good MCP security benchmark yet -- if you know of one, open an issue.

## Try it

```bash
pip install redteam-mcp
mcp-redteam scan ./your-mcp-server --no-llm
```

Example output:

```
$ mcp-redteam scan ./my-mcp-server --no-llm

Phase 0: Config validation...
  2 config issues found
Phase 1: Semgrep analysis...
  5 code findings

+----------+--------+-------------------+----------------------------------+
| Severity | Rule   | File:Line         | Title                            |
+----------+--------+-------------------+----------------------------------+
| CRITICAL | MRT001 | server.py:42      | Shell Injection                  |
| HIGH     | MRT002 | handlers.py:15    | Path Traversal                   |
| HIGH     | MRT003 | api.py:88         | SSRF                             |
| MEDIUM   | MRT012 | .mcp.json         | Unpinned Package                 |
| MEDIUM   | MRT010 | settings.json     | Scope Conflict                   |
+----------+--------+-------------------+----------------------------------+

7 findings (1 critical, 2 high, 2 medium, 0 low)
Risk score: 60/100
```

For CI/CD, add SARIF output and a fail threshold:

```bash
mcp-redteam scan ./server --fail-on critical --format sarif -o results.sarif
```

Results show up in GitHub's Security tab. There's also a [GitHub Action](https://github.com/m0rvayne/mcp-redteam/blob/main/action.yml) for one-line integration.

GitHub: [github.com/m0rvayne/mcp-redteam](https://github.com/m0rvayne/mcp-redteam)
PyPI: `pip install redteam-mcp`

## What's next

- **MCPTox benchmark** -- standardized vulnerable MCP corpus for measuring detection rates across scanners
- **Community rules** -- contributing guidelines for custom Semgrep rules
- **Cross-server chain detection in CLI** -- currently only available in the Claude Code plugin
- **Auto-fix in CLI** -- plugin can fix, CLI can't yet
- **Dependency CVE scanning** -- Cisco has this, we don't yet
- **Lower the FP rate** -- ~40% is better than 78%, but not good enough

If you maintain an MCP server, run this on it. If you find false positives, open an issue -- every FP report makes the rules better.

If you want to contribute rules, the format is standard Semgrep YAML with MCP-specific taint sources (tool decorators, handler parameters). Check the [rules/](https://github.com/m0rvayne/mcp-redteam/tree/main/rules) directory for examples.

---

*mcp-redteam is MIT licensed. Built because my own connectors needed auditing, open-sourced because yours do too.*
