# 96% of What an MCP Scanner Tells You Is About Code No MCP Client Can Reach

We scanned 56 MCP servers — 3.86 million lines, 428,000 GitHub stars between
them — and the most useful thing we found was not in any of them. It was in our
own scanner.

**Tool:** [mcp-redteam](https://github.com/m0rvayne/mcp-redteam) · **Corpus:**
[pinned to exact commits](../../research/corpus-manifest.json), reproducible with one command.

---

## The finding that changed the tool

Our scanner reported 5,809 findings rated CRITICAL or HIGH across the corpus.
Then we measured where they were:

| | |
|---|---|
| Findings in files that register MCP tools | **4%** |
| Findings everywhere else in the repository | **96%** |

Everywhere else means release scripts, build tooling, examples, internal
utilities. Code no MCP client can reach.

The clearest case is serena, at 29K stars. Our scanner found eight shell
injections. Seven were in `scripts/bump_version.py` and `repo_dir_sync.py`:

```python
os.system(f"git tag v{new_version}")
```

That is a maintainer running a release script on their own machine with their
own version string. Calling it a CRITICAL vulnerability in an MCP server is
simply wrong. The eighth was real.

One rule, MRT002 (path traversal), accounted for **93% of everything we rated
HIGH**. Sampling it found lines like these:

```python
p = EVIDENCE / name                          # an internal constant
out_dir = Path(out_dir)                      # a no-op normalisation
if not gate_dir or not Path(gate_dir).exists():   # an existence check
for p in sorted(Path(gate_dir).rglob("*")):       # a directory listing
```

None of them open a file. The rule was sinking on path *construction* — which
is how every program addresses a file — rather than on file *access*.

### What we changed

Two things, both in the tool rather than in anyone's server:

1. **Scope by reachability.** A file is on the MCP tool surface if it registers
   tools, or is reachable from such a file through imports. The second half
   matters: a traversal in `utils/files.py` called from a handler is a real
   finding, and a file-level filter would discard it. Findings off the surface
   are kept and reported, but lowered to INFO with the reason stated.
2. **MRT002 sinks on access, not construction** — `open()`, `read_text`,
   `write_text`, `unlink`, `shutil` operations. Taint still reaches them through
   the constructed variable, so real traversal is detected exactly as before.

Measured on the same corpus:

```
CRITICAL + HIGH    5809  ->  1737     (-70%)
CRITICAL            262  ->    89
HIGH               5547  ->  1648
```

Every finding we had manually confirmed as real survived.

**If you maintain an MCP security scanner, measure this on your own output.**
The failure mode is invisible from inside: every one of those 5,809 findings was
a genuine pattern match. They were just answers to a question nobody asked.

---

## Remote code execution: four servers, still there

Verified against each project's current `main` on 2026-09-14.

| Server | Stars | Where | Status |
|--------|-------|-------|--------|
| [serena](https://github.com/oraios/serena) | 29K | `solidlsp/util/subprocess_util.py:239`, `language_servers/common.py:115` — `shell=True` | [Reported](https://github.com/oraios/serena/issues/1569); closed same day as `not_planned` |
| [mcp-chrome](https://github.com/hangwin/mcp-chrome) | 12K | `userscript.ts:270,280` — `new Function(code)()` in the browser MAIN world | Present |
| [mcp-use](https://github.com/mcp-use/mcp-use) | 10K | `client/code_executor.py:124` — `exec(compiled_wrapped, namespace)` | [Reported](https://github.com/mcp-use/mcp-use/issues/1718); closed 2026-08-23 without a reply |
| [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) | 9K | `ida_mcp/api_python.py:157,170` — `exec(code, ...)` and `eval(code, ...)` behind a `py_eval` tool | Present, behind an opt-in flag |

Neither disclosure was fixed. serena's maintainer
[replied](https://github.com/oraios/serena/issues/1569): *"`shell=True` is
necessary; this is intentional. The arguments for the executions do not come
from user inputs."*

In MCP, arguments come from the LLM, and LLM output is steerable by anything the
model reads — a file, an issue title, a web page. A docstring telling the model
not to run unsafe commands is not a security boundary. We think this is a real
disagreement rather than an oversight, and we are recording both positions.

The mcp-use report sat open for two months and was closed without comment.

---

## Half of what GitHub calls an MCP server is not one

We selected candidates by GitHub topic — `mcp-server`, `mcp-servers` — then
verified after cloning: a repository counts only if it **both** declares an MCP
SDK dependency **and** registers a tool or server in source.

```
112  repositories labelled mcp-server
 56  actually depend on an MCP SDK and register something
```

**Half fail.** 46 declare no MCP SDK dependency at all; another 10 list one but
expose nothing. The label is a claim, not evidence.

This matters beyond tidiness. Directories, registries and "awesome" lists are
built on that label, so anyone counting the MCP ecosystem from topic search is
counting roughly double.

---

## What the 56 real servers look like

```
3,863,281 lines
   10,894 findings        89 CRITICAL   1,653 HIGH   681 MEDIUM   8,471 INFO
       13 servers with at least one CRITICAL
        1 server with no findings at all
```

Most of the remaining volume is two rules: stdout pollution (`print()` in a
stdio server, which does break JSON-RPC, but 5,662 times is an inventory rather
than an alarm) and what survives of MRT002.

**We are not claiming a false positive rate.** These are finding counts. A real
FP rate needs hand review of a sample, and we have not done it. Sampling
suggests the remaining MRT002 and MRT006 volume is still largely noise — which
is to say this work is not finished.

---

## Reproduce it

The corpus of our previous scan was never recorded. We published numbers nobody
could check, including us. That was a mistake, and this is the fix:

```bash
pip install redteam-mcp semgrep
git clone https://github.com/m0rvayne/mcp-redteam && cd mcp-redteam
python research/reproduce.py --workdir /tmp/mcp-corpus
```

Every repository is pinned to an exact commit. The script clones those commits,
re-scans and diffs against the recorded result. One server takes a minute:

```bash
python research/reproduce.py --workdir /tmp/mcp-corpus --only oraios/serena
```

Semgrep is not bit-deterministic — three runs over the same tree gave 887, 885
and 884 findings on our largest repository, with per-file timeouts disabled
entirely. The script tolerates 2% drift per repository and flags anything
larger. We would rather say that than claim an exact match that does not hold.

---

## What we got wrong

Reporting other people's bugs while hiding your own is not a defensible
position for a security tool, so:

- **Every finding we shipped had no evidence.** Semgrep returns matched source
  only to authenticated users; for everyone else the field reads `requires
  login`. We mapped that string straight into the report. Terminal, JSON, SARIF,
  HTML and our own GitHub Security tab all printed `requires login` where the
  vulnerable line belongs — under a stated philosophy of proving every finding
  with source evidence.
- **The published package found nothing at all.** Rules shipped to a directory
  the runtime never looked in, so `pip install redteam-mcp` produced a scanner
  that reported zero code findings, silently. On the vulnerable fixtures: 0
  before, 72 after.
- **Hardcoded-secret detection missed uppercase constants.** `API_KEY = "sk-..."`
  and `TOKEN = "ghp_..."` — the way most projects actually write it — matched
  nothing, because the rule only matched lowercase identifiers.
- **Scan results depended on machine load.** Semgrep's default per-file budget
  is 5 seconds; under load it drops files silently. The same corpus scanned
  twice gave 10,748 and 10,894 findings, with no indication that anything had
  been skipped.
- **The previous post said 7 RCE.** Manual review had already brought it to 4 —
  two downgraded to by-design risk, one retracted with an apology — and the
  README was not updated to match.

All are fixed. They are listed here because the class of bug matters more than
any individual one: **a scanner that is wrong tells you nothing, confidently.**
The only defence is measuring your own output and publishing what you find.

---

*Scan performed with mcp-redteam on 2026-09-11 against the pinned corpus in
`research/corpus-manifest.json`. Disclosure outcomes re-checked and the four RCE
findings re-verified against each project's current `main` on 2026-09-14. The
earlier 106-server scan is kept at [scan-106-servers.md](scan-106-servers.md);
its corpus was never recorded and it cannot be reproduced.*
