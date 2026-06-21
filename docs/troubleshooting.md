# Troubleshooting

## Common Issues

### "Semgrep not installed -- skipping deterministic code scan"

**Cause:** Semgrep is not in your PATH.

**Fix:**
```bash
pip install semgrep
```

Semgrep is optional -- deterministic code analysis requires it, but config checks and LLM analysis work without it.

---

### "No ANTHROPIC_API_KEY -- skipping LLM analysis"

**Cause:** The LLM behavioral analysis requires an Anthropic API key.

**Fix:**
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Or run without LLM (deterministic mode only):
```bash
mcp-redteam scan ./server --no-llm
```

---

### "requests is required for remote scanning"

**Cause:** The `requests` library is not installed (needed for `scan-remote`).

**Fix:**
```bash
pip install 'redteam-mcp[remote]'
```

---

### "path /foo does not exist"

**Cause:** The scan target path doesn't exist or is misspelled.

**Fix:** Verify the path exists:
```bash
ls -la /foo
```

The path is resolved to an absolute path before checking, so relative paths like `./server` work -- but the directory must exist.

---

### "sentence-transformers not installed -- skipping embedding analysis"

**Cause:** The embedding-based tool poisoning detector requires `sentence-transformers`.

**Fix:**
```bash
pip install 'redteam-mcp[embedding]'
```

Or install everything:
```bash
pip install 'redteam-mcp[all]'
```

The embedding detector is used by `scan-remote` to detect tool description poisoning. Local scans use Semgrep rules instead.

---

### Scan cancelled (Ctrl+C during scan-remote)

**Cause:** You pressed Ctrl+C during OAuth authentication or a remote scan.

**Fix:** This is a clean exit (code 0). Re-run when ready. To skip OAuth:
```bash
mcp-redteam scan-remote https://server.com/mcp --token <bearer-token>
# or skip auth entirely:
mcp-redteam scan-remote https://server.com/mcp --no-auth
```

---

### "Warning: scanning without auth -- may get limited results"

**Cause:** You used `--no-auth` on `scan-remote`. The server may reject unauthenticated requests or return fewer tools.

**Fix:** This is informational. If results look incomplete, authenticate:
```bash
mcp-redteam scan-remote https://server.com/mcp --token <bearer-token>
```

---

### Scan is slow (>2 minutes)

**Possible causes:**

1. Large codebase with many files -- use `--quick` for a fast config-only scan
2. Semgrep analyzing many files -- skips `node_modules`, `.venv`, `__pycache__`, `.git` by default
3. LLM API latency -- use `--no-llm` for deterministic-only scan

```bash
# Fast config-only scan (CRITICAL + HIGH only)
mcp-redteam scan ./server --quick

# Full scan without LLM
mcp-redteam scan ./server --no-llm
```

---

### HTML report is empty

**Cause:** No findings were detected.

**Fix:** This is expected if the server passes all checks. If you expected findings, run without `--quick` to include all severity levels:
```bash
mcp-redteam scan ./server --format html -o report.html
```

---

### Audit history comparison not showing

**Cause:** First scan -- no previous baseline to compare against.

**Fix:** Run the scan again after making changes. The second run will show:
```
fixed: N  new: N  confirmed: N  risk: 60 -> 45
```

Baselines are stored in `~/.mcp-redteam/baselines/`.

---

### CI pipeline exits with code 1

**Cause:** You used `--fail-on critical` or `--fail-on high` and findings at that severity or above were detected.

**Fix:** This is intentional for CI gating. To see what triggered it:
```bash
mcp-redteam scan ./server --fail-on critical --format json
```

Review and fix the findings, or lower the threshold.

---

### scan-remote returns "error" in metadata

**Cause:** The remote server returned an error -- it may be down, the URL may be wrong, or authentication failed.

**Fix:** Verify the server URL is correct and accessible:
```bash
curl -s https://your-server.com/mcp | head -20
```

If using OAuth, try with a direct bearer token instead:
```bash
mcp-redteam scan-remote https://your-server.com/mcp --token <your-token>
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Scan completed, no findings above threshold |
| 1    | Findings detected at or above `--fail-on` severity |
| 2    | Error: path not found, missing dependency, remote server error |
