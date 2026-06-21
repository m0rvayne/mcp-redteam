# Contributing to mcp-redteam

## Quick Start

1. Fork and clone the repository
2. Install dev dependencies: `pip install -e ".[dev]"`
3. Run tests: `pytest tests/ -v`
4. Install semgrep for rule tests: `pip install semgrep`

## Project Structure

```
mcp_redteam/
  cli.py                # CLI entry point (typer)
  models.py             # Pydantic models, RULE_REGISTRY
  engine/
    semgrep_runner.py    # Semgrep integration
    config_scanner.py    # Phase 0 config health checks
    remote_scanner.py    # Remote MCP server scanning
    embedding_detector.py # Tool poisoning via embeddings
    audit_history.py     # JSONL baseline storage
  llm/
    analyzer.py          # LLM behavioral analysis
  formatters/
    terminal.py          # Rich terminal output
    json_fmt.py          # JSON output
    sarif.py             # SARIF for GitHub Security tab
    html_fmt.py          # Self-contained HTML report
rules/
  python/                # 14 Semgrep rules for Python MCP servers
  javascript/            # 11 Semgrep rules for JS/TS MCP servers
tests/                   # 170+ tests across 12 test files
```

## Adding a Semgrep Rule

1. Create a YAML file in `rules/python/` or `rules/javascript/`
2. Use an existing rule as a template -- every rule must have `metadata.rule_id`
3. Assign the next MRT ID (check `RULE_REGISTRY` in `models.py` for the latest)
4. Register the rule in `RULE_REGISTRY` in `models.py`
5. Create a vulnerable fixture in `tests/fixtures/vulnerable/`
6. Add to the parametrized test in `tests/test_semgrep.py`
7. Run: `pytest tests/test_semgrep.py -v`

## Rule ID Convention

- MRT001--MRT008: Code security (semgrep)
- MRT009--MRT014: Config health (config_scanner)
- MRT015--MRT017: LLM/embedding analysis
- MRT018--MRT028: Code quality (semgrep)
- MRT029--MRT031: Remote scanning
- MRT000: Unknown/fallback

## Code Style

- Python 3.10+ required
- Pydantic v2 for all models
- Type hints on public functions
- Core depends only on typer, rich, pydantic -- no other required dependencies
- Optional deps live in extras: `[llm]`, `[remote]`, `[embedding]`

## Testing

- All PRs must pass: `pytest tests/ -v`
- New features need tests
- Security-sensitive code needs self-audit tests (see `tests/test_self_security.py`)
- Property-based tests welcome (we use Hypothesis in `test_fuzzing.py`)

Test files overview:

| File | What it covers |
|------|---------------|
| `test_semgrep.py` | Each rule: vulnerable fixture detected, benign fixture clean |
| `test_self_security.py` | 21 tests: our own code audited for vulnerabilities |
| `test_stress.py` | 1000/10000 findings, concurrent scans, unicode |
| `test_fuzzing.py` | Hypothesis property-based: any input, no crash |
| `test_edge_cases.py` | Corrupt JSON, missing files, null bytes, timeouts |
| `test_config_scanner.py` | Config health checks, scope conflicts, credential detection |
| `test_cli.py` | CLI argument parsing, output formats, exit codes |
| `test_models.py` | Pydantic model validation |
| `test_formatters.py` | Output formatter unit tests |
| `test_remote_scanner.py` | Remote MCP server scanning |
| `test_embedding_detector.py` | Embedding-based tool poisoning detection |
| `test_llm_analyzer.py` | LLM behavioral analysis |

## Commit Messages

Format: `scope: description`

Examples:
- `rules: add MRT032 for Go command injection`
- `engine: fix false positive in path traversal detection`
- `tests: add stress test for concurrent HTML formatter`
- `docs: update rule table in README`

## Pull Requests

- Keep PRs focused -- one feature or fix per PR
- Include test coverage for new code
- Update the rule table in `README.md` if adding rules
- Run `pytest tests/ -v` locally before opening a PR

## License

MIT -- all contributions are under the same license.
