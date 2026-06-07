# Roadmap

## v0.1.0 (current)

- 2-phase architecture: Deep Audit (per-server) + Chain Attacker (coordinator)
- Attack playbook: 12 categories, 80+ test cases, 40+ CVEs
- 4 audit categories: health, architecture, completeness, security
- Interactive HTML report (terminal style, CSS-only accordions)
- Fix strategy: auto-fix / requires decision / cannot fix
- Language selection (EN/RU/UK)
- Claude Code plugin with marketplace install

## v1.0.0

- [ ] 10+ real-world audits documented
- [ ] Single-server mode: `/mcp-redteam --server trello`
- [ ] Quick scan mode (security only, skip health/arch/completeness)
- [ ] JSON report format alongside HTML
- [ ] Baseline storage for temporal comparison
- [ ] Test with Sonnet/Haiku — document quality differences
- [ ] CONTRIBUTING.md
- [ ] Submit to anthropics/claude-plugins-official marketplace

## v1.1.0

- [ ] Incremental audit (only re-test changed servers)
- [ ] Severity filtering in report (show only CRITICAL+HIGH)
- [ ] Custom playbook injection (user adds own test cases)
- [ ] Report diff (compare two reports, show improvements/regressions)
- [ ] Integration with mcp-scan baselines

## v2.0.0

- [ ] Active cross-server chain testing (coordinator calls tools from multiple servers)
- [ ] Temporal drift monitoring (persistent baselines, automatic comparison)
- [ ] TOCTOU testing (dual-connection description mutation detection)
- [ ] Supply chain verification (npm/PyPI registry checks, typosquat detection)
- [ ] CI/CD integration (`mcp-redteam --ci --fail-on critical`)
- [ ] Sandbox execution (run tools in isolated environment)
- [ ] Comparison reports (before/after fix visualization)
