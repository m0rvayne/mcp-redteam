# Contributing

## Attack Vectors

Found a new MCP attack vector? Add it to `docs/attack-playbook.md`:

1. Choose the correct category (1-12) or propose a new one
2. Include: test number, attack name, mechanism, specific payload
3. Add references (CVE, research paper, blog post)
4. Submit a PR

## Bug Reports

Found a bug in the audit logic or report generation?

1. Open an issue with:
   - What you expected
   - What happened
   - Your MCP server setup (which servers, how many)
   - Claude Code version

## Fix Strategy Additions

Know a better way to fix a common MCP vulnerability?

1. Add to the relevant section in `CLAUDE.md` (auto-fixable / requires explanation / cannot fix)
2. Include exact code snippets, not generic advice

## Report Template

Want to improve the HTML report design?

1. Edit `templates/report-template.html`
2. Keep: CSS-only (no JavaScript), mobile responsive, all `<details>` closed by default
3. Test on Chrome, Safari, Firefox, and mobile Safari

## What NOT to submit

- Destructive payloads that could cause real damage
- Credential harvesting tools
- Anything that requires network access to external servers during audit
