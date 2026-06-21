"""Self-contained HTML report formatter for mcp-redteam scan results.

Generates a dark terminal-styled single-file HTML report with inline CSS.
No external dependencies — all styles embedded in a <style> block.
"""

import html
from datetime import datetime
from pathlib import Path

from mcp_redteam.models import Finding, ScanResult, Severity

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "#ff4444",
    Severity.HIGH: "#ff8800",
    Severity.MEDIUM: "#ffcc00",
    Severity.LOW: "#4488ff",
    Severity.INFO: "#888888",
}

_SEVERITY_ORDER = list(Severity)

_CSS = """\
:root {
  --bg: #0a0a0a; --surface: #111111; --border: #222222;
  --border-heavy: #333333; --text: #b0b0b8; --text-dim: #606068;
  --heading: #e0e0e8; --white: #f0f0f5;
  --critical: #ff4444; --high: #ff8800; --medium: #ffcc00;
  --low: #4488ff; --info: #888888;
  --mono: 'JetBrains Mono','Fira Code','SF Mono','Consolas',monospace;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:var(--mono); background:var(--bg); color:var(--text);
  -webkit-font-smoothing:antialiased; line-height:1.7; font-size:13px; }
.page { max-width:900px; margin:0 auto; padding:2rem 2.5rem; min-height:100vh; }
strong { color:var(--heading); font-weight:600; }
code { font-family:var(--mono); font-size:0.8em; background:var(--surface);
  padding:0.1em 0.35em; border:1px solid var(--border); }
.cover { padding-bottom:2.5rem; margin-bottom:2.5rem; border-bottom:1px solid var(--border); }
.cover-title { font-size:2.5rem; font-weight:700; color:var(--white);
  letter-spacing:-0.04em; line-height:1.1; margin-bottom:0.25rem; }
.cover-subtitle { font-size:0.9rem; color:var(--text-dim); margin-bottom:2rem; }
.cover-meta { font-size:0.8rem; line-height:2; }
.cover-meta .key { color:var(--text-dim); }
.cover-meta .val { color:var(--text); }
.sev-strip { display:flex; gap:0.75rem; margin-top:1.5rem; flex-wrap:wrap; }
.sev-chip { font-size:0.75rem; font-weight:600; }
.section { margin-bottom:2.5rem; }
.section-header { display:flex; align-items:baseline; gap:1rem; margin-bottom:1rem;
  padding-bottom:0.4rem; border-bottom:1px solid var(--border); }
.section-num { font-size:0.7rem; color:var(--text-dim); font-weight:400; min-width:2rem; }
.section-title { font-size:0.9rem; font-weight:600; color:var(--heading);
  text-transform:uppercase; letter-spacing:0.05em; }
.risk-item { display:flex; align-items:center; gap:0.6rem; margin-bottom:0.35rem; font-size:0.75rem; }
.risk-name { color:var(--text-dim); min-width:100px; text-align:right; }
.risk-track { flex:1; height:10px; background:var(--surface); border:1px solid var(--border); }
.risk-fill { height:100%; }
.risk-score { font-weight:600; min-width:24px; text-align:right; }
.finding { border:1px solid var(--border); margin-bottom:0.5rem; background:var(--surface); }
.finding summary { display:flex; align-items:center; gap:0.6rem; padding:0.6rem 0.85rem;
  cursor:pointer; user-select:none; list-style:none; font-size:0.8rem; }
.finding summary::-webkit-details-marker { display:none; }
.finding summary::before { content:">"; color:var(--text-dim); font-weight:400; flex-shrink:0; }
.finding[open] summary::before { content:"v"; }
.f-sev { font-size:0.65rem; font-weight:700; text-transform:uppercase; letter-spacing:0.02em; }
.f-title { flex:1; font-weight:500; color:var(--heading); }
.f-loc { font-size:0.7rem; color:var(--text-dim); }
.f-body { padding:0 0.85rem 0.85rem; border-top:1px solid var(--border);
  padding-top:0.85rem; margin-left:1.2rem; }
.f-field { margin-bottom:0.75rem; }
.f-field:last-child { margin-bottom:0; }
.f-label { font-size:0.65rem; font-weight:600; text-transform:uppercase;
  letter-spacing:0.06em; color:var(--text-dim); margin-bottom:0.2rem; }
.f-value { font-size:0.8rem; color:var(--text); line-height:1.65; }
pre { background:var(--bg); border:1px solid var(--border); padding:0.75rem 1rem;
  overflow-x:auto; font-family:var(--mono); font-size:0.75rem; line-height:1.6;
  color:var(--text); margin-top:0.3rem; white-space:pre-wrap; word-break:break-all; }
.footer { margin-top:2rem; padding-top:1rem; border-top:1px solid var(--border);
  display:flex; justify-content:center; gap:0.5rem; font-size:0.65rem; color:var(--text-dim); }
@media (max-width:640px) {
  .page { padding:1rem; } .cover-title { font-size:1.8rem; }
  .finding summary { flex-wrap:wrap; gap:0.35rem; }
}"""


def _e(text: str) -> str:
    """HTML-escape user-controlled content."""
    return html.escape(str(text), quote=True)


def _location_str(finding: Finding) -> str:
    if not finding.location:
        return ""
    loc = finding.location
    if loc.line:
        return "{}:{}".format(_e(loc.file), loc.line)
    return _e(loc.file)


def _severity_class(severity: Severity) -> str:
    return severity.value.lower()


def _risk_bar_color(score: int) -> str:
    if score >= 50:
        return "#ff4444"
    if score >= 20:
        return "#ffcc00"
    return "#44bb66"


def _duration_str(result: ScanResult) -> str:
    meta = result.metadata
    if meta.scan_end and meta.scan_start:
        delta = meta.scan_end - meta.scan_start
        secs = delta.total_seconds()
        if secs < 60:
            return "{:.1f}s".format(secs)
        return "{:.0f}m {:.0f}s".format(secs // 60, secs % 60)
    return "N/A"


def _render_finding(f: Finding) -> str:
    """Render a single finding as a <details> block (closed by default)."""
    sev_color = _SEVERITY_COLORS[f.severity]
    sev_label = f.severity.value
    loc = _location_str(f)
    rule_id = _e(f.rule_id or f.id)

    loc_html = ""
    if loc:
        loc_html = '<span class="f-loc">{}</span>'.format(loc)

    body_fields = []

    body_fields.append(
        '<div class="f-field">'
        '<div class="f-label">Description</div>'
        '<div class="f-value">{}</div>'
        '</div>'.format(_e(f.description))
    )

    if f.evidence:
        body_fields.append(
            '<div class="f-field">'
            '<div class="f-label">Evidence</div>'
            '<pre>{}</pre>'
            '</div>'.format(_e(f.evidence))
        )

    if f.fix:
        body_fields.append(
            '<div class="f-field">'
            '<div class="f-label">Fix</div>'
            '<div class="f-value">{}</div>'
            '</div>'.format(_e(f.fix))
        )

    return (
        '<details class="finding">'
        '<summary>'
        '<span class="f-sev" style="color:{sev_color}">[{sev_label}]</span>'
        '<span style="font-size:0.7rem;color:var(--text-dim)">{rule_id}</span>'
        '<span class="f-title">{title}</span>'
        '{loc_html}'
        '</summary>'
        '<div class="f-body">{body}</div>'
        '</details>'
    ).format(
        sev_color=sev_color,
        sev_label=sev_label,
        rule_id=rule_id,
        title=_e(f.title),
        loc_html=loc_html,
        body="\n".join(body_fields),
    )


def format_html(result: ScanResult) -> str:
    """Generate a self-contained HTML report string from scan results."""
    meta = result.metadata
    now_str = datetime.now().strftime("%B %d, %Y")
    target = _e(meta.target_path)
    duration = _duration_str(result)
    score = result.risk_score
    bar_color = _risk_bar_color(score)

    # Severity counts
    counts = {}
    for sev in Severity:
        counts[sev] = sum(1 for f in result.findings if f.severity == sev)

    # Severity chips
    chips = []
    for sev in Severity:
        if counts[sev] > 0:
            color = _SEVERITY_COLORS[sev]
            chips.append(
                '<span class="sev-chip" style="color:{}">[{}] {}</span>'.format(
                    color, sev.value, counts[sev]
                )
            )
    chips_html = "\n    ".join(chips)

    # Sort findings: CRITICAL first
    sorted_findings = sorted(
        result.findings,
        key=lambda f: _SEVERITY_ORDER.index(f.severity),
    )

    # Render findings
    findings_html = "\n".join(_render_finding(f) for f in sorted_findings)

    # Risk score bar
    risk_html = (
        '<div class="risk-item">'
        '<span class="risk-name">total</span>'
        '<div class="risk-track">'
        '<div class="risk-fill" style="width:{pct}%;background:{color}"></div>'
        '</div>'
        '<span class="risk-score" style="color:{color}">{score}</span>'
        '</div>'
    ).format(pct=min(score, 100), color=bar_color, score=score)

    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>mcp-redteam report &mdash; {target}</title>
<style>
{css}
</style>
</head>
<body>
<div class="page">

<div class="cover">
  <div class="cover-title">mcp-redteam</div>
  <div class="cover-subtitle">Security Scan Report</div>
  <div class="cover-meta">
    <div><span class="key">target:</span> <span class="val">{target}</span></div>
    <div><span class="key">date:</span> <span class="val">{date}</span></div>
    <div><span class="key">duration:</span> <span class="val">{duration}</span></div>
    <div><span class="key">mode:</span> <span class="val">{mode}</span></div>
    <div><span class="key">files_scanned:</span> <span class="val">{files}</span></div>
    <div><span class="key">total_findings:</span> <span class="val">{total}</span></div>
  </div>
  <div class="sev-strip">
    {chips}
  </div>
</div>

<div class="section">
  <div class="section-header">
    <span class="section-num">01</span>
    <span class="section-title">Risk Score</span>
  </div>
  {risk}
</div>

<div class="section">
  <div class="section-header">
    <span class="section-num">02</span>
    <span class="section-title">Findings ({total})</span>
  </div>
  {findings}
</div>

<div class="footer">
  <span>Generated by mcp-redteam v{version}</span>
</div>

</div>
</body>
</html>""".format(
        css=_CSS,
        target=target,
        date=now_str,
        duration=duration,
        mode=_e(meta.mode),
        files=meta.files_scanned,
        total=result.total_findings,
        chips=chips_html,
        risk=risk_html,
        findings=findings_html if sorted_findings else '<p style="color:var(--low)">No findings.</p>',
        version=_e(meta.tool_version),
    )


def write_html(result: ScanResult, output_path: Path) -> None:
    """Write HTML report to file."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(format_html(result), encoding="utf-8")
