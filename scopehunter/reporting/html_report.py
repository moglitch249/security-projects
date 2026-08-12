"""
html_report.py — HTML report generator using Jinja2 template.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, BaseLoader

from scopehunter.engine.orchestrator import ScanResult

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ScopeHunter Report — {{ target }}</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --dim: #8b949e; --accent: #58a6ff;
    --critical: #ff4444; --high: #f97316;
    --medium: #f59e0b; --low: #22d3ee; --info: #6b7280;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; line-height: 1.6; padding: 2rem; }
  h1 { color: var(--accent); font-size: 1.8rem; margin-bottom: 0.5rem; }
  h2 { color: var(--dim); font-size: 1rem; font-weight: normal; margin-bottom: 2rem; }
  h3 { color: var(--accent); margin: 1.5rem 0 0.75rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }
  .card .num { font-size: 2rem; font-weight: bold; }
  .card .label { color: var(--dim); font-size: 0.8rem; }
  .critical .num { color: var(--critical); }
  .high .num { color: var(--high); }
  .medium .num { color: var(--medium); }
  .low .num { color: var(--low); }
  .finding { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; border-left: 4px solid var(--border); }
  .finding.critical { border-left-color: var(--critical); }
  .finding.high { border-left-color: var(--high); }
  .finding.medium { border-left-color: var(--medium); }
  .finding.low { border-left-color: var(--low); }
  .finding.informational { border-left-color: var(--info); }
  .finding-title { font-weight: bold; font-size: 1rem; margin-bottom: 0.5rem; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; margin-right: 6px; }
  .badge.critical { background: #ff444422; color: var(--critical); }
  .badge.high { background: #f9731622; color: var(--high); }
  .badge.medium { background: #f59e0b22; color: var(--medium); }
  .badge.low { background: #22d3ee22; color: var(--low); }
  .badge.informational { background: #6b728022; color: var(--info); }
  .meta { color: var(--dim); font-size: 0.85rem; margin-bottom: 0.75rem; font-family: monospace; }
  .section { margin-bottom: 0.75rem; }
  .section label { color: var(--dim); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .section p { font-size: 0.9rem; white-space: pre-wrap; }
  .tech-table, .ep-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin-bottom: 1.5rem; }
  .tech-table th, .ep-table th { text-align: left; padding: 0.5rem; border-bottom: 1px solid var(--border); color: var(--dim); font-size: 0.75rem; }
  .tech-table td, .ep-table td { padding: 0.5rem; border-bottom: 1px solid var(--border); }
  .conf-bar { height: 6px; background: var(--border); border-radius: 3px; margin-top: 4px; }
  .conf-fill { height: 100%; background: var(--accent); border-radius: 3px; }
  pre { background: #010409; border: 1px solid var(--border); border-radius: 6px; padding: 0.75rem; font-size: 0.8rem; overflow-x: auto; color: var(--dim); margin-top: 0.5rem; }
  .cve-badge { background: #f59e0b22; color: var(--medium); padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-family: monospace; }
  footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--dim); font-size: 0.8rem; }
</style>
</head>
<body>
<h1>🎯 ScopeHunter Security Report</h1>
<h2>Target: {{ target }} | Generated: {{ generated_at }} | Profile: {{ profile }}</h2>

<div class="grid">
  <div class="card critical"><div class="num">{{ sev.critical }}</div><div class="label">Critical</div></div>
  <div class="card high"><div class="num">{{ sev.high }}</div><div class="label">High</div></div>
  <div class="card medium"><div class="num">{{ sev.medium }}</div><div class="label">Medium</div></div>
  <div class="card low"><div class="num">{{ sev.low }}</div><div class="label">Low</div></div>
  <div class="card"><div class="num">{{ sev.informational }}</div><div class="label">Info</div></div>
  <div class="card"><div class="num">{{ stats.endpoints_discovered }}</div><div class="label">Endpoints</div></div>
</div>

<h3>Technology Detection</h3>
<table class="tech-table">
<thead><tr><th>Technology</th><th>Confidence</th><th>Version</th><th>Signals</th></tr></thead>
<tbody>
{% for d in detections %}
<tr>
  <td><strong>{{ d.technology }}</strong></td>
  <td>
    {{ (d.confidence * 100) | int }}%
    <div class="conf-bar"><div class="conf-fill" style="width:{{ (d.confidence * 100) | int }}%"></div></div>
  </td>
  <td>{{ d.version or '—' }}</td>
  <td style="color:var(--dim);font-size:0.8rem">{{ d.evidence[:2] | join(', ') }}</td>
</tr>
{% endfor %}
</tbody>
</table>

{% if cves %}
<h3>⚠ Potentially Applicable CVEs (Manual Verification Required)</h3>
<p style="color:var(--dim);font-size:0.85rem;margin-bottom:1rem">
  These CVEs are identified for awareness only based on version detection. Do NOT exploit them. Manual verification is required.
</p>
<table class="tech-table">
<thead><tr><th>CVE ID</th><th>Component</th><th>Affected</th><th>Detected Version</th></tr></thead>
<tbody>
{% for cve in cves %}
<tr>
  <td><span class="cve-badge">{{ cve.id }}</span></td>
  <td>{{ cve.component }}</td>
  <td>{{ cve.affected_versions }}</td>
  <td>{{ cve.detected_version or 'Unknown' }}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% endif %}

<h3>Findings ({{ findings | length }})</h3>
{% for f in findings %}
<div class="finding {{ f.severity }}">
  <div class="finding-title">
    <span class="badge {{ f.severity }}">{{ f.severity | upper }}</span>
    {{ f.title }}
  </div>
  <div class="meta">{{ f.method }} {{ f.endpoint }}{% if f.parameter %} | param: {{ f.parameter }}{% endif %} | {{ f.confidence }} confidence ({{ (f.confidence_score * 100) | int }}%)</div>
  <div class="section"><label>Description</label><p>{{ f.description }}</p></div>
  <div class="section"><label>Why it matters</label><p style="color:var(--dim)">{{ f.why_it_matters }}</p></div>
  <div class="section"><label>Manual Verification</label><pre>{{ f.manual_verification }}</pre></div>
  <div class="section"><label>Remediation</label><p style="color:var(--dim)">{{ f.remediation }}</p></div>
  {% if f.evidence %}
  <div class="section"><label>Evidence</label>
    {% for ev in f.evidence %}
    <div style="font-family:monospace;font-size:0.8rem;color:var(--dim)">{{ ev.method }} {{ ev.url }} → {{ ev.status_code }} ({{ ev.response_size }}B, {{ ev.elapsed_ms | int }}ms){% if ev.session %} [{{ ev.session }}]{% endif %}</div>
    {% endfor %}
  </div>
  {% endif %}
</div>
{% endfor %}

<h3>Discovered Endpoints ({{ endpoints | length }})</h3>
<table class="ep-table">
<thead><tr><th>Method</th><th>URL</th><th>Status</th><th>Source</th><th>Has IDs</th></tr></thead>
<tbody>
{% for ep in endpoints[:100] %}
<tr>
  <td style="font-family:monospace">{{ ep.method }}</td>
  <td style="font-family:monospace;font-size:0.8rem">{{ ep.url[:80] }}</td>
  <td>{% if ep.status_code %}<span style="color:{% if ep.status_code < 300 %}var(--low){% elif ep.status_code < 400 %}var(--medium){% else %}var(--dim){% endif %}">{{ ep.status_code }}</span>{% else %}—{% endif %}</td>
  <td style="color:var(--dim);font-size:0.8rem">{{ ep.source }}</td>
  <td>{% if ep.has_object_ids %}<span style="color:var(--medium)">✓</span>{% else %}—{% endif %}</td>
</tr>
{% endfor %}
{% if endpoints | length > 100 %}<tr><td colspan="5" style="color:var(--dim);text-align:center">... and {{ endpoints | length - 100 }} more (see JSON report)</td></tr>{% endif %}
</tbody>
</table>

<footer>
  ScopeHunter v0.1.0 | For authorized security testing only | 
  All findings require manual verification before reporting.
</footer>
</body>
</html>
"""


def generate(result: ScanResult, output_path: Path) -> None:
    """Render the HTML report to output_path."""
    env = Environment(loader=BaseLoader())
    template = env.from_string(_HTML_TEMPLATE)

    sev = result.stats.get("findings_by_severity", {})

    # Prepare findings data
    findings_data = []
    for f in result.findings:
        d = f.to_dict()
        d["confidence"] = f.confidence.value
        d["confidence_score"] = f.confidence_score
        d["evidence"] = f.evidence
        findings_data.append(d)

    # Prepare endpoints data
    endpoints_data = [
        {
            "url": ep.url,
            "method": ep.method,
            "source": ep.source,
            "status_code": ep.status_code,
            "response_size": ep.response_size,
            "has_object_ids": ep.has_object_identifiers,
        }
        for ep in result.endpoints
    ]

    html = template.render(
        target=result.target,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        profile=result.scan_config.scan_profile,
        stats=result.stats,
        sev={
            "critical": sev.get("critical", 0),
            "high": sev.get("high", 0),
            "medium": sev.get("medium", 0),
            "low": sev.get("low", 0),
            "informational": sev.get("informational", 0),
        },
        detections=result.detections,
        cves=result.applicable_cves,
        findings=findings_data,
        endpoints=endpoints_data,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
