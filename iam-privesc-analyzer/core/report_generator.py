# Copyright (c) AKID's Global Cybersecurity Tools
# Module: report_generator.py
# Purpose: Renders analysis findings into JSON and a self-contained HTML report.

import json
from datetime import datetime, timezone

from jinja2 import Template

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>IAM Privilege Escalation Report</title>
<style>
  :root { --bg:#0d1117; --panel:#161b22; --border:#30363d; --text:#c9d1d9; --muted:#8b949e;
          --crit:#f85149; --high:#f0883e; --med:#d29922; --low:#3fb950; --info:#58a6ff; --accent:#39d0d8; }
  * { box-sizing: border-box; }
  body { background:var(--bg); color:var(--text); font-family:'Segoe UI',Consolas,monospace; margin:0; padding:0 0 60px; }
  header { padding:32px 40px 20px; border-bottom:1px solid var(--border); }
  header h1 { margin:0; font-size:22px; letter-spacing:0.5px; }
  header .sub { color:var(--muted); font-size:13px; margin-top:6px; }
  .copyright { color:var(--accent); font-size:12px; margin-top:10px; }
  .container { padding:24px 40px; max-width:1100px; margin:0 auto; }
  .summary-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:14px; margin-bottom:30px; }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:16px; }
  .card .num { font-size:26px; font-weight:700; }
  .card .label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:0.5px; margin-top:4px;}
  .crit .num{color:var(--crit)} .high .num{color:var(--high)} .med .num{color:var(--med)} .low .num{color:var(--low)}
  h2 { border-left:4px solid var(--accent); padding-left:10px; font-size:16px; margin-top:36px; }
  .finding { background:var(--panel); border:1px solid var(--border); border-left:4px solid var(--muted); border-radius:6px; padding:16px 18px; margin-bottom:14px; }
  .finding.critical{border-left-color:var(--crit)} .finding.high{border-left-color:var(--high)}
  .finding.medium{border-left-color:var(--med)} .finding.low{border-left-color:var(--low)} .finding.info{border-left-color:var(--info)}
  .badge { display:inline-block; font-size:11px; padding:2px 8px; border-radius:10px; text-transform:uppercase; font-weight:600; letter-spacing:0.5px; }
  .badge.critical{background:rgba(248,81,73,0.15); color:var(--crit)} .badge.high{background:rgba(240,136,62,0.15); color:var(--high)}
  .badge.medium{background:rgba(210,153,34,0.15); color:var(--med)} .badge.low{background:rgba(63,185,80,0.15); color:var(--low)}
  .badge.info{background:rgba(88,166,255,0.15); color:var(--info)}
  .path { font-family:Consolas,monospace; font-size:13px; margin:10px 0; color:var(--text); background:#010409; padding:10px 12px; border-radius:4px; overflow-x:auto; white-space:nowrap;}
  .arrow { color:var(--accent); margin:0 6px; }
  .rules { color:var(--muted); font-size:12px; margin-top:6px; }
  .admin-list li { margin-bottom:4px; }
  footer { text-align:center; color:var(--muted); font-size:12px; padding:30px; border-top:1px solid var(--border); margin-top:40px;}
</style>
</head>
<body>
<header>
  <h1>IAM Privilege Escalation Path Analyzer — Report</h1>
  <div class="sub">Account: {{ account.account }} &nbsp;|&nbsp; Generated: {{ generated_at }}</div>
  <div class="copyright">&copy; AKID's Global Cybersecurity Tools — Defensive IAM Security Assessment</div>
</header>
<div class="container">

  <div class="summary-grid">
    <div class="card"><div class="num">{{ summary.total_identities }}</div><div class="label">Total Identities</div></div>
    <div class="card crit"><div class="num">{{ summary.already_admin_count }}</div><div class="label">Already Admin</div></div>
    <div class="card high"><div class="num">{{ summary.identities_with_escalation_path }}</div><div class="label">Escalation-Risk Identities</div></div>
    <div class="card"><div class="num">{{ summary.total_paths_found }}</div><div class="label">Escalation Paths Found</div></div>
    <div class="card crit"><div class="num">{{ summary.findings_by_severity.critical }}</div><div class="label">Critical</div></div>
    <div class="card high"><div class="num">{{ summary.findings_by_severity.high }}</div><div class="label">High</div></div>
  </div>

  {% if summary.already_admin %}
  <h2>Already Admin-Equivalent Identities</h2>
  <ul class="admin-list">
    {% for a in summary.already_admin %}<li>{{ a }}</li>{% endfor %}
  </ul>
  {% endif %}

  <h2>Escalation Path Findings</h2>
  {% if findings|length == 0 %}
    <p style="color:var(--low)">No privilege escalation paths detected under the current ruleset.</p>
  {% endif %}
  {% for f in findings %}
  <div class="finding {{ f.max_severity }}">
    <span class="badge {{ f.max_severity }}">{{ f.max_severity }}</span>
    <strong>{{ f.source_name }}</strong> ({{ f.source_type }}) — {{ f.hops }} hop(s) to ADMIN
    <div class="path">
      {% for node in f.path %}{{ node }}{% if not loop.last %}<span class="arrow">&#8594;</span>{% endif %}{% endfor %}
    </div>
    {% if f.rule_titles %}
    <div class="rules">Techniques: {{ f.rule_titles | join(' | ') }}</div>
    {% endif %}
  </div>
  {% endfor %}

</div>
<footer>Generated by IAM Privilege Escalation Path Analyzer &mdash; &copy; AKID's Global Cybersecurity Tools. Read-only analysis; no changes were made to the AWS account.</footer>
</body>
</html>
"""


def _rule_titles(rule_ids, rules_by_id):
    return [rules_by_id.get(rid, rid) for rid in dict.fromkeys(rule_ids)]  # dedupe, preserve order


def generate_json_report(inventory_account, summary, findings, rules_by_id, output_path):
    serializable_findings = []
    for f in findings:
        serializable_findings.append({
            "source": f["source"],
            "source_name": f["source_name"],
            "source_type": f["source_type"],
            "path": f["path"],
            "hops": f["hops"],
            "max_severity": f["max_severity"],
            "rule_ids": f["rule_ids"],
            "rule_titles": _rule_titles(f["rule_ids"], rules_by_id),
        })

    report = {
        "copyright": "AKID's Global Cybersecurity Tools",
        "tool": "IAM Privilege Escalation Path Analyzer",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "account": inventory_account,
        "summary": summary,
        "findings": serializable_findings,
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    return report


def generate_html_report(report, output_path):
    template = Template(HTML_TEMPLATE)
    # attach rule_titles for template rendering
    findings = report["findings"]
    html = template.render(
        account=report["account"],
        generated_at=report["generated_at"],
        summary=report["summary"],
        findings=findings,
    )
    with open(output_path, "w") as f:
        f.write(html)
