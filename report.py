import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

REPORTS_DIR = os.environ.get("REPORTS_DIR", "reports")

SEVERITY_COLORS = {
    "critical": "#ff3b3b",
    "high": "#ff6b2b",
    "medium": "#f0a500",
    "low": "#4fa3e0",
    "info": "#7c8db5",
    "unknown": "#555",
}

PDF_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Helvetica Neue', Arial, sans-serif; color: #1a1a2e; background: #fff; }

  /* Cover page */
  .cover {
    height: 100vh;
    background: linear-gradient(135deg, #0d0d1a 0%, #1a1a2e 50%, #0f3460 100%);
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    color: white;
    text-align: center;
    padding: 60px;
    page-break-after: always;
  }
  .cover .logo { font-size: 48px; font-weight: 900; letter-spacing: 4px; color: #00d4ff; margin-bottom: 8px; }
  .cover .tagline { font-size: 14px; color: #7c8db5; letter-spacing: 2px; text-transform: uppercase; margin-bottom: 60px; }
  .cover h1 { font-size: 36px; font-weight: 700; margin-bottom: 16px; }
  .cover .target { font-size: 20px; color: #00d4ff; margin-bottom: 40px; word-break: break-all; }
  .cover .meta { font-size: 13px; color: #7c8db5; line-height: 2; }
  .cover .badge {
    display: inline-block; margin-top: 40px; padding: 10px 28px;
    border: 2px solid #00d4ff; border-radius: 4px; color: #00d4ff;
    font-size: 12px; letter-spacing: 2px; text-transform: uppercase;
  }

  /* Content */
  .content { padding: 48px 56px; }
  h2 { font-size: 22px; font-weight: 700; color: #0f3460; border-bottom: 3px solid #00d4ff;
       padding-bottom: 8px; margin-bottom: 24px; margin-top: 40px; }
  h2:first-child { margin-top: 0; }

  /* Summary cards */
  .summary-grid { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 32px; }
  .summary-card {
    flex: 1; min-width: 100px; padding: 20px; border-radius: 8px;
    text-align: center; color: white;
  }
  .summary-card .count { font-size: 36px; font-weight: 900; }
  .summary-card .label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; opacity: 0.85; }

  /* Findings */
  .finding {
    border: 1px solid #e0e6f0; border-radius: 8px;
    margin-bottom: 16px; overflow: hidden; page-break-inside: avoid;
  }
  .finding-header {
    padding: 14px 18px; display: flex; justify-content: space-between; align-items: center;
  }
  .finding-name { font-size: 15px; font-weight: 700; }
  .finding-id { font-size: 11px; opacity: 0.7; }
  .severity-badge {
    padding: 4px 12px; border-radius: 20px; font-size: 11px;
    font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: white;
  }
  .finding-body { padding: 14px 18px; background: #f8faff; }
  .finding-body p { font-size: 13px; line-height: 1.6; color: #444; margin-bottom: 8px; }
  .finding-body .matched { font-size: 12px; color: #0f3460; font-family: monospace; }
  .finding-tags { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 10px; }
  .tag { background: #e0e6f0; padding: 2px 8px; border-radius: 10px; font-size: 11px; color: #0f3460; }

  /* Footer */
  .footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid #e0e6f0;
            font-size: 11px; color: #aaa; text-align: center; }

  @page { margin: 0; }
  .content-page { padding: 48px 56px; }
</style>
</head>
<body>

<!-- Cover -->
<div class="cover">
  <div class="logo">CYBERSCAN</div>
  <div class="tagline">Security Vulnerability Report</div>
  <h1>Web Security Assessment</h1>
  <div class="target">{{ url }}</div>
  <div class="meta">
    Scan Date: {{ scan_date }}<br>
    Report Generated: {{ report_date }}<br>
    Total Findings: {{ findings|length }}
  </div>
  <div class="badge">Confidential</div>
</div>

<!-- Executive Summary -->
<div class="content-page">
  <h2>Executive Summary</h2>
  <p style="font-size:14px;line-height:1.8;color:#444;margin-bottom:28px;">
    CyberScan conducted an automated security assessment of <strong>{{ url }}</strong> on {{ scan_date }}.
    The scan tested for SSL/TLS misconfigurations, missing HTTP security headers, exposed administrative
    panels, and known CVEs using Nuclei templates.
    {% if findings %}
    A total of <strong>{{ findings|length }}</strong> finding(s) were identified across
    {{ severity_counts|length }} severity level(s). Immediate attention is recommended for any
    Critical or High severity findings.
    {% else %}
    No significant security issues were detected during this scan. This does not guarantee the
    absence of all vulnerabilities — a manual penetration test is recommended for comprehensive coverage.
    {% endif %}
  </p>

  <div class="summary-grid">
    {% for sev, color in severity_colors.items() %}
    {% set count = severity_counts.get(sev, 0) %}
    <div class="summary-card" style="background:{{ color }};">
      <div class="count">{{ count }}</div>
      <div class="label">{{ sev }}</div>
    </div>
    {% endfor %}
  </div>

  <h2>Findings Detail</h2>

  {% if not findings %}
  <p style="color:#7c8db5;font-style:italic;">No findings were detected for this target.</p>
  {% endif %}

  {% for finding in findings %}
  {% set color = severity_colors.get(finding.severity, '#555') %}
  <div class="finding">
    <div class="finding-header" style="background:{{ color }}22; border-left: 5px solid {{ color }};">
      <div>
        <div class="finding-name" style="color:{{ color }}">{{ finding.name }}</div>
        <div class="finding-id">{{ finding.template_id }}</div>
      </div>
      <div class="severity-badge" style="background:{{ color }};">{{ finding.severity }}</div>
    </div>
    <div class="finding-body">
      <p>{{ finding.description }}</p>
      {% if finding.matched_at %}
      <p class="matched">Matched at: {{ finding.matched_at }}</p>
      {% endif %}
      {% if finding.tags %}
      <div class="finding-tags">
        {% for tag in finding.tags %}
        <span class="tag">{{ tag }}</span>
        {% endfor %}
      </div>
      {% endif %}
      {% if finding.reference %}
      <p style="margin-top:8px;font-size:12px;color:#666;">
        Reference: {% for ref in finding.reference[:2] %}{{ ref }}{% if not loop.last %}, {% endif %}{% endfor %}
      </p>
      {% endif %}
    </div>
  </div>
  {% endfor %}

  <div class="footer">
    Generated by CyberScan &bull; {{ report_date }} &bull; For authorized use only
  </div>
</div>

</body>
</html>
"""


def generate_pdf(scan_id: str, url: str, findings: list, created_at: str) -> str:
    try:
        from weasyprint import HTML
    except ImportError:
        raise RuntimeError("WeasyPrint is not installed.")

    os.makedirs(REPORTS_DIR, exist_ok=True)

    severity_colors = {
        "critical": "#ff3b3b",
        "high": "#ff6b2b",
        "medium": "#f0a500",
        "low": "#4fa3e0",
        "info": "#7c8db5",
    }
    severity_counts = {}
    for f in findings:
        s = f.get("severity", "info")
        severity_counts[s] = severity_counts.get(s, 0) + 1

    try:
        scan_date = datetime.fromisoformat(created_at).strftime("%B %d, %Y %H:%M UTC")
    except Exception:
        scan_date = created_at

    env = Environment()
    tmpl = env.from_string(PDF_TEMPLATE)
    html_content = tmpl.render(
        url=url,
        findings=findings,
        scan_date=scan_date,
        report_date=datetime.utcnow().strftime("%B %d, %Y %H:%M UTC"),
        severity_colors=severity_colors,
        severity_counts=severity_counts,
    )

    out_path = os.path.join(REPORTS_DIR, f"{scan_id}.pdf")
    HTML(string=html_content).write_pdf(out_path)
    return out_path
