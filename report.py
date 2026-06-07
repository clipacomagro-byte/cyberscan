import os
from datetime import datetime

REPORTS_DIR = os.environ.get("REPORTS_DIR", "reports")

SEVERITY_COLORS = {
    "critical": "#cc2222",
    "high": "#cc5500",
    "medium": "#aa7700",
    "low": "#2266aa",
    "info": "#556688",
    "unknown": "#555555",
}

PDF_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: Arial, Helvetica, sans-serif; color: #111; background: #fff; font-size: 13px; }

  /* ---- Cover ---- */
  .cover {
    page-break-after: always;
    background: #0d1117;
    color: #fff;
    padding: 80px 60px;
    min-height: 100vh;
  }
  .cover-logo {
    font-size: 42px; font-weight: 900; letter-spacing: 4px;
    color: #00d4ff; margin-bottom: 6px;
  }
  .cover-logo span { color: #4a5568; font-weight: 300; }
  .cover-tagline {
    font-size: 12px; color: #4a5568; letter-spacing: 2px;
    text-transform: uppercase; margin-bottom: 80px;
  }
  .cover h1 { font-size: 32px; font-weight: 700; color: #e8edf5; margin-bottom: 14px; }
  .cover-url { font-size: 18px; color: #00d4ff; margin-bottom: 48px; word-break: break-all; }
  .cover-meta { font-size: 13px; color: #4a5568; line-height: 2.2; }
  .cover-badge {
    display: inline-block; margin-top: 48px;
    padding: 8px 24px; border: 2px solid #00d4ff;
    color: #00d4ff; font-size: 11px; letter-spacing: 2px; text-transform: uppercase;
  }

  /* ---- Content page ---- */
  .page { padding: 52px 56px; }

  h2 {
    font-size: 18px; font-weight: 700; color: #0f3460;
    border-bottom: 2px solid #00d4ff;
    padding-bottom: 8px; margin-bottom: 20px; margin-top: 36px;
  }
  h2:first-child { margin-top: 0; }
  p { line-height: 1.7; color: #333; margin-bottom: 10px; }

  /* Summary table */
  .summary-table { width: 100%; border-collapse: collapse; margin-bottom: 28px; }
  .summary-table td {
    padding: 14px 18px; text-align: center;
    font-weight: 700; font-size: 13px; color: #fff;
  }
  .summary-table .sev-count { font-size: 28px; display: block; font-weight: 900; }

  /* Finding cards */
  .finding {
    border: 1px solid #dde3ee;
    margin-bottom: 14px;
    page-break-inside: avoid;
  }
  .finding-head {
    padding: 12px 16px;
    border-left: 5px solid #ccc;
    display: table; width: 100%;
  }
  .finding-title { font-size: 14px; font-weight: 700; }
  .finding-badge {
    float: right; padding: 3px 10px;
    font-size: 10px; font-weight: 700; text-transform: uppercase;
    color: #fff; letter-spacing: 0.5px;
  }
  .finding-body { padding: 12px 16px; background: #f9faff; }
  .finding-body p { font-size: 12px; margin-bottom: 8px; }

  .can-block { background: #fff0f0; border-left: 3px solid #cc2222; padding: 10px 14px; margin-bottom: 10px; }
  .cannot-block { background: #f0fff8; border-left: 3px solid #007755; padding: 10px 14px; margin-bottom: 10px; }
  .burp-block { background: #fff8f0; border-left: 3px solid #cc5500; padding: 10px 14px; margin-bottom: 10px; }
  .block-label { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px; }
  .block-text { font-size: 12px; color: #333; line-height: 1.6; }
  .fix-text { font-size: 12px; color: #0f3460; font-style: italic; margin-top: 8px; }

  .protected-section h3 { font-size: 13px; font-weight: 700; color: #007755; margin-bottom: 10px; margin-top: 24px; }
  .protected-item { padding: 8px 12px; border-left: 3px solid #007755; margin-bottom: 6px; background: #f0fff8; }
  .protected-item .pi-name { font-size: 12px; font-weight: 700; }
  .protected-item .pi-desc { font-size: 11px; color: #555; margin-top: 3px; }

  .footer {
    margin-top: 40px; padding-top: 14px; border-top: 1px solid #dde3ee;
    font-size: 10px; color: #aaa; text-align: center;
  }
</style>
</head>
<body>

<div class="cover">
  <div class="cover-logo">CYBER<span>SCAN</span></div>
  <div class="cover-tagline">Web Security Assessment Report</div>
  <h1>Security Vulnerability Report</h1>
  <div class="cover-url">{{ url }}</div>
  <div class="cover-meta">
    Scan Date: {{ scan_date }}<br>
    Report Generated: {{ report_date }}<br>
    Total Checks: {{ all_findings|length }}<br>
    Issues Found: {{ vulnerable|length }}<br>
    Protected: {{ protected|length }}
  </div>
  <div class="cover-badge">Confidential — Authorized Use Only</div>
</div>

<div class="page">
  <h2>Executive Summary</h2>
  <p>
    CyberScan performed an automated security assessment of <strong>{{ url }}</strong> on {{ scan_date }}.
    The assessment covered SSL/TLS configuration, HTTP security headers, exposed administrative panels,
    and known CVE vulnerabilities.
  </p>
  {% if vulnerable %}
  <p>
    <strong>{{ vulnerable|length }}</strong> security issue(s) were identified.
    {% if crit_count > 0 %}<strong style="color:#cc2222">{{ crit_count }} Critical</strong> issue(s) require immediate remediation.{% endif %}
    {% if high_count > 0 %}<strong style="color:#cc5500">{{ high_count }} High</strong> risk finding(s) should be addressed promptly.{% endif %}
    Review the findings below and apply recommended fixes to improve your security posture.
  </p>
  {% else %}
  <p>No security issues were detected. The site demonstrates a strong baseline security configuration.
  A manual penetration test is recommended for comprehensive coverage.</p>
  {% endif %}

  <!-- Severity summary -->
  <table class="summary-table">
    <tr>
      {% for sev, color in sev_colors.items() %}
      <td style="background:{{ color }}">
        <span class="sev-count">{{ counts.get(sev, 0) }}</span>
        {{ sev | upper }}
      </td>
      {% endfor %}
    </tr>
  </table>

  <!-- Vulnerable findings -->
  {% if vulnerable %}
  <h2>Issues Found</h2>
  {% for f in vulnerable %}
  {% set color = sev_colors.get(f.severity, '#555') %}
  <div class="finding">
    <div class="finding-head" style="border-left-color:{{ color }};background:{{ color }}11">
      <span class="finding-badge" style="background:{{ color }}">{{ f.severity }}</span>
      <div class="finding-title" style="color:{{ color }}">{{ f.name }}</div>
      <div style="font-size:11px;color:#888;margin-top:2px">{{ f.get('category','') }}</div>
    </div>
    <div class="finding-body">
      {% if f.attacker_can %}
      <div class="can-block">
        <div class="block-label" style="color:#cc2222">An attacker CAN</div>
        <div class="block-text">{{ f.attacker_can }}</div>
      </div>
      {% endif %}
      {% if f.get('burp') %}
      <div class="burp-block">
        <div class="block-label" style="color:#cc5500">Burp Suite Attack — {{ f.burp.tool }}</div>
        <div class="block-text">{{ f.burp.how }}</div>
      </div>
      {% endif %}
      {% if f.recommendation %}
      <p class="fix-text"><strong>Fix:</strong> {{ f.recommendation }}</p>
      {% endif %}
      {% if f.detail %}
      <p style="font-size:11px;color:#888;font-family:monospace;margin-top:6px">{{ f.detail }}</p>
      {% endif %}
    </div>
  </div>
  {% endfor %}
  {% endif %}

  <!-- Protected -->
  {% if protected %}
  <div class="protected-section">
    <h3>Passing Checks ({{ protected|length }})</h3>
    {% for f in protected %}
    <div class="protected-item">
      <div class="pi-name">{{ f.name }}</div>
      {% if f.attacker_cannot %}
      <div class="pi-desc">Attacker CANNOT: {{ f.attacker_cannot }}</div>
      {% endif %}
    </div>
    {% endfor %}
  </div>
  {% endif %}

  <div class="footer">
    Generated by CyberScan &bull; {{ report_date }} &bull; cyberscan-production.up.railway.app
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

    sev_colors = {
        "critical": "#cc2222",
        "high": "#cc5500",
        "medium": "#aa7700",
        "low": "#2266aa",
        "info": "#556688",
    }

    vulnerable = [f for f in findings if f.get("status") == "vulnerable"]
    protected  = [f for f in findings if f.get("status") == "protected"]

    counts = {}
    for f in vulnerable:
        s = f.get("severity", "info")
        counts[s] = counts.get(s, 0) + 1

    crit_count = counts.get("critical", 0)
    high_count = counts.get("high", 0)

    try:
        scan_date = datetime.fromisoformat(created_at).strftime("%B %d, %Y %H:%M UTC")
    except Exception:
        scan_date = created_at

    from jinja2 import Environment as JinjaEnv
    env = JinjaEnv()
    tmpl = env.from_string(PDF_TEMPLATE)
    html_content = tmpl.render(
        url=url,
        all_findings=findings,
        vulnerable=vulnerable,
        protected=protected,
        scan_date=scan_date,
        report_date=datetime.utcnow().strftime("%B %d, %Y %H:%M UTC"),
        sev_colors=sev_colors,
        counts=counts,
        crit_count=crit_count,
        high_count=high_count,
    )

    out_path = os.path.join(REPORTS_DIR, f"{scan_id}.pdf")
    HTML(string=html_content).write_pdf(out_path)
    return out_path
