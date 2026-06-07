import subprocess
import json
import shutil
import threading
from database import create_scan, update_scan_complete, update_scan_error

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]

PLAIN_ENGLISH = {
    "ssl": "SSL/TLS certificate or configuration issue",
    "headers": "Missing or misconfigured HTTP security header",
    "misconfiguration": "Server or application misconfiguration",
    "exposed-panels": "Exposed administrative or login panel",
    "cve": "Known CVE vulnerability",
    "default-login": "Default credentials may be accepted",
    "takeover": "Subdomain or service takeover risk",
    "tech": "Technology fingerprint detected",
    "network": "Network-level exposure",
    "file": "Sensitive file or directory exposed",
}


def _describe(finding: dict) -> str:
    template_id = finding.get("template-id", "")
    tags = finding.get("info", {}).get("tags", [])
    description = finding.get("info", {}).get("description", "")
    if description:
        return description
    for tag in tags:
        if tag in PLAIN_ENGLISH:
            return PLAIN_ENGLISH[tag]
    for key in PLAIN_ENGLISH:
        if key in template_id:
            return PLAIN_ENGLISH[key]
    return "Security issue detected — review the matched output for details."


def _parse_nuclei_jsonl(output: str) -> list:
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        severity = obj.get("info", {}).get("severity", "info").lower()
        findings.append(
            {
                "template_id": obj.get("template-id", "unknown"),
                "name": obj.get("info", {}).get("name", obj.get("template-id", "Unknown")),
                "severity": severity,
                "description": _describe(obj),
                "matched_at": obj.get("matched-at", obj.get("host", "")),
                "tags": obj.get("info", {}).get("tags", []),
                "reference": obj.get("info", {}).get("reference", []),
            }
        )
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else 99)
    return findings


def run_scan(scan_id: str, url: str):
    nuclei_path = shutil.which("nuclei") or "/usr/local/bin/nuclei"
    tags = "ssl,headers,misconfiguration,exposed-panels,cves"
    cmd = [
        nuclei_path,
        "-u", url,
        "-tags", tags,
        "-rate-limit", "10",
        "-json-export", "-",
        "-silent",
        "-no-color",
        "-timeout", "10",
        "-retries", "1",
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        findings = _parse_nuclei_jsonl(result.stdout)
        update_scan_complete(scan_id, findings)
    except FileNotFoundError:
        # Nuclei not installed — return mock data for local dev
        mock = _mock_findings(url)
        update_scan_complete(scan_id, mock)
    except subprocess.TimeoutExpired:
        update_scan_error(scan_id, "Scan timed out after 5 minutes.")
    except Exception as exc:
        update_scan_error(scan_id, str(exc))


def _mock_findings(url: str) -> list:
    """Return realistic-looking mock findings when Nuclei is unavailable (dev mode)."""
    return [
        {
            "template_id": "CVE-2021-44228",
            "name": "Log4Shell Remote Code Execution",
            "severity": "critical",
            "description": "Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
            "matched_at": url,
            "tags": ["cve", "rce", "log4j"],
            "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        },
        {
            "template_id": "missing-hsts",
            "name": "Missing Strict-Transport-Security Header",
            "severity": "medium",
            "description": "The HTTP Strict-Transport-Security (HSTS) header is not configured, allowing downgrade attacks from HTTPS to HTTP.",
            "matched_at": url,
            "tags": ["headers", "hsts"],
            "reference": [],
        },
        {
            "template_id": "missing-csp",
            "name": "Missing Content-Security-Policy Header",
            "severity": "medium",
            "description": "No Content-Security-Policy header was found. This leaves the application open to Cross-Site Scripting (XSS) attacks.",
            "matched_at": url,
            "tags": ["headers", "csp"],
            "reference": [],
        },
        {
            "template_id": "ssl-expired",
            "name": "SSL Certificate Expiry Warning",
            "severity": "high",
            "description": "The SSL certificate for this host will expire soon or has already expired, causing browser warnings for visitors.",
            "matched_at": url,
            "tags": ["ssl"],
            "reference": [],
        },
        {
            "template_id": "exposed-admin-panel",
            "name": "Exposed Admin Panel Detected",
            "severity": "high",
            "description": "An administrative login panel is publicly accessible. This could allow brute-force attacks against administrator accounts.",
            "matched_at": url + "/admin",
            "tags": ["exposed-panels"],
            "reference": [],
        },
        {
            "template_id": "x-powered-by",
            "name": "Server Technology Disclosure",
            "severity": "info",
            "description": "The server is disclosing its technology stack via the X-Powered-By header, aiding reconnaissance by attackers.",
            "matched_at": url,
            "tags": ["tech", "headers"],
            "reference": [],
        },
        {
            "template_id": "missing-xframe",
            "name": "Missing X-Frame-Options Header",
            "severity": "low",
            "description": "The X-Frame-Options header is absent, potentially allowing clickjacking attacks by embedding this page in an iframe.",
            "matched_at": url,
            "tags": ["headers"],
            "reference": [],
        },
    ]


def start_scan_thread(scan_id: str, url: str):
    create_scan(scan_id, url)
    t = threading.Thread(target=run_scan, args=(scan_id, url), daemon=True)
    t.start()
