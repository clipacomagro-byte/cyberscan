"""
Direct HTTP security checks — always run regardless of Nuclei.
Each check returns a finding dict with attacker impact narrative.
"""
import ssl
import socket
import urllib.request
import urllib.error
import json
from datetime import datetime, timezone

TIMEOUT = 10

CHECKS = [
    {
        "id": "hsts",
        "name": "HTTP Strict Transport Security (HSTS)",
        "category": "Transport Security",
        "severity_fail": "high",
        "header": "strict-transport-security",
        "attacker_can": "Intercept your traffic by tricking browsers into using plain HTTP instead of HTTPS — a classic downgrade or man-in-the-middle attack on public Wi-Fi.",
        "attacker_cannot": "Force your browser onto plain HTTP — all connections stay encrypted even if someone tampers with links.",
        "recommendation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    {
        "id": "csp",
        "name": "Content Security Policy (CSP)",
        "category": "Injection Defence",
        "severity_fail": "high",
        "header": "content-security-policy",
        "attacker_can": "Inject malicious scripts into your pages (Cross-Site Scripting / XSS) and steal session cookies, credentials, or redirect users to phishing sites.",
        "attacker_cannot": "Run unauthorised scripts on your pages — the browser blocks anything not on your approved list.",
        "recommendation": "Add a Content-Security-Policy header defining trusted script/style sources.",
    },
    {
        "id": "xframe",
        "name": "Clickjacking Protection (X-Frame-Options)",
        "category": "UI Redress",
        "severity_fail": "medium",
        "header": "x-frame-options",
        "attacker_can": "Load your website invisibly inside an iframe on a malicious page and trick users into clicking buttons they can't see — stealing clicks, approving transactions, or changing settings.",
        "attacker_cannot": "Embed your site in a hidden iframe — browsers refuse to load it inside other pages.",
        "recommendation": "Add header: X-Frame-Options: DENY (or SAMEORIGIN if framing on your own domain is needed).",
    },
    {
        "id": "xcto",
        "name": "MIME-Type Sniffing Protection (X-Content-Type-Options)",
        "category": "Content Security",
        "severity_fail": "medium",
        "header": "x-content-type-options",
        "attacker_can": "Upload a file (e.g. an image) containing hidden JavaScript and trick older browsers into executing it as a script by exploiting MIME-type guessing.",
        "attacker_cannot": "Trick browsers into misinterpreting file types — content is always treated as declared.",
        "recommendation": "Add header: X-Content-Type-Options: nosniff",
    },
    {
        "id": "referrer",
        "name": "Referrer Policy",
        "category": "Privacy & Info Leakage",
        "severity_fail": "low",
        "header": "referrer-policy",
        "attacker_can": "See the full URL your users came from (including sensitive path or query parameters) by reading the Referer header your site leaks to third-party resources.",
        "attacker_cannot": "Harvest URL paths from your visitors via the Referer header — the policy controls exactly what gets shared.",
        "recommendation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
        "id": "permissions",
        "name": "Permissions Policy",
        "category": "Browser Feature Control",
        "severity_fail": "low",
        "header": "permissions-policy",
        "attacker_can": "Abuse browser features like camera, microphone, or geolocation if malicious code runs on your site — there are no restrictions in place to block it.",
        "attacker_cannot": "Silently access camera, microphone, or location via injected scripts — browser features are locked down by policy.",
        "recommendation": "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
    {
        "id": "server_disclosure",
        "name": "Server Technology Disclosure",
        "category": "Information Leakage",
        "severity_fail": "info",
        "header": None,  # custom check
        "attacker_can": "Identify exactly which web server and version you're running, then look up known exploits for that specific version to target you precisely.",
        "attacker_cannot": "Fingerprint your server stack from response headers — your technology choices stay private.",
        "recommendation": "Remove or obscure the Server and X-Powered-By headers in your web server config.",
    },
]


def _fetch(url: str):
    """Return (response_headers_dict, status_code, final_url) or raise."""
    req = urllib.request.Request(url, headers={"User-Agent": "CyberScan/1.0 Security Audit"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return headers, resp.status, resp.url


def _check_ssl(url: str) -> dict:
    """Check SSL certificate validity and expiry."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return {
            "id": "ssl",
            "name": "HTTPS / SSL Encryption",
            "category": "Transport Security",
            "severity": "critical",
            "status": "vulnerable",
            "matched_at": url,
            "attacker_can": "Intercept ALL traffic between your users and the server in plain text — passwords, session tokens, personal data — because no encryption is in use.",
            "attacker_cannot": None,
            "recommendation": "Enable HTTPS by installing a TLS certificate (free via Let's Encrypt).",
            "detail": "Site is not served over HTTPS.",
        }
    hostname = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, port), timeout=TIMEOUT), server_hostname=hostname) as s:
            cert = s.getpeercert()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
        if days_left < 0:
            return {
                "id": "ssl",
                "name": "HTTPS / SSL Encryption",
                "category": "Transport Security",
                "severity": "critical",
                "status": "vulnerable",
                "matched_at": url,
                "attacker_can": "Trigger scary browser security warnings for all visitors and potentially intercept traffic — the certificate has expired so HTTPS trust is broken.",
                "attacker_cannot": None,
                "recommendation": "Renew your TLS certificate immediately.",
                "detail": f"Certificate expired {abs(days_left)} days ago.",
            }
        if days_left < 30:
            return {
                "id": "ssl",
                "name": "HTTPS / SSL Encryption",
                "category": "Transport Security",
                "severity": "high",
                "status": "vulnerable",
                "matched_at": url,
                "attacker_can": "Exploit the upcoming certificate expiry — once it expires, all HTTPS trust breaks and users see security warnings.",
                "attacker_cannot": None,
                "recommendation": f"Renew your TLS certificate — it expires in {days_left} days.",
                "detail": f"Certificate expires in {days_left} days.",
            }
        return {
            "id": "ssl",
            "name": "HTTPS / SSL Encryption",
            "category": "Transport Security",
            "severity": "info",
            "status": "protected",
            "matched_at": url,
            "attacker_can": None,
            "attacker_cannot": "Intercept traffic in plain text — the connection is encrypted with a valid certificate.",
            "recommendation": None,
            "detail": f"Valid certificate, expires in {days_left} days.",
        }
    except ssl.SSLCertVerificationError as e:
        return {
            "id": "ssl",
            "name": "HTTPS / SSL Encryption",
            "category": "Transport Security",
            "severity": "critical",
            "status": "vulnerable",
            "matched_at": url,
            "attacker_can": "Present a fake certificate and intercept encrypted traffic — browsers will warn users that the connection is not trusted.",
            "attacker_cannot": None,
            "recommendation": "Fix the SSL certificate — ensure it's from a trusted CA and matches the domain.",
            "detail": f"SSL verification failed: {e}",
        }
    except Exception as e:
        return {
            "id": "ssl",
            "name": "HTTPS / SSL Encryption",
            "category": "Transport Security",
            "severity": "info",
            "status": "protected",
            "matched_at": url,
            "attacker_can": None,
            "attacker_cannot": "Intercept traffic — HTTPS is in use.",
            "recommendation": None,
            "detail": "HTTPS in use.",
        }


def _check_exposed_panels(base_url: str) -> list:
    """Check for publicly accessible admin panels."""
    paths = [
        ("/admin", "Admin Panel"),
        ("/wp-admin", "WordPress Admin"),
        ("/wp-login.php", "WordPress Login"),
        ("/administrator", "Joomla Admin"),
        ("/phpmyadmin", "phpMyAdmin"),
        ("/login", "Login Page"),
        ("/.env", "Environment Config File"),
        ("/config.php", "PHP Config File"),
        ("/server-status", "Apache Server Status"),
    ]
    findings = []
    base = base_url.rstrip("/")
    for path, label in paths:
        try:
            req = urllib.request.Request(
                base + path,
                headers={"User-Agent": "CyberScan/1.0 Security Audit"},
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                if r.status == 200:
                    findings.append({
                        "id": f"exposed_{path.strip('/').replace('/', '_') or 'panel'}",
                        "name": f"Exposed {label}",
                        "category": "Exposed Panels",
                        "severity": "critical" if ".env" in path or "config" in path else "high",
                        "status": "vulnerable",
                        "matched_at": base + path,
                        "attacker_can": f"Access the {label} at {path} without any restriction — this could allow full account takeover, credential theft, or database access.",
                        "attacker_cannot": None,
                        "recommendation": f"Restrict access to {path} by IP, add authentication, or remove it if unused.",
                        "detail": f"HTTP 200 returned from {path}",
                    })
        except Exception:
            pass
    return findings


def run_http_checks(url: str) -> list:
    """Run all direct HTTP security checks. Returns list of finding dicts."""
    results = []

    # SSL check first
    results.append(_check_ssl(url))

    # Fetch headers
    try:
        headers, status, final_url = _fetch(url)
    except Exception as e:
        results.append({
            "id": "fetch_error",
            "name": "Site Reachability",
            "category": "Connectivity",
            "severity": "critical",
            "status": "vulnerable",
            "matched_at": url,
            "attacker_can": None,
            "attacker_cannot": None,
            "recommendation": "Verify the URL is correct and the server is running.",
            "detail": f"Could not connect: {e}",
        })
        return results

    # Header checks
    for chk in CHECKS:
        if chk["header"] is None:
            # Server disclosure custom check
            server = headers.get("server", "")
            xpb = headers.get("x-powered-by", "")
            if server or xpb:
                detail_parts = []
                if server:
                    detail_parts.append(f"Server: {server}")
                if xpb:
                    detail_parts.append(f"X-Powered-By: {xpb}")
                results.append({
                    "id": chk["id"],
                    "name": chk["name"],
                    "category": chk["category"],
                    "severity": chk["severity_fail"],
                    "status": "vulnerable",
                    "matched_at": url,
                    "attacker_can": chk["attacker_can"],
                    "attacker_cannot": None,
                    "recommendation": chk["recommendation"],
                    "detail": " | ".join(detail_parts),
                })
            else:
                results.append({
                    "id": chk["id"],
                    "name": chk["name"],
                    "category": chk["category"],
                    "severity": "info",
                    "status": "protected",
                    "matched_at": url,
                    "attacker_can": None,
                    "attacker_cannot": chk["attacker_cannot"],
                    "recommendation": None,
                    "detail": "No server version headers detected.",
                })
        else:
            present = chk["header"] in headers
            results.append({
                "id": chk["id"],
                "name": chk["name"],
                "category": chk["category"],
                "severity": chk["severity_fail"] if not present else "info",
                "status": "protected" if present else "vulnerable",
                "matched_at": url,
                "attacker_can": None if present else chk["attacker_can"],
                "attacker_cannot": chk["attacker_cannot"] if present else None,
                "recommendation": None if present else chk["recommendation"],
                "detail": headers.get(chk["header"], "Header not present"),
            })

    # Exposed panels
    results.extend(_check_exposed_panels(url))

    return results
