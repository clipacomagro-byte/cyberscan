import subprocess
import json
import shutil
import threading
from database import create_scan, update_scan_complete, update_scan_error
from checks import run_http_checks

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def _parse_nuclei_jsonl(output: str) -> list:
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        severity = obj.get("info", {}).get("severity", "info").lower()
        name = obj.get("info", {}).get("name", obj.get("template-id", "Unknown"))
        description = obj.get("info", {}).get("description", "Security issue detected.")
        findings.append({
            "id": obj.get("template-id", "unknown"),
            "name": name,
            "category": "CVE / Misconfiguration",
            "severity": severity,
            "status": "vulnerable",
            "matched_at": obj.get("matched-at", obj.get("host", "")),
            "attacker_can": f"Exploit {name}: {description}",
            "attacker_cannot": None,
            "recommendation": "Apply the vendor patch or mitigate as described in the CVE advisory.",
            "detail": description,
            "tags": obj.get("info", {}).get("tags", []),
            "reference": obj.get("info", {}).get("reference", []),
        })
    return findings


def run_scan(scan_id: str, url: str):
    # Always run direct HTTP checks first
    findings = run_http_checks(url)

    # Then try Nuclei for CVEs on top
    nuclei_path = shutil.which("nuclei") or "/usr/local/bin/nuclei"
    try:
        result = subprocess.run(
            [
                nuclei_path,
                "-u", url,
                "-tags", "ssl,headers,misconfiguration,exposed-panels,cves",
                "-rate-limit", "10",
                "-json",           # correct flag for JSONL to stdout
                "-silent",
                "-no-color",
                "-timeout", "10",
                "-retries", "1",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        nuclei_findings = _parse_nuclei_jsonl(result.stdout)
        # Merge: add nuclei findings that aren't already covered by HTTP checks
        existing_ids = {f["id"] for f in findings}
        for nf in nuclei_findings:
            if nf["id"] not in existing_ids:
                findings.append(nf)
    except FileNotFoundError:
        pass  # Nuclei not installed — HTTP checks are enough
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    # Sort by severity
    findings.sort(
        key=lambda f: SEVERITY_ORDER.index(f.get("severity", "unknown"))
        if f.get("severity", "unknown") in SEVERITY_ORDER else 99
    )
    update_scan_complete(scan_id, findings)


def start_scan_thread(scan_id: str, url: str):
    create_scan(scan_id, url)
    t = threading.Thread(target=run_scan, args=(scan_id, url), daemon=True)
    t.start()
