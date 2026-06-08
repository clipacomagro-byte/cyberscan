"""
CyberScan Batch Scanner
Loads targets from targets.json, queues scans, generates PDF reports.
Run: python batch.py --tier easy
     python batch.py --sector forex
     python batch.py --all
"""
import json
import time
import uuid
import argparse
import os
import re
import shutil
from database import init_db, create_scan, get_scan
from scanner import run_scan
from report import generate_pdf, REPORTS_DIR

DESKTOP_DIR = os.path.join(os.path.expanduser("~"), "Desktop", "CyberScan Reports")


def export_to_desktop(name: str, domain: str, pdf_src: str):
    """Copy PDF to Desktop/CyberScan Reports/<Company Name>/"""
    company = re.sub(r'[<>:/\\|?*]', '-', name)
    clean_domain = domain.replace("https://","").replace("http://","").replace("www.","").rstrip("/")
    folder = os.path.join(DESKTOP_DIR, company)
    os.makedirs(folder, exist_ok=True)
    dst = os.path.join(folder, f"CyberScan_{clean_domain}.pdf")
    if os.path.exists(pdf_src):
        shutil.copy2(pdf_src, dst)
    return dst

TARGETS_FILE = "targets.json"


def load_targets(tier=None, sector=None):
    with open(TARGETS_FILE) as f:
        data = json.load(f)
    targets = data["targets"]
    if tier:
        targets = [t for t in targets if t.get("tier") == tier]
    if sector:
        targets = [t for t in targets if t.get("sector") == sector]
    return targets


def run_batch(targets, delay=5):
    init_db()
    os.makedirs(REPORTS_DIR, exist_ok=True)
    results = []

    print(f"\n{'='*60}")
    print(f"  CyberScan Batch — {len(targets)} targets queued")
    print(f"{'='*60}\n")

    for i, target in enumerate(targets, 1):
        name   = target["name"]
        domain = target["domain"]
        tier   = target.get("tier", "?")
        sector = target.get("sector", "?")

        print(f"[{i}/{len(targets)}] Scanning {name} ({domain}) [{tier}/{sector}]...")

        scan_id = str(uuid.uuid4())
        try:
            create_scan(scan_id, domain)
            run_scan(scan_id, domain, deep_tls=False)  # Skip SSL Labs in batch — too slow
            scan = get_scan(scan_id)
            findings = scan.get("findings", [])

            vulns    = [f for f in findings if f.get("status") == "vulnerable"]
            criticals = [f for f in vulns if f.get("severity") == "critical"]
            highs     = [f for f in vulns if f.get("severity") == "high"]

            # Generate PDF
            pdf_path = generate_pdf(scan_id, domain, findings, scan.get("created_at", ""))

            results.append({
                "name":     name,
                "domain":   domain,
                "tier":     tier,
                "sector":   sector,
                "scan_id":  scan_id,
                "total":    len(vulns),
                "critical": len(criticals),
                "high":     len(highs),
                "pdf":      pdf_path,
                "status":   "complete",
            })

            desktop_pdf = export_to_desktop(name, domain, pdf_path)
            print(f"  -> {len(vulns)} issues ({len(criticals)} critical, {len(highs)} high) | Desktop: {desktop_pdf}")

        except Exception as e:
            print(f"  -> ERROR: {e}")
            results.append({
                "name": name, "domain": domain,
                "status": "error", "error": str(e)
            })

        if i < len(targets):
            print(f"  Waiting {delay}s before next scan...\n")
            time.sleep(delay)

    # Summary
    print(f"\n{'='*60}")
    print(f"  BATCH COMPLETE — {len(targets)} scanned")
    print(f"{'='*60}")
    completed = [r for r in results if r["status"] == "complete"]
    hot_leads = sorted(
        [r for r in completed if r["critical"] > 0 or r["high"] > 0],
        key=lambda r: r["critical"] * 10 + r["high"],
        reverse=True
    )

    print(f"\n HOT LEADS ({len(hot_leads)} sites with Critical/High issues):\n")
    for r in hot_leads:
        print(f"  {r['name']:30s} | CRIT: {r['critical']} | HIGH: {r['high']} | {r['domain']}")
        print(f"  {'':30s}   PDF: {r['pdf']}")

    # Save summary
    summary_path = os.path.join(REPORTS_DIR, "batch_summary.json")
    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n Full summary saved: {summary_path}")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberScan Batch Scanner")
    parser.add_argument("--tier",   help="Filter by tier: easy, medium, hard")
    parser.add_argument("--sector", help="Filter by sector: forex, gambling")
    parser.add_argument("--all",    action="store_true", help="Scan all targets")
    parser.add_argument("--delay",  type=int, default=5, help="Seconds between scans (default: 5)")
    args = parser.parse_args()

    if not (args.tier or args.sector or args.all):
        parser.print_help()
        print("\nExamples:")
        print("  python batch.py --tier easy")
        print("  python batch.py --sector forex")
        print("  python batch.py --tier medium --sector gambling")
        print("  python batch.py --all --delay 10")
        exit(1)

    targets = load_targets(
        tier=args.tier,
        sector=args.sector if not args.all else None,
    )

    if not targets:
        print("No targets matched your filters.")
        exit(1)

    run_batch(targets, delay=args.delay)
