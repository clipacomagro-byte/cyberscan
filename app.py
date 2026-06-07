import os
import uuid
import re
from datetime import datetime
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    jsonify,
    send_file,
    abort,
)
from database import init_db, get_scan, get_all_scans
from scanner import start_scan_thread
from report import generate_pdf, REPORTS_DIR

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32))

URL_RE = re.compile(
    r"^https?://"
    r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"
    r"localhost|"
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"(?::\d+)?(?:/?|[/?]\S+)$",
    re.IGNORECASE,
)


def _validate_url(url: str) -> str | None:
    """Return cleaned URL or None if invalid."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if URL_RE.match(url):
        return url
    return None


@app.before_request
def setup():
    init_db()


@app.route("/")
def index():
    history = get_all_scans()
    return render_template("index.html", history=history)


@app.route("/scan", methods=["POST"])
def start_scan():
    url = request.form.get("url", "").strip()
    confirmed = request.form.get("permission_confirmed")

    if not confirmed:
        return render_template(
            "index.html",
            error="You must confirm you have permission to scan this website.",
            history=get_all_scans(),
        )

    clean_url = _validate_url(url)
    if not clean_url:
        return render_template(
            "index.html",
            error="Please enter a valid URL (e.g. https://example.com).",
            history=get_all_scans(),
        )

    scan_id = str(uuid.uuid4())
    start_scan_thread(scan_id, clean_url)
    return redirect(url_for("scan_progress", scan_id=scan_id))


@app.route("/scan/<scan_id>")
def scan_progress(scan_id):
    scan = get_scan(scan_id)
    if scan is None:
        abort(404)
    if scan["status"] == "complete":
        return redirect(url_for("scan_results", scan_id=scan_id))
    if scan["status"] == "error":
        return render_template("progress.html", scan=scan)
    return render_template("progress.html", scan=scan)


@app.route("/scan/<scan_id>/status")
def scan_status(scan_id):
    scan = get_scan(scan_id)
    if scan is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"status": scan["status"], "error": scan.get("error")})


@app.route("/results/<scan_id>")
def scan_results(scan_id):
    scan = get_scan(scan_id)
    if scan is None:
        abort(404)

    severity_order = ["critical", "high", "medium", "low", "info", "unknown"]
    grouped = {s: [] for s in severity_order}
    for f in scan.get("findings", []):
        s = f.get("severity", "unknown")
        if s not in grouped:
            s = "unknown"
        grouped[s].append(f)

    counts = {s: len(v) for s, v in grouped.items()}
    return render_template(
        "results.html",
        scan=scan,
        grouped=grouped,
        counts=counts,
        severity_order=severity_order,
    )


@app.route("/report/<scan_id>")
def download_report(scan_id):
    scan = get_scan(scan_id)
    if scan is None or scan["status"] != "complete":
        abort(404)

    pdf_path = os.path.join(REPORTS_DIR, f"{scan_id}.pdf")
    if not os.path.exists(pdf_path):
        try:
            generate_pdf(
                scan_id,
                scan["url"],
                scan.get("findings", []),
                scan.get("created_at", ""),
            )
        except Exception as e:
            return f"PDF generation failed: {e}", 500

    safe_name = re.sub(r"[^\w.-]", "_", scan["url"].replace("https://", "").replace("http://", ""))
    filename = f"CyberScan_{safe_name}_{scan_id[:8]}.pdf"
    return send_file(pdf_path, as_attachment=True, download_name=filename, mimetype="application/pdf")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5050)), debug=True)
