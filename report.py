import os
from datetime import datetime
from fpdf import FPDF


def _safe(text: str) -> str:
    """Replace Unicode characters unsupported by Helvetica with ASCII equivalents."""
    if not text:
        return ""
    return (
        text
        .replace("—", "--")   # em dash —
        .replace("–", "-")    # en dash –
        .replace("‘", "'")    # left single quote '
        .replace("’", "'")    # right single quote '
        .replace("“", '"')    # left double quote "
        .replace("”", '"')    # right double quote "
        .replace("•", "*")    # bullet •
        .replace(" ", " ")    # non-breaking space
        .replace("…", "...")  # ellipsis …
        .replace("→", "->")   # arrow →
        .replace("é", "e")    # é
        .replace("à", "a")    # à
        .replace("ü", "u")    # ü
        .encode("latin-1", errors="replace").decode("latin-1")
    )

REPORTS_DIR = os.environ.get("REPORTS_DIR", "reports")

SEV_COLORS = {
    "critical": (204, 34,  34),
    "high":     (204, 85,   0),
    "medium":   (170, 119,  0),
    "low":      (34,  102, 170),
    "info":     (85,  102, 136),
    "unknown":  (85,  85,  85),
}


class CyberScanPDF(FPDF):
    def header(self):
        pass

    def footer(self):
        if self.page_no() > 1:
            self.set_y(-14)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(150, 150, 150)
            self.cell(0, 6, f"CyberScan Security Report  |  Page {self.page_no() - 1}  |  Confidential", align="C")

    def cover(self, url, scan_date, report_date, vuln_count, protected_count):
        self.add_page()
        # Dark background
        self.set_fill_color(13, 17, 23)
        self.rect(0, 0, 210, 297, "F")

        # Accent bar top
        self.set_fill_color(0, 212, 255)
        self.rect(0, 0, 210, 3, "F")

        # Logo
        self.set_y(60)
        self.set_font("Helvetica", "B", 36)
        self.set_text_color(0, 212, 255)
        self.cell(0, 14, "CYBERSCAN", align="C", new_x="LMARGIN", new_y="NEXT")

        self.set_font("Helvetica", "", 10)
        self.set_text_color(74, 85, 104)
        self.cell(0, 7, "WEB SECURITY ASSESSMENT REPORT", align="C", new_x="LMARGIN", new_y="NEXT")

        # Divider
        self.ln(14)
        self.set_draw_color(0, 212, 255)
        self.set_line_width(0.5)
        self.line(40, self.get_y(), 170, self.get_y())
        self.ln(16)

        # Title
        self.set_font("Helvetica", "B", 22)
        self.set_text_color(232, 237, 245)
        self.cell(0, 10, "Security Vulnerability Report", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(8)

        # URL box
        self.set_fill_color(15, 25, 40)
        self.set_draw_color(0, 212, 255)
        self.set_line_width(0.3)
        self.set_x(20)
        self.set_font("Helvetica", "", 13)
        self.set_text_color(0, 212, 255)
        url_display = url if len(url) <= 55 else url[:52] + "..."
        self.cell(170, 12, url_display, border=1, align="C", fill=True, new_x="LMARGIN", new_y="NEXT")
        self.ln(24)

        # Stats row
        stats = [
            ("ISSUES FOUND", str(vuln_count), (204, 34, 34)),
            ("PROTECTED",    str(protected_count), (0, 180, 120)),
            ("TOTAL CHECKS", str(vuln_count + protected_count), (0, 212, 255)),
        ]
        box_w = 50
        start_x = (210 - box_w * 3 - 10) / 2
        for i, (label, val, color) in enumerate(stats):
            bx = start_x + i * (box_w + 5)
            self.set_xy(bx, self.get_y())
            self.set_fill_color(20, 30, 50)
            self.set_draw_color(*color)
            self.set_line_width(0.5)
            self.rect(bx, self.get_y(), box_w, 22, "FD")
            self.set_xy(bx, self.get_y() + 3)
            self.set_font("Helvetica", "B", 18)
            self.set_text_color(*color)
            self.cell(box_w, 9, val, align="C", new_x="RIGHT", new_y="TOP")
            self.set_xy(bx, self.get_y() + 13)
            self.set_font("Helvetica", "", 7)
            self.set_text_color(150, 160, 180)
            self.cell(box_w, 5, label, align="C")
        self.ln(34)

        # Meta
        self.set_font("Helvetica", "", 10)
        self.set_text_color(74, 85, 104)
        self.cell(0, 7, f"Scan Date: {scan_date}", align="C", new_x="LMARGIN", new_y="NEXT")
        self.cell(0, 7, f"Report Generated: {report_date}", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(20)

        # Confidential badge
        self.set_x(70)
        self.set_fill_color(13, 17, 23)
        self.set_draw_color(0, 212, 255)
        self.set_line_width(0.4)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(0, 212, 255)
        self.cell(70, 9, "CONFIDENTIAL  |  AUTHORIZED USE ONLY", border=1, align="C")

        # Bottom accent
        self.set_fill_color(0, 212, 255)
        self.rect(0, 294, 210, 3, "F")

    def summary_section(self, url, scan_date, vulnerable, protected):
        self.add_page()
        self.ln(6)

        # Section title
        self._section_title("Executive Summary")
        self.set_font("Helvetica", "", 10)
        self.set_text_color(50, 50, 50)
        intro = (
            f"CyberScan performed an automated security assessment of {url} on {scan_date}. "
            "The assessment covered SSL/TLS configuration, HTTP security headers, CORS policy, "
            "session cookie security, rate limiting, promo/bonus endpoint exposure, "
            "JavaScript secret leakage, subdomain enumeration, exposed administrative panels, "
            "and known CVE vulnerabilities."
        )
        self.multi_cell(0, 6, _safe(intro))
        self.ln(4)

        if vulnerable:
            crit = sum(1 for f in vulnerable if f.get("severity") == "critical")
            high = sum(1 for f in vulnerable if f.get("severity") == "high")
            summary = f"{len(vulnerable)} security issue(s) identified. "
            if crit: summary += f"{crit} Critical issue(s) require immediate remediation. "
            if high: summary += f"{high} High risk finding(s) should be addressed promptly."
            self.set_text_color(180, 30, 30)
            self.multi_cell(0, 6, summary)
        else:
            self.set_text_color(0, 150, 100)
            self.multi_cell(0, 6, "No security issues detected. The site demonstrates a strong security baseline.")
        self.ln(6)

        # Severity counts bar
        sev_counts = {}
        for f in vulnerable:
            s = f.get("severity", "info")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        col_w = 32
        sx = 14
        for sev, rgb in SEV_COLORS.items():
            count = sev_counts.get(sev, 0)
            self.set_xy(sx, self.get_y())
            self.set_fill_color(*rgb)
            self.set_text_color(255, 255, 255)
            self.set_font("Helvetica", "B", 14)
            self.rect(sx, self.get_y(), col_w, 14, "F")
            self.cell(col_w, 14, str(count), align="C")
            self.set_xy(sx, self.get_y() + 14)
            self.set_font("Helvetica", "", 6)
            self.set_text_color(*rgb)
            self.cell(col_w, 4, sev.upper(), align="C")
            sx += col_w + 2
        self.ln(22)

    def findings_section(self, findings):
        if not findings:
            return
        self._section_title("Security Issues Found")

        for f in findings:
            sev = f.get("severity", "info")
            rgb = SEV_COLORS.get(sev, (85, 85, 85))
            name = f.get("name", "Unknown")
            category = f.get("category", "")

            # Check page space
            if self.get_y() > 240:
                self.add_page()
                self.ln(6)

            # Finding header bar
            self.set_fill_color(*rgb)
            self.set_text_color(255, 255, 255)
            self.set_font("Helvetica", "B", 10)
            y0 = self.get_y()
            self.set_x(14)
            self.cell(0, 8, _safe(f"  {name}"), fill=True, new_x="LMARGIN", new_y="NEXT")

            # Severity badge on right — go back and write it
            self.set_xy(14, y0)
            self.set_font("Helvetica", "B", 7)
            self.cell(182, 8, sev.upper(), align="R", new_x="LMARGIN", new_y="NEXT")

            # Category
            self.set_fill_color(240, 243, 250)
            self.set_text_color(100, 110, 130)
            self.set_font("Helvetica", "I", 8)
            self.set_x(14)
            self.cell(182, 5, _safe(f"  {category}"), fill=True, new_x="LMARGIN", new_y="NEXT")

            # Body
            self.set_fill_color(252, 252, 255)
            body_y = self.get_y()

            if f.get("attacker_can"):
                self._impact_row("ATTACKER CAN", _safe(f["attacker_can"]), (220, 50, 50), (255, 240, 240))

            if f.get("burp"):
                burp = f["burp"]
                tool_line = f"Tool: {burp.get('tool','')}"
                self._impact_row("BURP SUITE ATTACK", _safe(tool_line + "\n" + burp.get("how","")), (180, 80, 0), (255, 248, 235))

            if f.get("recommendation"):
                self._impact_row("FIX", _safe(f["recommendation"]), (0, 100, 180), (240, 248, 255))

            if f.get("detail"):
                self.set_x(14)
                self.set_font("Courier", "", 7)
                self.set_text_color(120, 120, 120)
                self.cell(182, 5, _safe(f"  {f['detail'][:120]}"), new_x="LMARGIN", new_y="NEXT")

            self.ln(4)

    def protected_section(self, protected):
        if not protected:
            return
        if self.get_y() > 220:
            self.add_page()
            self.ln(6)
        self._section_title("Passing Security Checks")
        for f in protected:
            if self.get_y() > 265:
                self.add_page()
                self.ln(6)
            self.set_x(14)
            self.set_fill_color(240, 255, 248)
            self.set_draw_color(0, 180, 120)
            self.set_line_width(0.3)
            name = f.get("name", "")
            cannot = f.get("attacker_cannot", "")
            self.set_font("Helvetica", "B", 9)
            self.set_text_color(0, 130, 80)
            self.cell(5, 7, "", fill=True)
            self.cell(177, 7, _safe(f"  {name}"), fill=True, new_x="LMARGIN", new_y="NEXT")
            if cannot:
                self.set_x(19)
                self.set_font("Helvetica", "", 8)
                self.set_text_color(80, 80, 80)
                self.multi_cell(177, 5, _safe(f"Attacker CANNOT: {cannot}"))
            self.ln(2)

    def _section_title(self, title):
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(15, 52, 96)
        self.set_draw_color(0, 212, 255)
        self.set_line_width(0.6)
        self.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        self.line(14, self.get_y(), 196, self.get_y())
        self.ln(5)

    def _impact_row(self, label, text, label_rgb, bg_rgb):
        self.set_x(14)
        self.set_fill_color(*bg_rgb)
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*label_rgb)
        self.cell(182, 5, _safe(f"  {label}"), fill=True, new_x="LMARGIN", new_y="NEXT")
        self.set_x(14)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(50, 50, 50)
        self.multi_cell(182, 5, _safe(f"  {text}"), fill=True)


def generate_pdf(scan_id: str, url: str, findings: list, created_at: str) -> str:
    os.makedirs(REPORTS_DIR, exist_ok=True)

    try:
        scan_date = datetime.fromisoformat(created_at).strftime("%B %d, %Y %H:%M UTC")
    except Exception:
        scan_date = created_at
    report_date = datetime.utcnow().strftime("%B %d, %Y %H:%M UTC")

    vulnerable = [f for f in findings if f.get("status") == "vulnerable"]
    protected  = [f for f in findings if f.get("status") == "protected"]

    pdf = CyberScanPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(14, 14, 14)

    pdf.cover(url, scan_date, report_date, len(vulnerable), len(protected))
    pdf.summary_section(url, scan_date, vulnerable, protected)
    pdf.findings_section(vulnerable)
    pdf.protected_section(protected)

    out_path = os.path.join(REPORTS_DIR, f"{scan_id}.pdf")
    pdf.output(out_path)
    return out_path
