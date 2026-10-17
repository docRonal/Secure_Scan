"""Aggregate scan findings and render HTML, CSV, and PDF reports."""
import csv
import io
from pathlib import Path

from fpdf import FPDF
from fpdf.enums import XPos, YPos
from jinja2 import Environment, FileSystemLoader
from sqlalchemy.orm import Session

from app.models import ScanJob, Finding

SEVERITY_WEIGHT = {
    "info": 0,
    "low": 1,
    "medium": 4,
    "high": 8,
    "critical": 15,
}

# RGB color values for PDF output.
SEVERITY_COLOR_RGB = {
    "info": (139, 151, 163),
    "low": (62, 143, 176),
    "medium": (216, 162, 58),
    "high": (217, 102, 43),
    "critical": (194, 59, 59),
}

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
_env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=True)


def build_report(db: Session, scan_job_id: int) -> dict:
    scan_job: ScanJob = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
    if scan_job is None:
        raise ValueError(f"Scan job {scan_job_id} not found")

    findings: list[Finding] = (
        db.query(Finding).filter(Finding.scan_id == scan_job_id).all()
    )

    severity_counts = {k: 0 for k in SEVERITY_WEIGHT}
    for f in findings:
        severity_counts[f.severity.value] += 1

    risk_score = sum(SEVERITY_WEIGHT[f.severity.value] for f in findings)

    return {
        "scan_id": scan_job.id,
        "domain": scan_job.asset.domain,
        "scan_type": scan_job.scan_type.value,
        "status": scan_job.status.value,
        "error_message": scan_job.error_message,
        "generated_at": scan_job.completed_at.isoformat() if scan_job.completed_at else None,
        "risk_score": risk_score,
        "severity_counts": severity_counts,
        "findings": [
            {
                "checker": f.checker,
                "title": f.title,
                "severity": f.severity.value,
                "description": f.description,
                "recommendation": f.recommendation,
                "owasp_category": f.owasp_category,
                "cwe_id": f.cwe_id,
                "evidence": f.evidence,
            }
            for f in findings
        ],
    }


def render_html_report(report: dict) -> str:
    template = _env.get_template("report.html")
    return template.render(report=report)


def render_csv_report(report: dict) -> str:
    """Render findings as CSV."""
    buf = io.StringIO()
    writer = csv.writer(buf)

    def safe_cell(value: str | None) -> str:
        text = value or ""
        if text.lstrip(" \t\r\n\x00").startswith(("=", "+", "-", "@")):
            return f"'{text}"
        return text

    writer.writerow(
        ["severity", "title", "checker", "owasp_category", "cwe_id", "description", "recommendation", "evidence"]
    )
    for f in report["findings"]:
        writer.writerow(
            [
                safe_cell(f["severity"]), safe_cell(f["title"]), safe_cell(f["checker"]),
                safe_cell(f["owasp_category"]), safe_cell(f["cwe_id"]),
                safe_cell(f["description"]), safe_cell(f["recommendation"]), safe_cell(f["evidence"]),
            ]
        )
    return buf.getvalue()


_FONTS_DIR = Path(__file__).resolve().parent.parent / "assets" / "fonts"


class _ReportPDF(FPDF):
    def header(self):
        self.set_font("DejaVu", "B", 14)
        self.set_text_color(27, 42, 74)  # Navy.
        self.cell(0, 10, "SecureScan AI — отчёт по сканированию", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(15, 111, 168)  # Accent.
        self.set_line_width(0.5)
        self.line(10, 20, 200, 20)
        self.ln(6)

    def footer(self):
        self.set_y(-15)
        self.set_font("DejaVu", "", 8)
        self.set_text_color(91, 103, 112)
        self.cell(0, 10, f"Стр. {self.page_no()}", align="C")


def render_pdf_report(report: dict) -> bytes:
    """Render the report PDF using bundled DejaVu fonts."""
    pdf = _ReportPDF()
    pdf.add_font("DejaVu", "", str(_FONTS_DIR / "DejaVuSans.ttf"))
    pdf.add_font("DejaVu", "B", str(_FONTS_DIR / "DejaVuSans-Bold.ttf"))
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    pdf.set_font("DejaVu", "", 10)
    pdf.set_text_color(91, 103, 112)
    meta = f"Скан #{report['scan_id']} · {report['domain']} · тип: {report['scan_type']} · статус: {report['status']}"
    pdf.multi_cell(0, 6, meta)
    pdf.ln(2)

    if report.get("error_message"):
        if report["status"] == "cancelled":
            pdf.set_fill_color(235, 235, 235)
            pdf.set_text_color(91, 103, 112)
            label = "Скан остановлен"
        else:
            pdf.set_fill_color(255, 235, 235)
            pdf.set_text_color(194, 59, 59)
            label = "Скан заблокирован" if report["status"] == "blocked_unverified" else "Ошибка скана"
        pdf.set_font("DejaVu", "B", 10)
        pdf.multi_cell(0, 6, f"{label}: {report['error_message']}", fill=True)
        pdf.ln(3)

    pdf.set_text_color(27, 42, 74)
    pdf.set_font("DejaVu", "B", 20)
    pdf.cell(0, 12, f"Риск-скор: {report['risk_score']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("DejaVu", "", 10)
    pdf.set_text_color(0, 0, 0)
    counts = report["severity_counts"]
    pdf.cell(
        0, 8,
        f"critical: {counts['critical']}  ·  high: {counts['high']}  ·  medium: {counts['medium']}  ·  "
        f"low: {counts['low']}  ·  info: {counts['info']}",
        new_x=XPos.LMARGIN, new_y=YPos.NEXT,
    )
    pdf.ln(4)

    pdf.set_font("DejaVu", "B", 13)
    pdf.cell(0, 8, "Находки", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)

    if not report["findings"]:
        pdf.set_font("DejaVu", "", 10)
        pdf.cell(0, 8, "Находок нет.")

    for f in report["findings"]:
        color = SEVERITY_COLOR_RGB.get(f["severity"], (0, 0, 0))

        pdf.set_font("DejaVu", "B", 10)
        pdf.set_text_color(*color)
        pdf.cell(0, 7, f"[{f['severity'].upper()}] {f['title']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_font("DejaVu", "", 9)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 5.5, f["description"])

        if f["recommendation"]:
            pdf.set_text_color(15, 111, 168)
            pdf.multi_cell(0, 5.5, f"Рекомендация: {f['recommendation']}")

        pdf.set_text_color(139, 151, 163)
        pdf.set_font("DejaVu", "", 8)
        tags = f["checker"]
        if f["owasp_category"]:
            tags += f" · OWASP {f['owasp_category']}"
        if f["cwe_id"]:
            tags += f" · {f['cwe_id']}"
        pdf.multi_cell(0, 5, tags)
        pdf.ln(3)

    return bytes(pdf.output())
