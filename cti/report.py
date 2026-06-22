"""Report generation — self-contained HTML via jinja2 (PDF optional via weasyprint)."""
from __future__ import annotations
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from loguru import logger
from .models import Report

_TPL_DIR = Path(__file__).parent / "templates"


def render_html(report: Report, path: Path) -> None:
    env = Environment(loader=FileSystemLoader(str(_TPL_DIR)), autoescape=select_autoescape(["html"]))
    html = env.get_template("report.html.j2").render(r=report)
    path.write_text(html, encoding="utf-8")
    logger.info(f"HTML report: {path}")


def render_pdf(html_path: Path, pdf_path: Path) -> bool:
    """Optional — only if weasyprint is installed. Returns success."""
    try:
        from weasyprint import HTML  # heavy native deps; optional
    except Exception:
        logger.warning("weasyprint not installed — skipping PDF (HTML report is the primary output).")
        return False
    try:
        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        logger.info(f"PDF report: {pdf_path}")
        return True
    except Exception as e:
        logger.warning(f"PDF generation failed: {e}")
        return False
