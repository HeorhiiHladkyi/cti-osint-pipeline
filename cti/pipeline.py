"""Orchestrates the 3 mandatory steps: collect -> store -> analyze & report."""
from __future__ import annotations
import sys
from pathlib import Path
from loguru import logger
from tqdm import tqdm

from .config import settings
from .models import IoCResult, Report
from .ioc import detect_type
from .collectors import collectors_for
from .scoring import score_ioc
from . import graph as graphmod
from . import stix as stixmod
from . import storage, report as reportmod


def _setup_logging(run_dir: Path) -> None:
    logger.remove()
    logger.add(sys.stderr, level="INFO", format="<level>{level: <8}</level> | {message}")
    logger.add(run_dir / "run.log", level="INFO",
               format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {message}")


def run_pipeline(indicators: list[str], base: str = "output") -> tuple[Report, dict]:
    run_dir = storage.make_run_dir(base)
    _setup_logging(run_dir)
    logger.info(f"Keys present: {settings.key_status()}")

    # ── Step 1: COLLECTION ──────────────────────────────────────────────
    results: list[IoCResult] = []
    for raw in tqdm(indicators, desc="Collecting", unit="ioc"):
        itype = detect_type(raw)
        if itype == "unknown":
            logger.warning(f"Skipping unrecognized indicator: {raw}")
            continue
        res = IoCResult(indicator=raw, type=itype)  # type: ignore
        for name, fn in collectors_for(itype):
            try:
                res.sources.append(fn(raw, itype))
            except Exception as e:  # never let one source crash the run
                logger.error(f"[{name}] crashed on {raw}: {e}")
        # ── Step 2: STORAGE (per-IoC raw artifacts) ─────────────────────
        storage.save_raw(run_dir, res)
        results.append(res)

    # ── Step 3: ANALYSIS & REPORT ───────────────────────────────────────
    for r in results:
        score_ioc(r)
    g = graphmod.build_graph(results)
    report = Report(run_dir=str(run_dir), inputs=indicators, key_status=settings.key_status(), results=results)

    # machine-readable + evidence artifacts
    storage.save_json(run_dir / "iocs.json", stixmod.to_ioc_json(results))
    storage.save_json(run_dir / "stix_bundle.json", stixmod.to_stix_bundle(results))
    storage.save_json(run_dir / "graph.json", graphmod.export_json(g))
    storage.write_sqlite(run_dir, report)
    try:
        graphmod.render_pyvis(g, str(run_dir / "graph.html"))
        logger.info("Interactive graph: graph.html")
    except Exception as e:
        logger.warning(f"pyvis graph skipped: {e}")

    html_path = run_dir / "report.html"
    reportmod.render_html(report, html_path)
    reportmod.render_pdf(html_path, run_dir / "report.pdf")  # optional

    archive = storage.zip_run(run_dir)
    paths = {
        "run_dir": str(run_dir), "report_html": str(html_path),
        "graph_html": str(run_dir / "graph.html"), "stix": str(run_dir / "stix_bundle.json"),
        "iocs_json": str(run_dir / "iocs.json"), "archive": str(archive),
    }
    logger.info(f"Done. Overall threat level: {report.overall.upper()}")
    return report, paths
