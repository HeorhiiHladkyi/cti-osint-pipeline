"""Evidence preservation: timestamped artifact tree + SQLite + ZIP archive."""
from __future__ import annotations
import json
import re
import sqlite3
import zipfile
from datetime import datetime
from pathlib import Path
from loguru import logger
from .models import IoCResult, Report


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80]


def make_run_dir(base: str = "output") -> Path:
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run = Path(base) / ts
    (run / "raw").mkdir(parents=True, exist_ok=True)
    logger.info(f"Artifact directory: {run}")
    return run


def save_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def save_raw(run_dir: Path, result: IoCResult) -> None:
    folder = run_dir / "raw" / _safe(result.indicator)
    folder.mkdir(parents=True, exist_ok=True)
    for s in result.sources:
        save_json(folder / f"{s.source}.json", s.model_dump())


def write_sqlite(run_dir: Path, report: Report) -> None:
    db = sqlite3.connect(run_dir / "evidence.sqlite")
    cur = db.cursor()
    cur.execute("CREATE TABLE iocs (indicator TEXT, type TEXT, threat_level TEXT, score INT, confidence TEXT, reasons TEXT)")
    cur.execute("CREATE TABLE sources (indicator TEXT, source TEXT, ok INT, skipped INT, reason TEXT, data TEXT)")
    cur.execute("CREATE TABLE edges (source TEXT, target TEXT, rel TEXT)")
    for r in report.results:
        cur.execute("INSERT INTO iocs VALUES (?,?,?,?,?,?)",
                    (r.indicator, r.type, r.threat_level, r.score, r.confidence, "; ".join(r.reasons)))
        for s in r.sources:
            cur.execute("INSERT INTO sources VALUES (?,?,?,?,?,?)",
                        (r.indicator, s.source, int(s.ok), int(s.skipped), s.reason,
                         json.dumps(s.data, ensure_ascii=False, default=str)))
        for e in r.related:
            cur.execute("INSERT INTO edges VALUES (?,?,?)", (r.indicator, e["target"], e["rel"]))
    db.commit()
    db.close()
    logger.info("SQLite evidence DB written: evidence.sqlite")


def zip_run(run_dir: Path) -> Path:
    archive = run_dir.with_suffix(".zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        for p in run_dir.rglob("*"):
            if p.is_file():
                z.write(p, p.relative_to(run_dir.parent))
    logger.info(f"Evidence archive: {archive}")
    return archive
