from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from cores.Schema.schema_class import Analysis, Reports
from cores.sync_pg_db import SyncSessionLocal
from utils.evidence_score import evidence_score, risk_level_for
from utils.file_type_detect import detect_from_virustotal, is_spoofed, resolve

REPORTS_DIR = Path("reports")


def _load_vt_report(task_id: str | None) -> dict | None:
    if not task_id:
        return None
    path = REPORTS_DIR / f"virustotal-{task_id}.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def backfill(session: Session, *, dry_run: bool = False, force: bool = False) -> dict:
    rows = (
        session.execute(
            select(Analysis, Reports)
            .join(Reports, Analysis.rid == Reports.rid)
            .where(Analysis.deleted_at.is_(None))
        )
        .unique()
        .all()
    )

    tally = {
        "rows": len(rows),
        "detected": 0,
        "detection_source": {},
        "mismatched": 0,
        "score_filled": 0,
        "unreadable_file": 0,
        "still_unknown": 0,
    }

    for analysis, report in rows:
        if analysis.detected_type and not force:
            continue

        detection = None
        if analysis.file_path and Path(analysis.file_path).is_file():
            detection = resolve(analysis.file_path, analysis.file_type, None)
        else:
            tally["unreadable_file"] += 1

        if detection is not None and detection.source == "extension" and detection.category == "unknown":
            vt_detection = detect_from_virustotal(_load_vt_report(analysis.task_id))
            if vt_detection is not None:
                detection = vt_detection

        if detection is None or detection.category == "unknown":
            tally["still_unknown"] += 1
        else:
            tally["detected"] += 1
            tally["detection_source"][detection.source] = (
                tally["detection_source"].get(detection.source, 0) + 1
            )
            mismatch = is_spoofed(analysis.file_type, detection)
            tally["mismatched"] += int(mismatch)
            analysis.detected_type = detection.category
            analysis.detected_source = detection.source
            analysis.file_type_mismatch = mismatch
            report.detected_type = detection.category

        if report.score is None:
            computed = evidence_score(
                {
                    "virustotal": report.virustotal_score,
                    "mobsf": report.mobsf_score,
                    "cape": report.cape_score,
                    "ai": report.rampart_score,
                }
            )
            if computed is not None:
                tally["score_filled"] += 1
                report.score = computed
                report.score_source = "tools"
                if not report.risk_level:
                    report.risk_level = risk_level_for(computed)
                if not report.analysis_summary:
                    report.analysis_summary = (
                        "คะแนนคำนวณจากหลักฐานของเครื่องมือที่ทำงานสำเร็จ "
                        "เนื่องจากการวิเคราะห์ด้วย AI ไม่สำเร็จ"
                    )

    if dry_run:
        session.rollback()
    else:
        session.commit()
    return tally


def main() -> int:
    parser = argparse.ArgumentParser(
        description="One-off backfill of detected_type for rows analysed before the column existed."
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    with SyncSessionLocal() as session:
        tally = backfill(session, dry_run=args.dry_run, force=args.force)

    prefix = "[dry-run] " if args.dry_run else ""
    print(f"{prefix}rows examined        : {tally['rows']}")
    print(f"{prefix}category identified  : {tally['detected']}")
    print(f"{prefix}  by classifier      : {tally['detection_source']}")
    print(f"{prefix}suffix contradicted  : {tally['mismatched']}")
    print(f"{prefix}scores backfilled    : {tally['score_filled']}")
    print(f"{prefix}file gone from disk  : {tally['unreadable_file']}")
    print(f"{prefix}still unclassified   : {tally['still_unknown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
