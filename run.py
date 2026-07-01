"""
Single-command orchestrator.
Usage:
  python run.py                  # full pipeline then start Flask
  python run.py --ingest-only
  python run.py --enrich-only
  python run.py --score-only
  python run.py --rules-only
  python run.py --dashboard-only
  python run.py --pipeline-only  # all pipeline stages, no Flask
"""

import argparse
import json
import sys
import os
from datetime import datetime, timezone

from db.database import init_db, get_db
from config import FLASK_HOST, FLASK_PORT

os.makedirs("output/sigma_rules", exist_ok=True)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _write_pipeline_run(stage: str, status: str, summary: dict, started: str) -> None:
    conn = get_db()
    conn.execute(
        """
        INSERT INTO pipeline_runs (started_at, finished_at, stage, status, summary_json)
        VALUES (?, ?, ?, ?, ?)
        """,
        (started, _now(), stage, status, json.dumps(summary)),
    )
    conn.commit()
    conn.close()


def stage_ingest() -> dict:
    from pipeline.ingestion.feed_manager import run_all
    print("\n══ [1/4] INGESTION ══════════════════════════")
    results = run_all()
    summary = {r["feed"]: {"new": r["iocs_new"], "total": r["iocs_fetched"]} for r in results}
    return summary


def stage_enrich() -> dict:
    from pipeline.enrichment.enricher import run
    print("\n══ [2/4] ENRICHMENT ═════════════════════════")
    return run()


def stage_score() -> dict:
    from pipeline.scoring.scorer import run
    print("\n══ [3/4] SCORING ════════════════════════════")
    return run()


def stage_rules() -> dict:
    from pipeline.rules.sigma_generator import generate as gen_sigma
    from pipeline.rules.spl_generator   import generate as gen_spl
    print("\n══ [4/4] RULE GENERATION ════════════════════")
    s = gen_sigma()
    p = gen_spl()
    return {**s, **p}


def start_dashboard() -> None:
    from dashboard.app import create_app
    app = create_app()
    print(f"\n🛡  Dashboard → http://127.0.0.1:{FLASK_PORT}\n")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="ThreatIntel Platform")
    parser.add_argument("--ingest-only",    action="store_true")
    parser.add_argument("--enrich-only",    action="store_true")
    parser.add_argument("--score-only",     action="store_true")
    parser.add_argument("--rules-only",     action="store_true")
    parser.add_argument("--pipeline-only",  action="store_true")
    parser.add_argument("--dashboard-only", action="store_true")
    args = parser.parse_args()

    print("🛡  ThreatIntel Platform — starting up")
    init_db()

    started = _now()
    summary = {}

    if args.dashboard_only:
        start_dashboard()
        return

    if args.ingest_only:
        summary = stage_ingest()
        _write_pipeline_run("ingest", "success", summary, started)
        return

    if args.enrich_only:
        summary = stage_enrich()
        _write_pipeline_run("enrich", "success", summary, started)
        return

    if args.score_only:
        summary = stage_score()
        _write_pipeline_run("score", "success", summary, started)
        return

    if args.rules_only:
        summary = stage_rules()
        _write_pipeline_run("rules", "success", summary, started)
        return

    # Full pipeline
    try:
        s1 = stage_ingest()
        _write_pipeline_run("ingest", "success", s1, started)

        s2 = stage_enrich()
        _write_pipeline_run("enrich", "success", s2, _now())

        s3 = stage_score()
        _write_pipeline_run("score", "success", s3, _now())

        s4 = stage_rules()
        _write_pipeline_run("rules", "success", s4, _now())

        summary = {**s1, **s2, **s3, **s4}
        _write_pipeline_run("complete", "success", summary, started)
        print("\n✅  Pipeline complete.\n")

    except Exception as exc:
        _write_pipeline_run("error", "error", {"error": str(exc)}, started)
        print(f"\n❌  Pipeline failed: {exc}")
        sys.exit(1)

    if not args.pipeline_only:
        start_dashboard()


if __name__ == "__main__":
    main()