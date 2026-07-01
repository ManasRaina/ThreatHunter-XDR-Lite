"""
Feed manager — runs all enabled ingesters and writes audit rows to feed_runs.
"""

from datetime import datetime, timezone
from db.database import get_db
from config import FEEDS
from pipeline.ingestion import urlhaus, threatfox, otx


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


INGESTERS = {
    "urlhaus":   urlhaus,
    "threatfox": threatfox,
    "otx":       otx,
}


def run_all() -> list[dict]:
    results = []

    for name, module in INGESTERS.items():
        if not FEEDS.get(name, {}).get("enabled", False):
            print(f"[Feeds] {name} disabled — skipping")
            continue

        print(f"[Feeds] Running {name} ...")
        result = module.ingest()
        _write_run(result)
        results.append(result)

        status = result["status"]
        new    = result.get("iocs_new", 0)
        total  = result.get("iocs_fetched", 0)
        print(f"[Feeds] {name}: {new} new / {total} fetched — {status}")

    return results


def _write_run(result: dict) -> None:
    conn = get_db()
    conn.execute(
        """
        INSERT INTO feed_runs
            (feed_name, run_at, iocs_fetched, iocs_new, status, error_msg, duration_sec)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            result["feed"],
            _now(),
            result.get("iocs_fetched", 0),
            result.get("iocs_new", 0),
            result["status"],
            result.get("error_msg"),
            result.get("duration_sec"),
        ),
    )
    conn.commit()
    conn.close()