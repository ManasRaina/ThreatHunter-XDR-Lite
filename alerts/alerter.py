"""
Alert generation engine.

Evaluates scored IOCs and creates alerts when:
  - score exceeds MIN_SCORE_FOR_RULE threshold
  - severity is high or critical
  - the same indicator value appears across multiple feeds
"""

import logging

from config import MIN_SCORE_FOR_RULE
from db.database import fetchall, get_db

from alerts.alert_service import create_alert, deduplicate_alert

logger = logging.getLogger("tip.alerts")

SOURCE_SCORE = "score_threshold"
SOURCE_SEVERITY = "severity"
SOURCE_MULTI_FEED = "multi_feed"


def _feed_count_for_value(value: str) -> int:
    row = fetchall(
        """
        SELECT COUNT(DISTINCT source_feed) AS feed_count
        FROM iocs
        WHERE value = ?
        """,
        (value,),
    )
    return row[0]["feed_count"] if row else 0


def _evaluate_ioc(ioc: dict) -> list[dict]:
    """Return alert payloads that apply to a single scored IOC."""
    alerts: list[dict] = []
    ioc_id = ioc["id"]
    value = ioc["value"]
    score = ioc["score"]
    confidence = (ioc["confidence"] or "low").lower()
    feed = ioc.get("source_feed") or "unknown"
    ioc_type = ioc.get("type") or "unknown"

    if score >= MIN_SCORE_FOR_RULE:
        alerts.append({
            "ioc_id": ioc_id,
            "severity": confidence if confidence in ("high", "critical") else "high",
            "title": "Score threshold exceeded",
            "description": (
                f"IOC {value} ({ioc_type}) scored {score}/100, "
                f"exceeding threshold of {MIN_SCORE_FOR_RULE}. Feed: {feed}."
            ),
            "source": SOURCE_SCORE,
        })

    if confidence in ("high", "critical"):
        alerts.append({
            "ioc_id": ioc_id,
            "severity": confidence,
            "title": f"{confidence.title()} severity IOC detected",
            "description": (
                f"IOC {value} ({ioc_type}) classified as {confidence} "
                f"with score {score}/100. Feed: {feed}."
            ),
            "source": SOURCE_SEVERITY,
        })

    feed_count = _feed_count_for_value(value)
    if feed_count > 1:
        alerts.append({
            "ioc_id": ioc_id,
            "severity": "high" if confidence not in ("high", "critical") else confidence,
            "title": "Multi-feed correlation detected",
            "description": (
                f"Indicator {value} ({ioc_type}) observed across "
                f"{feed_count} distinct feeds."
            ),
            "source": SOURCE_MULTI_FEED,
        })

    return alerts


def run() -> dict:
    """
    Scan all scored IOCs and create deduplicated alerts.
    Returns summary counts.
    """
    conn = get_db()
    rows = conn.execute(
        """
        SELECT i.id, i.value, i.type, i.source_feed,
               s.score, s.confidence
        FROM iocs i
        JOIN scores s ON s.ioc_id = i.id
        ORDER BY s.score DESC
        """
    ).fetchall()
    conn.close()

    created = 0
    skipped = 0
    evaluated = len(rows)

    logger.info("[Alerter] Evaluating %s scored IOCs for alerts ...", evaluated)

    for row in rows:
        ioc = dict(row)
        for payload in _evaluate_ioc(ioc):
            if deduplicate_alert(payload["ioc_id"], payload["title"], payload["source"]):
                skipped += 1
                continue
            create_alert(
                ioc_id=payload["ioc_id"],
                severity=payload["severity"],
                title=payload["title"],
                description=payload["description"],
                source=payload["source"],
            )
            created += 1

    summary = {
        "evaluated": evaluated,
        "alerts_created": created,
        "alerts_skipped": skipped,
    }
    logger.info(
        "[Alerter] Done — %s created, %s skipped (duplicates).",
        created,
        skipped,
    )
    print(
        f"[Alerter] Done — {created} alerts created, "
        f"{skipped} duplicates skipped ({evaluated} IOCs evaluated)."
    )
    return summary
