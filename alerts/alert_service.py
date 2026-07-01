"""
Alert persistence and query service.
"""

from datetime import datetime, timezone

from db.database import execute, fetchall, fetchone, get_db


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def deduplicate_alert(ioc_id: int, title: str, source: str) -> dict | None:
    """Return an existing alert if the same IOC/title/source was already recorded."""
    return fetchone(
        """
        SELECT id, ioc_id, severity, title, description, source, created_at
        FROM alerts
        WHERE ioc_id = ? AND title = ? AND source = ?
        """,
        (ioc_id, title, source),
    )


def create_alert(
    ioc_id: int,
    severity: str,
    title: str,
    description: str,
    source: str,
) -> dict:
    """
    Insert a new alert unless an identical one already exists.
    Returns the alert row (existing or newly created).
    """
    existing = deduplicate_alert(ioc_id, title, source)
    if existing:
        return existing

    alert_id = execute(
        """
        INSERT INTO alerts (ioc_id, severity, title, description, source, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (ioc_id, severity, title, description, source, _now()),
    )

    alert = fetchone(
        """
        SELECT id, ioc_id, severity, title, description, source, created_at
        FROM alerts
        WHERE id = ?
        """,
        (alert_id,),
    )
    return alert or {
        "id": alert_id,
        "ioc_id": ioc_id,
        "severity": severity,
        "title": title,
        "description": description,
        "source": source,
        "created_at": _now(),
    }


def get_alerts(
    limit: int = 25,
    offset: int = 0,
    severity: str | None = None,
) -> tuple[list[dict], int]:
    """Return paginated alerts with linked IOC context."""
    where = ["1=1"]
    params: list = []

    if severity:
        where.append("a.severity = ?")
        params.append(severity)

    where_clause = " AND ".join(where)

    conn = get_db()
    total = conn.execute(
        f"SELECT COUNT(*) FROM alerts a WHERE {where_clause}",
        params,
    ).fetchone()[0]

    rows = conn.execute(
        f"""
        SELECT a.id, a.ioc_id, a.severity, a.title, a.description, a.source, a.created_at,
               i.value AS ioc_value, i.type AS ioc_type, i.source_feed,
               s.score, s.confidence
        FROM alerts a
        JOIN iocs i ON i.id = a.ioc_id
        LEFT JOIN scores s ON s.ioc_id = a.ioc_id
        WHERE {where_clause}
        ORDER BY a.created_at DESC, a.id DESC
        LIMIT ? OFFSET ?
        """,
        [*params, limit, offset],
    ).fetchall()
    conn.close()

    return [dict(r) for r in rows], total


def get_alert_by_id(alert_id: int) -> dict | None:
    """Return a single alert with IOC and score context."""
    return fetchone(
        """
        SELECT a.id, a.ioc_id, a.severity, a.title, a.description, a.source, a.created_at,
               i.value AS ioc_value, i.type AS ioc_type, i.source_feed, i.malware_family,
               i.first_seen, i.last_seen, i.is_actionable,
               s.score, s.confidence, s.factors_json, s.scored_at
        FROM alerts a
        JOIN iocs i ON i.id = a.ioc_id
        LEFT JOIN scores s ON s.ioc_id = a.ioc_id
        WHERE a.id = ?
        """,
        (alert_id,),
    )
