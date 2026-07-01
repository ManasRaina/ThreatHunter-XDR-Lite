"""
REST API route handlers for the Threat Intelligence Platform.
"""

import logging
import threading
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from db.database import fetchall, fetchone, get_db

logger = logging.getLogger("tip.api")

api_bp = Blueprint("api", __name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_pagination(default_limit: int = 50, max_limit: int = 200) -> tuple[int, int, int]:
    try:
        page = max(int(request.args.get("page", 1)), 1)
        limit = min(int(request.args.get("limit", default_limit)), max_limit)
    except (TypeError, ValueError):
        raise ValueError("Invalid pagination parameters")
    offset = (page - 1) * limit
    return page, limit, offset


# ── IOCs ──────────────────────────────────────────────────────────────────────

@api_bp.route("/iocs")
def list_iocs():
    try:
        page, limit, offset = _parse_pagination()
    except ValueError as exc:
        logger.warning("Invalid pagination on /iocs: %s", exc)
        return jsonify({"error": str(exc)}), 400

    ioc_type = request.args.get("type", "").strip()
    confidence = request.args.get("confidence", "").strip()
    feed = request.args.get("feed", "").strip()
    search = request.args.get("search", "").strip()

    where = ["1=1"]
    params: list = []

    if ioc_type:
        where.append("i.type = ?")
        params.append(ioc_type)
    if feed:
        where.append("i.source_feed = ?")
        params.append(feed)
    if search:
        where.append("i.value LIKE ?")
        params.append(f"%{search}%")
    if confidence:
        where.append("s.confidence = ?")
        params.append(confidence)

    where_clause = " AND ".join(where)

    try:
        conn = get_db()
        total = conn.execute(
            f"""
            SELECT COUNT(*) FROM iocs i
            LEFT JOIN scores s ON s.ioc_id = i.id
            WHERE {where_clause}
            """,
            params,
        ).fetchone()[0]

        rows = conn.execute(
            f"""
            SELECT i.id, i.value, i.type, i.source_feed, i.malware_family,
                   i.first_seen, i.last_seen, i.raw_tags, i.is_actionable,
                   s.score, s.confidence
            FROM iocs i
            LEFT JOIN scores s ON s.ioc_id = i.id
            WHERE {where_clause}
            ORDER BY s.score DESC NULLS LAST, i.last_seen DESC
            LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        ).fetchall()
        conn.close()
    except Exception as exc:
        logger.exception("Database error on GET /iocs")
        return jsonify({"error": "Failed to fetch IOCs"}), 500

    return jsonify({
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit if total else 0,
        "results": [dict(r) for r in rows],
    })


@api_bp.route("/ioc/<int:ioc_id>")
def get_ioc(ioc_id: int):
    try:
        ioc = fetchone(
            """
            SELECT i.*, s.score, s.confidence, s.factors_json, s.scored_at
            FROM iocs i
            LEFT JOIN scores s ON s.ioc_id = i.id
            WHERE i.id = ?
            """,
            (ioc_id,),
        )
        if not ioc:
            logger.info("IOC not found: id=%s", ioc_id)
            return jsonify({"error": "Not found"}), 404

        enrichments = fetchall(
            "SELECT provider, result_json, enriched_at FROM enrichments WHERE ioc_id = ?",
            (ioc_id,),
        )
        rules = fetchall(
            """
            SELECT id, rule_type, rule_id, title, content, file_path, generated_at
            FROM detection_rules
            WHERE ioc_id = ?
            ORDER BY generated_at DESC
            """,
            (ioc_id,),
        )
    except Exception:
        logger.exception("Database error on GET /ioc/%s", ioc_id)
        return jsonify({"error": "Failed to fetch IOC"}), 500

    return jsonify({"ioc": ioc, "enrichments": enrichments, "rules": rules})


# ── Alerts ────────────────────────────────────────────────────────────────────

@api_bp.route("/alerts")
def list_alerts():
    """Return persisted alerts from the alerts table."""
    try:
        page, limit, offset = _parse_pagination(default_limit=25)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    severity = request.args.get("severity", "").strip() or None

    try:
        from alerts.alert_service import get_alerts

        results, total = get_alerts(limit=limit, offset=offset, severity=severity)
    except Exception:
        logger.exception("Database error on GET /alerts")
        return jsonify({"error": "Failed to fetch alerts"}), 500

    return jsonify({
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit if total else 0,
        "results": results,
    })


@api_bp.route("/alert/<int:alert_id>")
def get_alert(alert_id: int):
    """Return a single alert by ID."""
    try:
        from alerts.alert_service import get_alert_by_id

        alert = get_alert_by_id(alert_id)
    except Exception:
        logger.exception("Database error on GET /alert/%s", alert_id)
        return jsonify({"error": "Failed to fetch alert"}), 500

    if not alert:
        logger.info("Alert not found: id=%s", alert_id)
        return jsonify({"error": "Not found"}), 404

    return jsonify(alert)


# ── Rules ─────────────────────────────────────────────────────────────────────

@api_bp.route("/rules")
def list_rules():
    try:
        page, limit, offset = _parse_pagination()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    rule_type = request.args.get("type", "").strip()
    search = request.args.get("search", "").strip()

    where = ["1=1"]
    params: list = []

    if rule_type:
        where.append("dr.rule_type = ?")
        params.append(rule_type)
    if search:
        where.append("dr.title LIKE ?")
        params.append(f"%{search}%")

    where_clause = " AND ".join(where)

    try:
        conn = get_db()
        total = conn.execute(
            f"SELECT COUNT(*) FROM detection_rules dr WHERE {where_clause}",
            params,
        ).fetchone()[0]

        rows = conn.execute(
            f"""
            SELECT dr.id, dr.ioc_id, dr.rule_type, dr.rule_id, dr.title,
                   dr.content, dr.file_path, dr.generated_at,
                   i.value AS ioc_value, i.type AS ioc_type, s.confidence
            FROM detection_rules dr
            JOIN iocs i ON i.id = dr.ioc_id
            LEFT JOIN scores s ON s.ioc_id = i.id
            WHERE {where_clause}
            ORDER BY dr.generated_at DESC
            LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        ).fetchall()
        conn.close()
    except Exception:
        logger.exception("Database error on GET /rules")
        return jsonify({"error": "Failed to fetch rules"}), 500

    return jsonify({
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit if total else 0,
        "results": [dict(r) for r in rows],
    })


# ── Feed refresh ──────────────────────────────────────────────────────────────

@api_bp.route("/refresh-feeds", methods=["POST"])
def refresh_feeds():
    def _run_feeds() -> None:
        try:
            from pipeline.ingestion.feed_manager import run_all

            results = run_all()
            summary = {
                r["feed"]: {
                    "status": r["status"],
                    "new": r.get("iocs_new", 0),
                    "fetched": r.get("iocs_fetched", 0),
                }
                for r in results
            }
            logger.info("Feed refresh complete: %s", summary)
        except Exception:
            logger.exception("Feed refresh failed")

    try:
        t = threading.Thread(target=_run_feeds, daemon=True)
        t.start()
    except Exception:
        logger.exception("Failed to start feed refresh thread")
        return jsonify({"error": "Failed to start feed refresh"}), 500

    logger.info("Feed refresh started in background")
    return jsonify({
        "status": "started",
        "message": "Feed refresh running in background.",
        "started_at": _now(),
    }), 202


# ── Dashboard stats ───────────────────────────────────────────────────────────

@api_bp.route("/dashboard/stats")
def dashboard_stats():
    try:
        conn = get_db()

        total_iocs = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]

        severity_rows = conn.execute(
            """
            SELECT confidence, COUNT(*) AS count
            FROM scores
            GROUP BY confidence
            ORDER BY CASE confidence
                WHEN 'critical' THEN 1
                WHEN 'high'     THEN 2
                WHEN 'medium'   THEN 3
                WHEN 'low'      THEN 4
                ELSE 5
            END
            """
        ).fetchall()
        iocs_by_severity = {row["confidence"]: row["count"] for row in severity_rows}

        source_rows = conn.execute(
            """
            SELECT source_feed, COUNT(*) AS count
            FROM iocs
            GROUP BY source_feed
            ORDER BY count DESC
            """
        ).fetchall()
        iocs_by_source = [dict(r) for r in source_rows]

        recent_threats = conn.execute(
            """
            SELECT i.id, i.value, i.type, i.source_feed, i.malware_family,
                   i.last_seen, s.score, s.confidence
            FROM iocs i
            LEFT JOIN scores s ON s.ioc_id = i.id
            ORDER BY i.last_seen DESC
            LIMIT 10
            """
        ).fetchall()

        sigma_rules = conn.execute(
            "SELECT COUNT(*) FROM detection_rules WHERE rule_type = 'sigma'"
        ).fetchone()[0]
        spl_rules = conn.execute(
            "SELECT COUNT(*) FROM detection_rules WHERE rule_type = 'spl'"
        ).fetchone()[0]
        total_rules = conn.execute(
            "SELECT COUNT(*) FROM detection_rules"
        ).fetchone()[0]
        actionable = conn.execute(
            "SELECT COUNT(*) FROM iocs WHERE is_actionable = 1"
        ).fetchone()[0]
        high_risk = conn.execute(
            "SELECT COUNT(*) FROM scores WHERE confidence IN ('high', 'critical')"
        ).fetchone()[0]

        conn.close()
    except Exception:
        logger.exception("Database error on GET /dashboard/stats")
        return jsonify({"error": "Failed to fetch dashboard stats"}), 500

    return jsonify({
        "total_iocs": total_iocs,
        "high_risk": high_risk,
        "actionable": actionable,
        "total_rules": total_rules,
        "sigma_rules": sigma_rules,
        "spl_rules": spl_rules,
        "iocs_by_severity": iocs_by_severity,
        "iocs_by_source": iocs_by_source,
        "recent_threats": [dict(r) for r in recent_threats],
    })
