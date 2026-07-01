import io
import json
import zipfile
import threading
from flask import Blueprint, jsonify, request, Response
from db.database import fetchall, fetchone, get_db
from datetime import datetime, timezone

api_bp = Blueprint("api", __name__)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ── Stats ─────────────────────────────────────────────────────────────────────

@api_bp.route("/stats")
def stats():
    conn = get_db()
    total_iocs      = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    high_risk       = conn.execute(
        "SELECT COUNT(*) FROM scores WHERE confidence IN ('high','critical')"
    ).fetchone()[0]
    actionable      = conn.execute(
        "SELECT COUNT(*) FROM iocs WHERE is_actionable = 1"
    ).fetchone()[0]
    total_rules     = conn.execute(
        "SELECT COUNT(*) FROM detection_rules"
    ).fetchone()[0]
    sigma_rules     = conn.execute(
        "SELECT COUNT(*) FROM detection_rules WHERE rule_type = 'sigma'"
    ).fetchone()[0]
    spl_rules       = conn.execute(
        "SELECT COUNT(*) FROM detection_rules WHERE rule_type = 'spl'"
    ).fetchone()[0]
    critical_count  = conn.execute(
        "SELECT COUNT(*) FROM scores WHERE confidence = 'critical'"
    ).fetchone()[0]
    medium_count    = conn.execute(
        "SELECT COUNT(*) FROM scores WHERE confidence = 'medium'"
    ).fetchone()[0]
    low_count       = conn.execute(
        "SELECT COUNT(*) FROM scores WHERE confidence = 'low'"
    ).fetchone()[0]
    conn.close()

    return jsonify({
        "total_iocs":    total_iocs,
        "high_risk":     high_risk,
        "actionable":    actionable,
        "total_rules":   total_rules,
        "sigma_rules":   sigma_rules,
        "spl_rules":     spl_rules,
        "critical":      critical_count,
        "high":          high_risk - critical_count,
        "medium":        medium_count,
        "low":           low_count,
    })


# ── IOCs ──────────────────────────────────────────────────────────────────────

@api_bp.route("/iocs")
def iocs():
    page       = max(int(request.args.get("page", 1)), 1)
    limit      = min(int(request.args.get("limit", 50)), 200)
    offset     = (page - 1) * limit
    ioc_type   = request.args.get("type", "")
    confidence = request.args.get("confidence", "")
    feed       = request.args.get("feed", "")
    search     = request.args.get("search", "").strip()

    where  = ["1=1"]
    params = []

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

    conn   = get_db()
    total  = conn.execute(
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

    return jsonify({
        "total":   total,
        "page":    page,
        "limit":   limit,
        "pages":   (total + limit - 1) // limit,
        "results": [dict(r) for r in rows],
    })


@api_bp.route("/iocs/<int:ioc_id>")
def ioc_detail(ioc_id: int):
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
        return jsonify({"error": "Not found"}), 404

    enrichments = fetchall(
        "SELECT provider, result_json, enriched_at FROM enrichments WHERE ioc_id = ?",
        (ioc_id,),
    )
    rules = fetchall(
        "SELECT rule_type, title, content, generated_at FROM detection_rules WHERE ioc_id = ?",
        (ioc_id,),
    )
    return jsonify({"ioc": ioc, "enrichments": enrichments, "rules": rules})


# ── Feeds ─────────────────────────────────────────────────────────────────────

@api_bp.route("/feeds")
def feeds():
    conn  = get_db()
    feeds_data = conn.execute(
        """
        SELECT source_feed,
               COUNT(*)                        AS ioc_count,
               MAX(last_seen)                  AS last_seen,
               SUM(is_actionable)              AS actionable_count
        FROM iocs
        GROUP BY source_feed
        """
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in feeds_data])


@api_bp.route("/feeds/runs")
def feed_runs():
    rows = fetchall(
        """
        SELECT * FROM feed_runs
        ORDER BY run_at DESC
        LIMIT 50
        """
    )
    return jsonify(rows)


# ── Rules ─────────────────────────────────────────────────────────────────────

@api_bp.route("/rules")
def rules():
    page       = max(int(request.args.get("page", 1)), 1)
    limit      = min(int(request.args.get("limit", 50)), 200)
    offset     = (page - 1) * limit
    rule_type  = request.args.get("type", "")
    search     = request.args.get("search", "").strip()

    where  = ["1=1"]
    params = []
    if rule_type:
        where.append("rule_type = ?")
        params.append(rule_type)
    if search:
        where.append("title LIKE ?")
        params.append(f"%{search}%")

    where_clause = " AND ".join(where)
    conn  = get_db()
    total = conn.execute(
        f"SELECT COUNT(*) FROM detection_rules WHERE {where_clause}", params
    ).fetchone()[0]

    rows  = conn.execute(
        f"""
        SELECT dr.id, dr.rule_type, dr.rule_id, dr.title, dr.generated_at,
               i.value AS ioc_value, i.type AS ioc_type, s.confidence
        FROM detection_rules dr
        JOIN iocs   i ON i.id = dr.ioc_id
        LEFT JOIN scores s ON s.ioc_id = i.id
        WHERE {where_clause}
        ORDER BY dr.generated_at DESC
        LIMIT ? OFFSET ?
        """,
        [*params, limit, offset],
    ).fetchall()
    conn.close()

    return jsonify({
        "total":   total,
        "page":    page,
        "pages":   (total + limit - 1) // limit,
        "results": [dict(r) for r in rows],
    })


@api_bp.route("/rules/<int:rule_id>")
def rule_detail(rule_id: int):
    rule = fetchone("SELECT * FROM detection_rules WHERE id = ?", (rule_id,))
    if not rule:
        return jsonify({"error": "Not found"}), 404
    return jsonify(rule)


@api_bp.route("/rules/download/sigma/<int:rule_id>")
def download_sigma(rule_id: int):
    rule = fetchone(
        "SELECT * FROM detection_rules WHERE id = ? AND rule_type = 'sigma'",
        (rule_id,),
    )
    if not rule:
        return jsonify({"error": "Not found"}), 404
    return Response(
        rule["content"],
        mimetype="text/yaml",
        headers={"Content-Disposition": f'attachment; filename="rule_{rule_id}.yml"'},
    )


@api_bp.route("/rules/download/spl/<int:rule_id>")
def download_spl(rule_id: int):
    rule = fetchone(
        "SELECT * FROM detection_rules WHERE id = ? AND rule_type = 'spl'",
        (rule_id,),
    )
    if not rule:
        return jsonify({"error": "Not found"}), 404
    return Response(
        rule["content"],
        mimetype="text/plain",
        headers={"Content-Disposition": f'attachment; filename="query_{rule_id}.txt"'},
    )


@api_bp.route("/rules/download/sigma/all")
def download_sigma_all():
    rows = fetchall(
        "SELECT rule_id, title, content FROM detection_rules WHERE rule_type = 'sigma'"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for row in rows:
            fname = f"{row['rule_id'][:8]}.yml"
            zf.writestr(fname, row["content"])
    buf.seek(0)
    return Response(
        buf.read(),
        mimetype="application/zip",
        headers={"Content-Disposition": 'attachment; filename="sigma_rules.zip"'},
    )


@api_bp.route("/rules/download/spl/all")
def download_spl_all():
    rows = fetchall(
        "SELECT title, content FROM detection_rules WHERE rule_type = 'spl'"
    )
    combined = "\n\n".join(f"-- {r['title']}\n{r['content']}" for r in rows)
    return Response(
        combined,
        mimetype="text/plain",
        headers={"Content-Disposition": 'attachment; filename="spl_queries.txt"'},
    )


# ── Charts ────────────────────────────────────────────────────────────────────

@api_bp.route("/charts/type-distribution")
def chart_type_dist():
    rows = fetchall(
        "SELECT type, COUNT(*) AS count FROM iocs GROUP BY type ORDER BY count DESC"
    )
    return jsonify(rows)


@api_bp.route("/charts/score-distribution")
def chart_score_dist():
    rows = fetchall(
        """
        SELECT confidence, COUNT(*) AS count
        FROM scores
        GROUP BY confidence
        ORDER BY CASE confidence
            WHEN 'critical' THEN 1
            WHEN 'high'     THEN 2
            WHEN 'medium'   THEN 3
            WHEN 'low'      THEN 4
        END
        """
    )
    return jsonify(rows)


@api_bp.route("/charts/feed-timeline")
def chart_feed_timeline():
    rows = fetchall(
        """
        SELECT DATE(first_seen) AS day, source_feed, COUNT(*) AS count
        FROM iocs
        GROUP BY day, source_feed
        ORDER BY day DESC
        LIMIT 90
        """
    )
    return jsonify(rows)


# ── Pipeline ──────────────────────────────────────────────────────────────────

@api_bp.route("/pipeline/status")
def pipeline_status():
    row = fetchone(
        "SELECT * FROM pipeline_runs ORDER BY id DESC LIMIT 1"
    )
    return jsonify(row or {"stage": "idle", "status": "idle"})


@api_bp.route("/pipeline/history")
def pipeline_history():
    rows = fetchall(
        "SELECT * FROM pipeline_runs ORDER BY id DESC LIMIT 20"
    )
    return jsonify(rows)


@api_bp.route("/pipeline/run", methods=["POST"])
def pipeline_run():
    def _run():
        from run import stage_ingest, stage_enrich, stage_score, stage_rules, _write_pipeline_run
        started = _now()
        try:
            s1 = stage_ingest();  _write_pipeline_run("ingest",   "success", s1, started)
            s2 = stage_enrich();  _write_pipeline_run("enrich",   "success", s2, _now())
            s3 = stage_score();   _write_pipeline_run("score",    "success", s3, _now())
            s4 = stage_rules();   _write_pipeline_run("rules",    "success", s4, _now())
            _write_pipeline_run("complete", "success", {**s1,**s2,**s3,**s4}, started)
        except Exception as exc:
            _write_pipeline_run("error", "error", {"error": str(exc)}, started)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return jsonify({"status": "started", "message": "Pipeline running in background."})


# ── Activity feed ─────────────────────────────────────────────────────────────

@api_bp.route("/activity")
def activity():
    feed_rows = fetchall(
        """
        SELECT feed_name AS source, run_at AS time,
               iocs_new AS count, status, 'feed' AS event_type
        FROM feed_runs
        ORDER BY run_at DESC LIMIT 10
        """
    )
    pipeline_rows = fetchall(
        """
        SELECT stage AS source, started_at AS time,
               0 AS count, status, 'pipeline' AS event_type
        FROM pipeline_runs
        ORDER BY id DESC LIMIT 5
        """
    )
    combined = sorted(
        feed_rows + pipeline_rows,
        key=lambda x: x["time"],
        reverse=True,
    )[:15]
    return jsonify(combined)