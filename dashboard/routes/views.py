from flask import Blueprint, render_template
from db.database import fetchone, fetchall

views_bp = Blueprint("views", __name__)


@views_bp.route("/")
def index():
    return render_template("index.html", active="dashboard")


@views_bp.route("/iocs")
def iocs():
    return render_template("iocs.html", active="iocs")


@views_bp.route("/iocs/<int:ioc_id>")
def ioc_detail(ioc_id: int):
    ioc = fetchone("SELECT * FROM iocs WHERE id = ?", (ioc_id,))
    if not ioc:
        return render_template("iocs.html", active="iocs"), 404

    score = fetchone("SELECT * FROM scores WHERE ioc_id = ?", (ioc_id,))
    enrichments = fetchall(
        "SELECT provider, result_json, enriched_at FROM enrichments WHERE ioc_id = ?",
        (ioc_id,),
    )
    sigma_rule = fetchone(
        "SELECT * FROM detection_rules WHERE ioc_id = ? AND rule_type = 'sigma'",
        (ioc_id,),
    )
    spl_rule = fetchone(
        "SELECT * FROM detection_rules WHERE ioc_id = ? AND rule_type = 'spl'",
        (ioc_id,),
    )
    return render_template(
        "ioc_detail.html",
        active="iocs",
        ioc=ioc,
        score=score,
        enrichments=enrichments,
        sigma_rule=sigma_rule,
        spl_rule=spl_rule,
    )


@views_bp.route("/feeds")
def feeds():
    return render_template("feeds.html", active="feeds")


@views_bp.route("/rules")
def rules():
    return render_template("rules.html", active="rules")


@views_bp.route("/pipeline")
def pipeline():
    return render_template("pipeline.html", active="pipeline")