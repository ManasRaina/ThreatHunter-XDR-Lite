"""
Scoring stage.

Assigns a 0–100 risk score and a confidence band (low/medium/high/critical)
to every IOC that has been enriched but not yet scored.

Scoring is factor-based:
  - Base points from IOC type
  - Feed reputation bonus
  - Malware family recognition
  - High-risk tag keywords
  - Suspicious structural signals (TLD, URL pattern, private-IP check)
  - VirusTotal detection ratio (if available)
  - AbuseIPDB confidence score (if available)

After scoring, marks is_actionable = 1 for IOCs with score >= MIN_SCORE_FOR_RULE.
"""

import json
from datetime import datetime, timezone

from config import SCORE_BANDS, MIN_SCORE_FOR_RULE
from db.database import get_db


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ── Scoring weights ───────────────────────────────────────────────────────────

# Base score by IOC type (higher = more directly actionable)
_TYPE_BASE = {
    "ip":     25,
    "domain": 20,
    "url":    20,
    "md5":    30,
    "sha256": 30,
}

# Feed reputation multipliers (additive bonus)
_FEED_BONUS = {
    "threatfox": 15,   # C2 / active malware IOCs
    "urlhaus":   10,   # malicious URLs — high signal
    "otx":        8,   # community intelligence — slightly lower confidence
}

# Points per positive metadata signal
_SIGNAL_POINTS = {
    "known_family":   20,
    "high_risk_tags": 15,
    "suspicious_tld": 10,
    "suspicious_url": 10,
}


def _confidence_band(score: int) -> str:
    for band, (lo, hi) in SCORE_BANDS.items():
        if lo <= score <= hi:
            return band
    return "low"


def _score_ioc(ioc: dict, enrichments: list[dict]) -> tuple[int, dict]:
    """
    Returns (final_score 0–100, factors_dict).
    factors_dict maps factor_name → points_added.
    """
    factors: dict[str, int] = {}
    score = 0

    # 1. Type base
    base = _TYPE_BASE.get(ioc["type"], 10)
    factors["type_base"] = base
    score += base

    # 2. Feed bonus
    feed_bonus = _FEED_BONUS.get(ioc["source_feed"], 5)
    factors["feed_reputation"] = feed_bonus
    score += feed_bonus

    # 3. Parse enrichment providers
    meta = {}
    vt   = {}
    ab   = {}
    for e in enrichments:
        try:
            data = json.loads(e["result_json"])
        except (TypeError, ValueError, KeyError):
            continue
        prov = e.get("provider", data.get("provider", ""))
        if prov == "metadata":
            meta = data
        elif prov == "virustotal":
            vt = data
        elif prov == "abuseipdb":
            ab = data

    # 4. Metadata signals
    for signal, pts in _SIGNAL_POINTS.items():
        if meta.get(signal):
            factors[signal] = pts
            score += pts

    # 5. Malware family name present
    if ioc.get("malware_family"):
        factors["malware_family_known"] = 10
        score += 10

    # 6. Tags present (more tags = more context = higher confidence)
    tag_count = int(meta.get("tag_count", 0))
    if tag_count >= 3:
        factors["rich_tag_set"] = 5
        score += 5
    elif tag_count >= 1:
        factors["has_tags"] = 2
        score += 2

    # 7. VirusTotal signals (if present)
    if vt and not vt.get("error"):
        if vt.get("found"):
            malicious  = int(vt.get("malicious",  0))
            suspicious = int(vt.get("suspicious", 0))
            reputation = int(vt.get("reputation", 0))

            if malicious >= 10:
                factors["vt_high_detections"] = 20
                score += 20
            elif malicious >= 5:
                factors["vt_medium_detections"] = 12
                score += 12
            elif malicious >= 1:
                factors["vt_low_detections"] = 6
                score += 6

            if suspicious >= 3:
                factors["vt_suspicious"] = 4
                score += 4

            if reputation < -20:
                factors["vt_negative_reputation"] = 5
                score += 5

    # 8. AbuseIPDB signals (if present)
    if ab and not ab.get("error"):
        abuse_score = int(ab.get("abuse_score", 0))
        if abuse_score >= 75:
            factors["abuseipdb_high"] = 20
            score += 20
        elif abuse_score >= 25:
            factors["abuseipdb_medium"] = 10
            score += 10
        elif abuse_score >= 10:
            factors["abuseipdb_low"] = 5
            score += 5

        if ab.get("is_tor"):
            factors["is_tor_exit"] = 8
            score += 8

        total_reports = int(ab.get("total_reports", 0))
        if total_reports >= 50:
            factors["many_abuse_reports"] = 5
            score += 5

    # 9. Private IP penalty (should never be in threat feed but can happen)
    if meta.get("is_private_ip"):
        factors["private_ip_penalty"] = -30
        score -= 30

    # Clamp to [0, 100]
    final = max(0, min(100, score))
    return final, factors


# ── Main entry point ──────────────────────────────────────────────────────────

def run() -> dict:
    conn = get_db()

    # IOCs that have enrichment but no score yet, OR have been enriched after they were scored
    rows = conn.execute(
        """
        SELECT DISTINCT i.id, i.value, i.type, i.source_feed, i.malware_family, i.raw_tags
        FROM iocs i
        JOIN enrichments e ON e.ioc_id = i.id
        WHERE NOT EXISTS (
            SELECT 1 FROM scores s WHERE s.ioc_id = i.id
        ) OR EXISTS (
            SELECT 1 FROM enrichments e2
            JOIN scores s2 ON s2.ioc_id = e2.ioc_id
            WHERE e2.ioc_id = i.id AND e2.enriched_at > s2.scored_at
        )
        ORDER BY i.id
        """
    ).fetchall()

    total = len(rows)
    done  = 0
    print(f"[Scorer] Scoring {total} enriched IOCs ...")

    for row in rows:
        ioc    = dict(row)
        ioc_id = ioc["id"]

        enrichments = conn.execute(
            "SELECT provider, result_json FROM enrichments WHERE ioc_id = ?",
            (ioc_id,),
        ).fetchall()

        enrich_list = [dict(e) for e in enrichments]
        score, factors = _score_ioc(ioc, enrich_list)
        confidence     = _confidence_band(score)

        conn.execute(
            """
            INSERT OR REPLACE INTO scores (ioc_id, score, confidence, factors_json, scored_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (ioc_id, score, confidence, json.dumps(factors), _now()),
        )

        # Mark actionable if score meets threshold
        if score >= MIN_SCORE_FOR_RULE:
            conn.execute(
                "UPDATE iocs SET is_actionable = 1 WHERE id = ?",
                (ioc_id,),
            )

        done += 1
        if done % 100 == 0:
            print(f"[Scorer]   {done}/{total} scored ...")

    conn.commit()
    conn.close()
    print(f"[Scorer] Done — {done} IOCs scored.")
    return {"scored": done}
