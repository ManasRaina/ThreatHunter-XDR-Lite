"""
Enrichment stage.

Default mode: metadata-driven — no external API keys required.
  - Derives signals from IOC type, value patterns, tags, malware family name.
  - Marks IOCs actionable based on those signals.

Optional:
  - VirusTotal (VT_API_KEY in .env)   → type=ip,domain,url,md5,sha256
  - AbuseIPDB  (ABUSEIPDB_API_KEY)   → type=ip only

Rate-limiting is enforced per config values (VT_RATE_SLEEP, ABUSEIPDB_SLEEP).
Enrichment is capped at ENRICHMENT_LIMIT IOCs per run.
"""

import json
import re
import time
from datetime import datetime, timezone

import requests

from config import (
    ENRICHMENT_LIMIT,
    VT_API_KEY,
    VT_RATE_SLEEP,
    ABUSEIPDB_API_KEY,
    ABUSEIPDB_SLEEP,
)
from db.database import get_db


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ── Metadata enrichment (always runs, no API key) ─────────────────────────────

_SUSPICIOUS_FAMILIES = {
    "mirai", "emotet", "trickbot", "qakbot", "cobalt strike", "metasploit",
    "njrat", "darkcomet", "asyncrat", "redline", "raccoon", "amadey",
    "lokibot", "formbook", "remcos", "nanocore", "agent tesla",
    "magniber", "lockbit", "revil", "conti", "blackcat", "clop",
    "wannacry", "petya", "notpetya", "ryuk", "maze", "sodinokibi",
}

_HIGH_RISK_TAGS = {
    "botnet", "c2", "c&c", "command-and-control", "ransomware", "banker",
    "stealer", "rat", "exploit", "dropper", "loader", "backdoor",
    "phishing", "malspam", "cryptominer", "ddos",
}

_PRIVATE_IP_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\."),
    re.compile(r"^127\."),
    re.compile(r"^::1$"),
    re.compile(r"^fc00:"),
]

_SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".buzz",
    ".club", ".work", ".icu", ".cyou", ".shop",
}

_SUSPICIOUS_URL_PATTERNS = [
    re.compile(r"/[a-z0-9]{32,}$", re.I),   # long random path
    re.compile(r"\.php\?[a-z]+=", re.I),     # PHP with params
    re.compile(r"/(wp-admin|admin|shell|cmd|exec)", re.I),
    re.compile(r"\.(exe|dll|bat|ps1|vbs|jar|zip|rar)$", re.I),
]


def _is_private_ip(value: str) -> bool:
    return any(p.match(value) for p in _PRIVATE_IP_RANGES)


def _enrich_metadata(ioc: dict) -> dict:
    """
    Derive signals purely from what we already know about the IOC.
    Returns a dict of signal_name → bool/str that downstream scoring uses.
    """
    itype   = ioc.get("type", "")
    value   = ioc.get("value", "")
    tags    = (ioc.get("raw_tags") or "").lower()
    family  = (ioc.get("malware_family") or "").lower().strip()
    feed    = ioc.get("source_feed", "")

    signals: dict = {
        "provider":       "metadata",
        "ioc_type":       itype,
        "source_feed":    feed,
        "is_private_ip":  False,
        "suspicious_tld": False,
        "suspicious_url": False,
        "known_family":   False,
        "high_risk_tags": False,
        "family_name":    family or None,
        "tag_count":      len([t for t in tags.split(",") if t.strip()]),
    }

    if itype == "ip":
        signals["is_private_ip"] = _is_private_ip(value)

    if itype == "domain":
        for tld in _SUSPICIOUS_TLDS:
            if value.endswith(tld):
                signals["suspicious_tld"] = True
                break

    if itype == "url":
        for pattern in _SUSPICIOUS_URL_PATTERNS:
            if pattern.search(value):
                signals["suspicious_url"] = True
                break

    if family:
        for sus in _SUSPICIOUS_FAMILIES:
            if sus in family:
                signals["known_family"] = True
                break

    if tags:
        for tag in tags.split(","):
            if tag.strip() in _HIGH_RISK_TAGS:
                signals["high_risk_tags"] = True
                break

    return signals


# ── VirusTotal (optional) ─────────────────────────────────────────────────────

_VT_BASE = "https://www.virustotal.com/api/v3"
_VT_TYPE_ENDPOINTS = {
    "ip":     "/ip_addresses/{value}",
    "domain": "/domains/{value}",
    "url":    "/urls/{id}",      # requires submission first
    "md5":    "/files/{value}",
    "sha256": "/files/{value}",
}


def _enrich_virustotal(ioc: dict) -> dict | None:
    if not VT_API_KEY:
        return None
    itype = ioc["type"]
    value = ioc["value"]

    headers = {"x-apikey": VT_API_KEY}

    try:
        if itype in ("ip", "domain"):
            endpoint = _VT_BASE + _VT_TYPE_ENDPOINTS[itype].format(value=value)
            resp = requests.get(endpoint, headers=headers, timeout=20)
        elif itype in ("md5", "sha256"):
            endpoint = _VT_BASE + _VT_TYPE_ENDPOINTS[itype].format(value=value)
            resp = requests.get(endpoint, headers=headers, timeout=20)
        else:
            return None   # skip url type (needs 2-step submission)

        if resp.status_code == 404:
            return {"provider": "virustotal", "found": False, "value": value}
        resp.raise_for_status()
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "provider":   "virustotal",
            "found":       True,
            "malicious":   stats.get("malicious", 0),
            "suspicious":  stats.get("suspicious", 0),
            "harmless":    stats.get("harmless", 0),
            "undetected":  stats.get("undetected", 0),
            "reputation":  attrs.get("reputation", 0),
        }
    except Exception as exc:
        return {"provider": "virustotal", "error": str(exc)}
    finally:
        time.sleep(VT_RATE_SLEEP)


# ── AbuseIPDB (optional) ──────────────────────────────────────────────────────

def _enrich_abuseipdb(ioc: dict) -> dict | None:
    if not ABUSEIPDB_API_KEY or ioc["type"] != "ip":
        return None
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ioc["value"], "maxAgeInDays": 30},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "provider":          "abuseipdb",
            "abuse_score":       data.get("abuseConfidenceScore", 0),
            "total_reports":     data.get("totalReports", 0),
            "country":           data.get("countryCode", ""),
            "isp":               data.get("isp", ""),
            "is_tor":            data.get("isTor", False),
            "is_whitelisted":    data.get("isWhitelisted", False),
        }
    except Exception as exc:
        return {"provider": "abuseipdb", "error": str(exc)}
    finally:
        time.sleep(ABUSEIPDB_SLEEP)


# ── Actionability logic ───────────────────────────────────────────────────────

def _is_actionable(meta: dict, vt: dict | None, ab: dict | None) -> bool:
    """Return True if this IOC has enough positive signals to act on."""
    if meta.get("known_family"):
        return True
    if meta.get("high_risk_tags"):
        return True
    if vt and vt.get("malicious", 0) >= 3:
        return True
    if ab and ab.get("abuse_score", 0) >= 25:
        return True
    if meta.get("suspicious_tld") and meta.get("tag_count", 0) > 0:
        return True
    if meta.get("suspicious_url") and meta.get("known_family"):
        return True
    return False


# ── Main entry point ──────────────────────────────────────────────────────────

def run() -> dict:
    # Determine which enrichments we want to check missing records for
    conditions = ["NOT EXISTS (SELECT 1 FROM enrichments e WHERE e.ioc_id = i.id AND e.provider = 'metadata')"]
    if VT_API_KEY:
        conditions.append(
            """(i.type IN ('ip', 'domain', 'md5', 'sha256') AND NOT EXISTS (
                SELECT 1 FROM enrichments e WHERE e.ioc_id = i.id AND e.provider = 'virustotal'
            ))"""
        )
    if ABUSEIPDB_API_KEY:
        conditions.append(
            """(i.type = 'ip' AND NOT EXISTS (
                SELECT 1 FROM enrichments e WHERE e.ioc_id = i.id AND e.provider = 'abuseipdb'
            ))"""
        )

    query = f"""
        SELECT i.id, i.value, i.type, i.source_feed, i.malware_family, i.raw_tags
        FROM iocs i
        WHERE {" OR ".join(conditions)}
        ORDER BY i.id
        LIMIT ?
    """

    conn = get_db()
    rows = conn.execute(query, (ENRICHMENT_LIMIT,)).fetchall()

    total = len(rows)
    done  = 0
    print(f"[Enricher] Enriching {total} IOCs needing active enrichments (cap={ENRICHMENT_LIMIT}) ...")

    for row in rows:
        ioc = dict(row)
        ioc_id = ioc["id"]

        # Fetch existing enrichments for this IOC
        existing_rows = conn.execute(
            "SELECT provider, result_json FROM enrichments WHERE ioc_id = ?",
            (ioc_id,)
        ).fetchall()
        existing = {}
        for r in existing_rows:
            try:
                existing[r["provider"]] = json.loads(r["result_json"])
            except Exception:
                pass

        # 1. Metadata
        if "metadata" not in existing:
            meta = _enrich_metadata(ioc)
            conn.execute(
                "INSERT OR REPLACE INTO enrichments (ioc_id, provider, result_json, enriched_at) VALUES (?, 'metadata', ?, ?)",
                (ioc_id, json.dumps(meta), _now())
            )
        else:
            meta = existing["metadata"]

        # 2. VirusTotal
        vt = existing.get("virustotal")
        if not vt and VT_API_KEY and ioc["type"] in ("ip", "domain", "md5", "sha256"):
            vt = _enrich_virustotal(ioc)
            if vt:
                conn.execute(
                    "INSERT OR REPLACE INTO enrichments (ioc_id, provider, result_json, enriched_at) VALUES (?, 'virustotal', ?, ?)",
                    (ioc_id, json.dumps(vt), _now())
                )

        # 3. AbuseIPDB
        ab = existing.get("abuseipdb")
        if not ab and ABUSEIPDB_API_KEY and ioc["type"] == "ip":
            ab = _enrich_abuseipdb(ioc)
            if ab:
                conn.execute(
                    "INSERT OR REPLACE INTO enrichments (ioc_id, provider, result_json, enriched_at) VALUES (?, 'abuseipdb', ?, ?)",
                    (ioc_id, json.dumps(ab), _now())
                )

        # 4. Update is_actionable flag
        actionable = 1 if _is_actionable(meta, vt, ab) else 0
        conn.execute(
            "UPDATE iocs SET is_actionable = ? WHERE id = ?",
            (actionable, ioc_id),
        )
        conn.commit()

        done += 1
        if done % 50 == 0:
            print(f"[Enricher]   {done}/{total} enriched ...")

    conn.close()
    print(f"[Enricher] Done — {done} IOCs enriched.")
    return {"enriched": done}



# ── Internal write helper ─────────────────────────────────────────────────────

def _write_enrichment(ioc_id: int, provider: str, result: dict) -> None:
    conn = get_db()
    conn.execute(
        """
        INSERT OR REPLACE INTO enrichments (ioc_id, provider, result_json, enriched_at)
        VALUES (?, ?, ?, ?)
        """,
        (ioc_id, provider, json.dumps(result), _now()),
    )
    conn.commit()
    conn.close()
