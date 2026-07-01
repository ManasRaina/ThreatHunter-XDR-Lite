"""
ThreatFox feed ingester.
Uses the public JSON export — NO API key required.
URL: https://threatfox.abuse.ch/export/json/recent/

The export is a JSON object keyed by IOC ID.
Each value is a list of one or more IOC dicts with fields:
  ioc_value, ioc_type, threat_type, malware, malware_printable,
  first_seen_utc, last_seen_utc, confidence_level, reference, tags

The old API endpoint /api/v1/ now requires auth for get_iocs queries.
This public export is equivalent and requires zero credentials.
"""

import time
import requests
from datetime import datetime, timezone

from config import FEEDS
from db.database import get_db

FEED_NAME = "threatfox"
# Public JSON export — no auth needed
EXPORT_URL = "https://threatfox.abuse.ch/export/json/recent/"

# Map ThreatFox ioc_type → our internal type
TYPE_MAP = {
    "ip:port":      "ip",
    "domain":       "domain",
    "url":          "url",
    "md5_hash":     "md5",
    "sha256_hash":  "sha256",
}

_HEADERS = {
    "User-Agent": "ThreatIntelOS/1.0 (research; contact@example.com)",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_date(s: str) -> str:
    if not s:
        return _now()
    for fmt in ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            clean = s.replace(" UTC", "")
            return datetime.strptime(clean, fmt.replace(" UTC", "")).replace(
                tzinfo=timezone.utc
            ).isoformat(timespec="seconds")
        except ValueError:
            continue
    return _now()


def _extract_value(raw: str, ioc_type: str) -> str:
    """For ip:port entries, strip the port."""
    if ioc_type == "ip" and ":" in raw:
        return raw.split(":")[0].strip()
    return raw.strip()


def ingest() -> dict:
    started = time.time()
    result = {
        "feed":         FEED_NAME,
        "iocs_fetched": 0,
        "iocs_new":     0,
        "status":       "success",
        "error_msg":    None,
    }

    try:
        resp = requests.get(EXPORT_URL, headers=_HEADERS, timeout=60)

        if not resp.ok:
            result["status"]    = "error"
            result["error_msg"] = f"HTTP {resp.status_code}: {resp.text[:200]}"
            print(f"[ThreatFox] HTTP error {resp.status_code}")
            return result

        raw_data = resp.json()   # dict keyed by ioc_id

        if not isinstance(raw_data, dict):
            result["status"]    = "error"
            result["error_msg"] = "Unexpected response format from ThreatFox export"
            return result

        conn    = get_db()
        fetched = 0
        new     = 0

        for ioc_id_str, ioc_list in raw_data.items():
            if not isinstance(ioc_list, list):
                continue

            for item in ioc_list:
                raw_type   = (item.get("ioc_type") or "").lower()
                ioc_type   = TYPE_MAP.get(raw_type)
                if not ioc_type:
                    continue

                raw_value = (item.get("ioc_value") or "").strip()
                if not raw_value:
                    continue

                value          = _extract_value(raw_value, ioc_type)
                malware_family = (
                    item.get("malware_printable") or item.get("malware") or ""
                ).strip() or None
                first_seen     = _parse_date(item.get("first_seen_utc"))

                tags_raw = item.get("tags") or []
                if isinstance(tags_raw, list):
                    tags_str = ",".join(str(t) for t in tags_raw) or None
                else:
                    tags_str = str(tags_raw) or None

                fetched += 1

                try:
                    cur = conn.execute(
                        """
                        INSERT INTO iocs (value, type, source_feed, malware_family,
                                          first_seen, last_seen, raw_tags)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(value, type) DO UPDATE SET
                            last_seen      = excluded.last_seen,
                            malware_family = COALESCE(excluded.malware_family, iocs.malware_family),
                            raw_tags       = COALESCE(excluded.raw_tags, iocs.raw_tags)
                        """,
                        (value, ioc_type, FEED_NAME, malware_family,
                         first_seen, _now(), tags_str),
                    )
                    # rowcount==1 → true INSERT (brand-new IOC)
                    # rowcount==2 → UPSERT updated existing row
                    if cur.rowcount == 1:
                        new += 1
                except Exception as exc:
                    print(f"[ThreatFox] Row error for {value!r}: {exc}")

        conn.commit()
        conn.close()

        result["iocs_fetched"] = fetched
        result["iocs_new"]     = new
        print(f"[ThreatFox] Fetched {fetched} IOCs, {new} new.")

    except Exception as exc:
        result["status"]    = "error"
        result["error_msg"] = str(exc)
        print(f"[ThreatFox] Fatal error: {exc}")

    result["duration_sec"] = round(time.time() - started, 2)
    return result