"""
AlienVault OTX ingester.
Requires OTX_API_KEY in .env — skipped automatically if blank.
Pulls the latest subscribed pulses and extracts IOCs from each.
"""

import time
import requests
from datetime import datetime, timezone

from config import FEEDS, OTX_API_KEY
from db.database import get_db

FEED_NAME = "otx"
FEED_URL  = FEEDS["otx"]["url"]

OTX_TYPE_MAP = {
    "IPv4":       "ip",
    "IPv6":       "ip",
    "domain":     "domain",
    "hostname":   "domain",
    "URL":        "url",
    "FileHash-MD5":    "md5",
    "FileHash-SHA256": "sha256",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_date(s: str) -> str:
    if not s:
        return _now()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).isoformat(timespec="seconds")
        except ValueError:
            continue
    return _now()


def ingest() -> dict:
    started = time.time()
    result = {
        "feed":         FEED_NAME,
        "iocs_fetched": 0,
        "iocs_new":     0,
        "status":       "success",
        "error_msg":    None,
    }

    if not OTX_API_KEY:
        result["status"]    = "error"
        result["error_msg"] = "OTX_API_KEY not set — skipping"
        result["duration_sec"] = 0
        return result

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    page    = 1
    fetched = 0
    new     = 0
    conn    = get_db()

    try:
        while True:
            resp = requests.get(
                FEED_URL,
                headers=headers,
                params={"limit": 20, "page": page},
                timeout=60,
            )
            resp.raise_for_status()
            data    = resp.json()
            pulses  = data.get("results", [])

            if not pulses:
                break

            for pulse in pulses:
                tags_str  = ",".join(pulse.get("tags", []))
                family    = pulse.get("name", "")

                for indicator in pulse.get("indicators", []):
                    raw_type  = indicator.get("type", "")
                    ioc_type  = OTX_TYPE_MAP.get(raw_type)
                    if not ioc_type:
                        continue

                    value     = (indicator.get("indicator") or "").strip()
                    if not value:
                        continue

                    created   = _parse_date(indicator.get("created"))
                    fetched  += 1

                    try:
                        cur = conn.execute(
                            """
                            INSERT INTO iocs (value, type, source_feed, malware_family,
                                              first_seen, last_seen, raw_tags)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(value, type) DO UPDATE SET
                                last_seen      = excluded.last_seen,
                                malware_family = COALESCE(excluded.malware_family, iocs.malware_family)
                            """,
                            (value, ioc_type, FEED_NAME, family or None,
                             created, _now(), tags_str or None),
                        )
                        if cur.lastrowid and cur.rowcount == 1:
                            new += 1
                    except Exception:
                        pass

            if not data.get("next"):
                break
            page += 1

        conn.commit()

    except Exception as exc:
        result["status"]    = "error"
        result["error_msg"] = str(exc)

    finally:
        conn.close()

    result["iocs_fetched"] = fetched
    result["iocs_new"]     = new
    result["duration_sec"] = round(time.time() - started, 2)
    return result