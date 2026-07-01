"""
URLHaus feed ingester.
Downloads the recent CSV (no API key required).

Format note: URLHaus CSV comment lines start with '#', INCLUDING the header line
which is "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter".
The actual data rows are unquoted or double-quoted fields — NOT comment lines.

Fix: extract fieldnames from the comment-header line, then feed only data rows to DictReader.
"""

import csv
import io
import time
import requests
from datetime import datetime, timezone

from config import FEEDS
from db.database import get_db

FEED_NAME = "urlhaus"
FEED_URL  = FEEDS["urlhaus"]["url"]

_HEADERS = {
    "User-Agent": "ThreatIntelOS/1.0 (research; contact@example.com)"
}

# The URLHaus CSV header is embedded in a comment line:
# "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter"
_KNOWN_HEADER = ["id", "dateadded", "url", "url_status", "last_online",
                 "threat", "tags", "urlhaus_link", "reporter"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_date(s: str) -> str:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).isoformat(timespec="seconds")
        except ValueError:
            continue
    return _now()


def _extract_fieldnames(lines: list[str]) -> list[str]:
    """
    URLHaus embeds the column header as a comment line like:
      # id,dateadded,url,...
    Find it and return the field names.
    """
    for line in lines:
        if line.startswith("#"):
            # Strip leading '#' and whitespace, then check if it looks like CSV header
            candidate = line.lstrip("# ").strip()
            if "dateadded" in candidate and "url" in candidate:
                return [f.strip() for f in candidate.split(",")]
    return _KNOWN_HEADER   # fallback


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
        resp = requests.get(FEED_URL, headers=_HEADERS, timeout=45)
        resp.raise_for_status()
        raw_lines = resp.text.splitlines()

        # Extract fieldnames from comment-header line
        fieldnames = _extract_fieldnames(raw_lines)

        # Data rows: non-empty, not starting with '#'
        data_lines = [l for l in raw_lines if l.strip() and not l.startswith("#")]

        if not data_lines:
            result["status"]    = "error"
            result["error_msg"] = "URLHaus returned 0 data rows"
            return result

        reader = csv.DictReader(io.StringIO("\n".join(data_lines)), fieldnames=fieldnames)

        conn    = get_db()
        fetched = 0
        new     = 0

        for row in reader:
            url_val = (row.get("url") or "").strip().strip('"')
            if not url_val:
                continue

            fetched += 1

            threat   = (row.get("threat") or "").strip() or None
            tags_raw = (row.get("tags")   or "").strip() or None
            date_add = (row.get("dateadded") or _now()).strip().strip('"')
            date_iso = _parse_date(date_add)

            try:
                cur = conn.execute(
                    """
                    INSERT INTO iocs (value, type, source_feed, malware_family,
                                      first_seen, last_seen, raw_tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(value, type) DO UPDATE SET
                        last_seen      = excluded.last_seen,
                        raw_tags       = excluded.raw_tags,
                        malware_family = COALESCE(excluded.malware_family, iocs.malware_family)
                    """,
                    (url_val, "url", FEED_NAME, threat,
                     date_iso, _now(), tags_raw),
                )
                # rowcount==1 → pure INSERT (new IOC)
                # rowcount==2 → UPSERT updated existing row
                if cur.rowcount == 1:
                    new += 1
            except Exception as exc:
                print(f"[URLHaus] Row error for {url_val!r}: {exc}")

        conn.commit()
        conn.close()

        result["iocs_fetched"] = fetched
        result["iocs_new"]     = new

    except Exception as exc:
        result["status"]    = "error"
        result["error_msg"] = str(exc)
        print(f"[URLHaus] Fatal error: {exc}")

    result["duration_sec"] = round(time.time() - started, 2)
    return result