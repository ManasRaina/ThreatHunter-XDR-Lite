"""
Splunk SPL query generator.
Generates one SPL query per high-confidence IOC and stores in detection_rules.
"""

import uuid
from datetime import datetime, timezone

from config import MIN_SCORE_FOR_RULE
from db.database import get_db


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


SPL_TEMPLATES = {
    "ip": (
        'index=* (src_ip="{value}" OR dest_ip="{value}" OR dst_ip="{value}")\n'
        '| eval ioc="{value}", ioc_type="ip", risk="{confidence}", score={score},\n'
        '       family="{family}", source_feed="{feed}"\n'
        '| table _time, src_ip, dest_ip, ioc, ioc_type, risk, score, family, source_feed\n'
        '| sort -_time'
    ),
    "domain": (
        'index=* (query="{value}" OR dns="{value}" OR url="*{value}*")\n'
        '| eval ioc="{value}", ioc_type="domain", risk="{confidence}", score={score},\n'
        '       family="{family}", source_feed="{feed}"\n'
        '| table _time, src_ip, query, url, ioc, ioc_type, risk, score, family, source_feed\n'
        '| sort -_time'
    ),
    "url": (
        'index=* (url="{value}" OR uri="{value}" OR cs-uri-stem="*{value}*")\n'
        '| eval ioc="{value}", ioc_type="url", risk="{confidence}", score={score},\n'
        '       family="{family}", source_feed="{feed}"\n'
        '| table _time, src_ip, dest_ip, url, ioc, ioc_type, risk, score, family, source_feed\n'
        '| sort -_time'
    ),
    "md5": (
        'index=* (md5="{value}" OR file_hash="{value}" OR CommandLine="*{value}*")\n'
        '| eval ioc="{value}", ioc_type="md5", risk="{confidence}", score={score},\n'
        '       family="{family}", source_feed="{feed}"\n'
        '| table _time, host, user, process, md5, ioc, ioc_type, risk, score, family, source_feed\n'
        '| sort -_time'
    ),
    "sha256": (
        'index=* (sha256="{value}" OR file_hash="{value}")\n'
        '| eval ioc="{value}", ioc_type="sha256", risk="{confidence}", score={score},\n'
        '       family="{family}", source_feed="{feed}"\n'
        '| table _time, host, user, process, sha256, ioc, ioc_type, risk, score, family, source_feed\n'
        '| sort -_time'
    ),
}

DEFAULT_SPL = (
    'index=* "{value}"\n'
    '| eval ioc="{value}", ioc_type="{ioc_type}", risk="{confidence}", score={score}\n'
    '| table _time, ioc, ioc_type, risk, score\n'
    '| sort -_time'
)


def generate() -> dict:
    conn = get_db()

    rows = conn.execute(
        """
        SELECT i.id, i.value, i.type, i.source_feed, i.malware_family,
               s.score, s.confidence
        FROM iocs i
        JOIN scores s ON s.ioc_id = i.id
        WHERE s.score >= ?
          AND NOT EXISTS (
              SELECT 1 FROM detection_rules dr
              WHERE dr.ioc_id = i.id AND dr.rule_type = 'spl'
          )
        ORDER BY s.score DESC
        """,
        (MIN_SCORE_FOR_RULE,),
    ).fetchall()

    total = len(rows)
    done  = 0
    print(f"[SPL] Generating queries for {total} IOCs ...")

    for row in rows:
        ioc    = dict(row)
        rtype  = ioc["type"]
        family = ioc.get("malware_family") or "unknown"
        tmpl   = SPL_TEMPLATES.get(rtype, DEFAULT_SPL)

        content = tmpl.format(
            value=ioc["value"].replace('"', '\\"'),
            confidence=ioc["confidence"],
            score=ioc["score"],
            family=family,
            feed=ioc["source_feed"],
            ioc_type=rtype,
        )

        title = f"SPL: Detect {rtype.upper()} - {ioc['value'][:40]} ({family})"
        rid   = str(uuid.uuid4())

        conn.execute(
            """
            INSERT OR IGNORE INTO detection_rules
                (ioc_id, rule_type, rule_id, title, content, file_path, generated_at)
            VALUES (?, 'spl', ?, ?, ?, NULL, ?)
            """,
            (ioc["id"], rid, title, content, _now()),
        )
        done += 1

    conn.commit()
    conn.close()
    print(f"[SPL] Done — {done} SPL queries generated.")
    return {"spl_rules": done}