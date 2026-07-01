"""
Sigma YAML rule generator.

Generates one Sigma detection rule per high-confidence IOC (score >= MIN_SCORE_FOR_RULE).
Rules are:
  - Written to output/sigma_rules/<rule_id>.yml
  - Stored in detection_rules table with rule_type='sigma'

Sigma spec reference: https://github.com/SigmaHQ/sigma/wiki/Specification
"""

import os
import uuid
from datetime import datetime, timezone

from config import MIN_SCORE_FOR_RULE, SIGMA_OUTPUT_DIR
from db.database import get_db


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y/%m/%d")


# ── Sigma YAML templates by IOC type ─────────────────────────────────────────

def _sigma_ip(value: str, family: str, feed: str, confidence: str, score: int, rule_id: str) -> str:
    return f"""title: Threat Intelligence - Malicious IP Detected
id: {rule_id}
status: experimental
description: >
  Detects network communication with known malicious IP {value} sourced from {feed}.
  Malware family: {family}. Risk score: {score}/100 ({confidence}).
references:
  - https://threatintel.local/iocs
author: ThreatIntelOS
date: {_today()}
tags:
  - attack.command_and_control
  - attack.t1071
logsource:
  category: network_connection
  product: windows
detection:
  selection_src:
    src_ip: '{value}'
  selection_dst:
    dst_ip: '{value}'
  condition: selection_src or selection_dst
fields:
  - src_ip
  - dst_ip
  - dst_port
  - User
falsepositives:
  - Legitimate traffic to this IP (verify before blocking)
level: {confidence}
"""


def _sigma_domain(value: str, family: str, feed: str, confidence: str, score: int, rule_id: str) -> str:
    return f"""title: Threat Intelligence - Malicious Domain Detected
id: {rule_id}
status: experimental
description: >
  Detects DNS resolution or web traffic to known malicious domain {value} sourced from {feed}.
  Malware family: {family}. Risk score: {score}/100 ({confidence}).
references:
  - https://threatintel.local/iocs
author: ThreatIntelOS
date: {_today()}
tags:
  - attack.command_and_control
  - attack.t1071.004
  - attack.exfiltration
logsource:
  category: dns
product: windows
detection:
  selection:
    QueryName|contains: '{value}'
  condition: selection
fields:
  - QueryName
  - QueryResults
  - Image
falsepositives:
  - None expected
level: {confidence}
"""


def _sigma_url(value: str, family: str, feed: str, confidence: str, score: int, rule_id: str) -> str:
    # Escape single quotes in URL values for YAML safety
    safe_value = value.replace("'", "\\'")
    return f"""title: Threat Intelligence - Malicious URL Detected
id: {rule_id}
status: experimental
description: >
  Detects HTTP/HTTPS requests to known malicious URL sourced from {feed}.
  Malware family: {family}. Risk score: {score}/100 ({confidence}).
references:
  - https://threatintel.local/iocs
author: ThreatIntelOS
date: {_today()}
tags:
  - attack.initial_access
  - attack.t1566.002
  - attack.command_and_control
logsource:
  category: proxy
product: windows
detection:
  selection:
    c-uri|contains: '{safe_value}'
  condition: selection
fields:
  - c-uri
  - c-ip
  - cs-username
  - cs-host
falsepositives:
  - None expected for exact URL match
level: {confidence}
"""


def _sigma_hash(value: str, hash_type: str, family: str, feed: str, confidence: str, score: int, rule_id: str) -> str:
    hash_field = "md5" if hash_type == "md5" else "sha256"
    attack_tag = "attack.t1204.002"
    return f"""title: Threat Intelligence - Malicious File Hash Detected
id: {rule_id}
status: experimental
description: >
  Detects execution or presence of file with known malicious {hash_type.upper()} hash from {feed}.
  Malware family: {family}. Risk score: {score}/100 ({confidence}).
references:
  - https://threatintel.local/iocs
author: ThreatIntelOS
date: {_today()}
tags:
  - attack.execution
  - {attack_tag}
  - attack.defense_evasion
logsource:
  category: file_event
  product: windows
detection:
  selection:
    {hash_field}|contains: '{value}'
  condition: selection
fields:
  - FileName
  - {hash_field}
  - Image
  - User
falsepositives:
  - None expected for known-bad hash
level: {confidence}
"""


# Dispatch table
_TEMPLATE_DISPATCH = {
    "ip":     _sigma_ip,
    "domain": _sigma_domain,
    "url":    _sigma_url,
    "md5":    lambda v, f, fd, c, s, r: _sigma_hash(v, "md5",    f, fd, c, s, r),
    "sha256": lambda v, f, fd, c, s, r: _sigma_hash(v, "sha256", f, fd, c, s, r),
}


def _build_sigma(ioc: dict, score: int, confidence: str, rule_id: str) -> str:
    itype   = ioc["type"]
    value   = ioc["value"]
    family  = ioc.get("malware_family") or "unknown"
    feed    = ioc.get("source_feed", "unknown")

    builder = _TEMPLATE_DISPATCH.get(itype, _sigma_url)
    return builder(value, family, feed, confidence, score, rule_id)


# ── Main entry point ──────────────────────────────────────────────────────────

def generate() -> dict:
    os.makedirs(SIGMA_OUTPUT_DIR, exist_ok=True)
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
              WHERE dr.ioc_id = i.id AND dr.rule_type = 'sigma'
          )
        ORDER BY s.score DESC
        """,
        (MIN_SCORE_FOR_RULE,),
    ).fetchall()

    total = len(rows)
    done  = 0
    print(f"[Sigma] Generating rules for {total} IOCs (score >= {MIN_SCORE_FOR_RULE}) ...")

    for row in rows:
        ioc        = dict(row)
        rule_id    = str(uuid.uuid4())
        score      = ioc["score"]
        confidence = ioc["confidence"]

        content = _build_sigma(ioc, score, confidence, rule_id)

        # Write to disk
        fname    = f"{rule_id[:8]}.yml"
        filepath = os.path.join(SIGMA_OUTPUT_DIR, fname)
        try:
            with open(filepath, "w", encoding="utf-8") as fh:
                fh.write(content)
        except OSError as exc:
            print(f"[Sigma] Warning: could not write {filepath}: {exc}")
            filepath = None

        title = (
            f"Sigma: Detect {ioc['type'].upper()} - "
            f"{ioc['value'][:40]} ({ioc.get('malware_family') or 'unknown'})"
        )

        conn.execute(
            """
            INSERT OR IGNORE INTO detection_rules
                (ioc_id, rule_type, rule_id, title, content, file_path, generated_at)
            VALUES (?, 'sigma', ?, ?, ?, ?, ?)
            """,
            (ioc["id"], rule_id, title, content, filepath, _now()),
        )
        done += 1

    conn.commit()
    conn.close()
    print(f"[Sigma] Done — {done} Sigma rules generated.")
    return {"sigma_rules": done}
