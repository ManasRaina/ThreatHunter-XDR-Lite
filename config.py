import os
from dotenv import load_dotenv

load_dotenv()

# ── API Keys ──────────────────────────────────────────────────────────────────
VT_API_KEY        = os.getenv("VT_API_KEY", "").strip()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
OTX_API_KEY       = os.getenv("OTX_API_KEY", "").strip()
FLASK_SECRET_KEY  = os.getenv("FLASK_SECRET_KEY", "dev-secret")

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR         = os.path.dirname(os.path.abspath(__file__))
DB_PATH          = os.path.join(BASE_DIR, "db", "tip.db")
SCHEMA_PATH      = os.path.join(BASE_DIR, "db", "schema.sql")
SIGMA_OUTPUT_DIR = os.path.join(BASE_DIR, "output", "sigma_rules")

# ── Feed config ───────────────────────────────────────────────────────────────
FEEDS = {
    "urlhaus": {
        "url":     "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "enabled": True,
    },
    "threatfox": {
        "url":     "https://threatfox-api.abuse.ch/api/v1/",
        "enabled": True,
    },
    "otx": {
        "url":     "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "enabled": bool(OTX_API_KEY),
    },
}

# ── Enrichment ────────────────────────────────────────────────────────────────
ENRICHMENT_LIMIT = 5          # cap per pipeline run
VT_RATE_SLEEP    = 15           # free tier: 4 req/min → 15s between calls
ABUSEIPDB_SLEEP  = 1

# ── Scoring ───────────────────────────────────────────────────────────────────
SCORE_BANDS = {
    "critical": (76, 100),
    "high":     (51, 75),
    "medium":   (26, 50),
    "low":      (0,  25),
}
MIN_SCORE_FOR_RULE = 50         # only generate rules above this threshold

# ── Flask ─────────────────────────────────────────────────────────────────────
FLASK_HOST  = "0.0.0.0"
FLASK_PORT  = 5001
FLASK_DEBUG = False