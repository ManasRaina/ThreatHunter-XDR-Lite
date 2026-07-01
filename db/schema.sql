-- ── IOC STORE ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS iocs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    value           TEXT    NOT NULL,
    type            TEXT    NOT NULL,
    source_feed     TEXT    NOT NULL,
    malware_family  TEXT,
    first_seen      TEXT    NOT NULL,
    last_seen       TEXT    NOT NULL,
    raw_tags        TEXT,
    is_actionable   INTEGER NOT NULL DEFAULT 0,
    UNIQUE(value, type)
);

-- ── ENRICHMENT ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS enrichments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id          INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    provider        TEXT    NOT NULL,
    result_json     TEXT    NOT NULL,
    enriched_at     TEXT    NOT NULL,
    UNIQUE(ioc_id, provider)
);

-- ── SCORES ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scores (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id          INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE UNIQUE,
    score           INTEGER NOT NULL,
    confidence      TEXT    NOT NULL,
    factors_json    TEXT    NOT NULL,
    scored_at       TEXT    NOT NULL
);

-- ── DETECTION RULES ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS detection_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id          INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    rule_type       TEXT    NOT NULL,
    rule_id         TEXT    NOT NULL UNIQUE,
    title           TEXT    NOT NULL,
    content         TEXT    NOT NULL,
    file_path       TEXT,
    generated_at    TEXT    NOT NULL
);

-- ── ALERTS ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id          INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    severity        TEXT    NOT NULL,
    title           TEXT    NOT NULL,
    description     TEXT    NOT NULL,
    source          TEXT    NOT NULL,
    created_at      TEXT    NOT NULL,
    UNIQUE(ioc_id, title, source)
);

-- ── FEED RUN LOG ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS feed_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_name       TEXT    NOT NULL,
    run_at          TEXT    NOT NULL,
    iocs_fetched    INTEGER DEFAULT 0,
    iocs_new        INTEGER DEFAULT 0,
    status          TEXT    NOT NULL,
    error_msg       TEXT,
    duration_sec    REAL
);

-- ── PIPELINE RUN LOG ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pipeline_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT    NOT NULL,
    finished_at     TEXT,
    stage           TEXT    NOT NULL,
    status          TEXT    NOT NULL,
    summary_json    TEXT
);

-- ── INDEXES ──────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_iocs_type       ON iocs(type);
CREATE INDEX IF NOT EXISTS idx_iocs_value      ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_feed       ON iocs(source_feed);
CREATE INDEX IF NOT EXISTS idx_iocs_actionable ON iocs(is_actionable);
CREATE INDEX IF NOT EXISTS idx_scores_score    ON scores(score DESC);
CREATE INDEX IF NOT EXISTS idx_scores_conf     ON scores(confidence);
CREATE INDEX IF NOT EXISTS idx_rules_type      ON detection_rules(rule_type);
CREATE INDEX IF NOT EXISTS idx_alerts_ioc      ON alerts(ioc_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created  ON alerts(created_at DESC);