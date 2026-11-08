-- DiskGuardian local schema (SQLite).
-- Everything stays on this machine. No browser credentials, cookies, history or
-- autofill data is ever stored, and there is no table for them by design.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_sessions (
    scan_id      TEXT PRIMARY KEY,
    scan_type    TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    completed_at TEXT,
    status       TEXT NOT NULL,
    summary_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_scan_sessions_type_time
    ON scan_sessions (scan_type, started_at DESC);

CREATE TABLE IF NOT EXISTS findings (
    finding_id         TEXT PRIMARY KEY,
    scan_id            TEXT NOT NULL REFERENCES scan_sessions (scan_id) ON DELETE CASCADE,
    category           TEXT NOT NULL,
    target             TEXT NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    evidence_json      TEXT NOT NULL DEFAULT '[]',
    risk_level         TEXT NOT NULL DEFAULT 'unknown',
    confidence         REAL,
    recommended_action TEXT NOT NULL DEFAULT 'review'
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings (category, risk_level);

CREATE TABLE IF NOT EXISTS software_inventory (
    software_id      TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    version          TEXT,
    publisher        TEXT,
    install_location TEXT,
    uninstall_string TEXT,
    signature_status TEXT,
    risk_level       TEXT NOT NULL DEFAULT 'unknown',
    evidence_json    TEXT NOT NULL DEFAULT '[]',
    scanned_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_software_name ON software_inventory (name);

CREATE TABLE IF NOT EXISTS browser_inventory (
    browser_id     TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    profile_path   TEXT NOT NULL,
    extensions_json TEXT NOT NULL DEFAULT '[]',
    settings_json  TEXT NOT NULL DEFAULT '{}',
    scanned_at     TEXT NOT NULL,
    UNIQUE (name, profile_path)
);

CREATE TABLE IF NOT EXISTS action_plans (
    plan_id           TEXT PRIMARY KEY,
    plan_type         TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'pending',
    risk_level        TEXT NOT NULL,
    plan_hash         TEXT NOT NULL,
    requires_approval INTEGER NOT NULL DEFAULT 1,
    summary_json      TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_action_plans_status ON action_plans (status, created_at DESC);

CREATE TABLE IF NOT EXISTS action_items (
    item_id        TEXT PRIMARY KEY,
    plan_id        TEXT NOT NULL REFERENCES action_plans (plan_id) ON DELETE CASCADE,
    action_type    TEXT NOT NULL,
    target         TEXT NOT NULL,
    target_hash    TEXT NOT NULL,
    metadata_json  TEXT NOT NULL DEFAULT '{}',
    order_index    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_action_items_plan ON action_items (plan_id, order_index);

-- One-time, hash-bound authorization. The engine writes these rows; the plugin
-- only ever receives an opaque approval_id.
CREATE TABLE IF NOT EXISTS approval_records (
    approval_id          TEXT PRIMARY KEY,
    plan_id              TEXT NOT NULL REFERENCES action_plans (plan_id) ON DELETE CASCADE,
    plan_hash            TEXT NOT NULL,
    target_manifest_hash TEXT NOT NULL,
    approved_at          TEXT NOT NULL,
    expires_at           TEXT NOT NULL,
    used                 INTEGER NOT NULL DEFAULT 0,
    used_at              TEXT,
    approval_source      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_approvals_plan ON approval_records (plan_id);

CREATE TABLE IF NOT EXISTS action_logs (
    audit_id    TEXT PRIMARY KEY,
    plan_id     TEXT,
    action_id   TEXT,
    operation   TEXT NOT NULL,
    target      TEXT,
    result      TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_action_logs_time ON action_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_action_logs_plan ON action_logs (plan_id);

CREATE TABLE IF NOT EXISTS quarantine_records (
    quarantine_id   TEXT PRIMARY KEY,
    original_path   TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    sha256          TEXT NOT NULL,
    plan_id         TEXT,
    quarantined_at  TEXT NOT NULL,
    restored_at     TEXT,
    purged_at       TEXT,
    status          TEXT NOT NULL DEFAULT 'quarantined'
);

CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine_records (status, quarantined_at DESC);

-- Reversible startup-entry changes: the original value is kept here so the
-- entry can be restored exactly, and so "disabled by DiskGuardian" is a fact
-- recorded in the database rather than an assumption.
CREATE TABLE IF NOT EXISTS startup_changes (
    change_id   TEXT PRIMARY KEY,
    hive        TEXT NOT NULL,
    key_path    TEXT NOT NULL,
    view        INTEGER NOT NULL,
    value_name  TEXT NOT NULL,
    value_data  TEXT NOT NULL,
    plan_id     TEXT,
    changed_at  TEXT NOT NULL,
    restored_at TEXT,
    status      TEXT NOT NULL DEFAULT 'disabled'
);

CREATE INDEX IF NOT EXISTS idx_startup_changes_status ON startup_changes (status, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_startup_changes_target ON startup_changes (hive, key_path, value_name);

