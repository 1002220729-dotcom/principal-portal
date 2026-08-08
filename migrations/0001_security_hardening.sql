-- Security schema upgrade for principal-db.
-- Applied after a full D1 export and Time Travel bookmark are recorded.
-- Existing business data is preserved. Existing legacy login sessions are
-- intentionally invalidated because the previous table stored raw tokens.

ALTER TABLE staff_auth
  ADD COLUMN password_iterations INTEGER NOT NULL DEFAULT 100000;

ALTER TABLE staffsessions RENAME TO staffsessions_legacy_20260808;

CREATE TABLE staffsessions (
  token_hash      TEXT PRIMARY KEY,
  username        TEXT NOT NULL,
  school          TEXT,
  year            TEXT,
  role            TEXT NOT NULL,
  created_at      TEXT NOT NULL,
  expires_at      TEXT NOT NULL,
  last_seen_at    TEXT NOT NULL,
  revoked_at      TEXT,
  ip_hash         TEXT,
  user_agent_hash TEXT
);

DROP TABLE staffsessions_legacy_20260808;

CREATE INDEX idx_staffsessions_username
  ON staffsessions(username);
CREATE INDEX idx_staffsessions_expires_at
  ON staffsessions(expires_at);

CREATE TABLE audit_log (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at     TEXT NOT NULL,
  request_id      TEXT,
  actor_username  TEXT,
  actor_role      TEXT,
  actor_school    TEXT,
  action          TEXT NOT NULL,
  resource_type   TEXT,
  resource_id     TEXT,
  target_school   TEXT,
  target_year     TEXT,
  outcome         TEXT,
  ip_hash         TEXT,
  user_agent_hash TEXT,
  metadata_json   TEXT
);

CREATE INDEX idx_audit_log_occurred_at
  ON audit_log(occurred_at);
CREATE INDEX idx_audit_log_actor
  ON audit_log(actor_username, occurred_at);

CREATE INDEX IF NOT EXISTS idx_portal_data_type_school_year
  ON portal_data(type, school, year);
CREATE INDEX IF NOT EXISTS idx_inventory_school_year
  ON inventory(school, year);
CREATE INDEX IF NOT EXISTS idx_budget_entries_school_year
  ON budget_entries(school, year);
CREATE INDEX IF NOT EXISTS idx_budget_allocations_school_year
  ON budget_allocations(school, year);
CREATE INDEX IF NOT EXISTS idx_teacher_entries_status_updated
  ON teacher_entries(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_teacher_bonuses_status_updated
  ON teacher_bonuses(status, updated_at);
