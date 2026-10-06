-- Additive outbox. No edits to existing calendars, credentials or portal records.
CREATE TABLE IF NOT EXISTS google_calendar_write_grants (
  owner TEXT PRIMARY KEY NOT NULL, connection_version TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS google_calendar_write_states (
  state_hash TEXT PRIMARY KEY NOT NULL
);
CREATE TABLE IF NOT EXISTS google_calendar_outbound_targets (
  owner TEXT NOT NULL, school TEXT NOT NULL, year TEXT NOT NULL,
  since_date TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0,
  revision INTEGER NOT NULL DEFAULT 1, synced_revision INTEGER NOT NULL DEFAULT 0,
  lease_token TEXT, lease_until TEXT, retry_at TEXT,
  last_synced_at TEXT, last_error TEXT,
  PRIMARY KEY(owner,school,year)
);
CREATE TABLE IF NOT EXISTS google_calendar_outbound_events (
  owner TEXT NOT NULL, school TEXT NOT NULL, year TEXT NOT NULL, local_id TEXT NOT NULL,
  google_id TEXT NOT NULL, synced_hash TEXT, cancelled INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(owner,school,year,local_id), UNIQUE(owner,google_id)
);
CREATE TRIGGER IF NOT EXISTS google_calendar_outbound_insert AFTER INSERT ON portal_data
WHEN NEW.type='calendar' BEGIN
  UPDATE google_calendar_outbound_targets SET revision=revision+1,retry_at=NULL
    WHERE enabled=1 AND school=NEW.school AND year=NEW.year;
END;
CREATE TRIGGER IF NOT EXISTS google_calendar_outbound_update AFTER UPDATE OF payload ON portal_data
WHEN NEW.type='calendar' AND OLD.payload IS NOT NEW.payload BEGIN
  UPDATE google_calendar_outbound_targets SET revision=revision+1,retry_at=NULL
    WHERE enabled=1 AND school=NEW.school AND year=NEW.year;
END;
