-- Additive only. Never touches portal_data, shared calendar records or sessions.
CREATE TABLE IF NOT EXISTS private_google_calendar_connections (
  owner TEXT PRIMARY KEY NOT NULL,
  google_sub TEXT NOT NULL,
  refresh_cipher TEXT NOT NULL,
  version TEXT NOT NULL,
  connected_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS private_google_calendar_states (
  state_hash TEXT PRIMARY KEY NOT NULL,
  owner TEXT NOT NULL,
  session_hash TEXT NOT NULL,
  verifier_cipher TEXT NOT NULL,
  claimed_at TEXT,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_private_google_calendar_state_expiry
  ON private_google_calendar_states(expires_at);
CREATE INDEX IF NOT EXISTS idx_private_google_calendar_state_owner
  ON private_google_calendar_states(owner);
