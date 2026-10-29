CREATE TABLE IF NOT EXISTS accounts (
  user_id TEXT NOT NULL,
  id TEXT NOT NULL,
  name TEXT NOT NULL,
  token TEXT NOT NULL,
  zone_hint TEXT,
  active INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, id)
);

CREATE INDEX IF NOT EXISTS idx_accounts_user ON accounts (user_id);

CREATE TABLE IF NOT EXISTS sessions (
  user_id TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS seen_updates (
  user_id TEXT NOT NULL,
  update_id INTEGER NOT NULL,
  seen_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, update_id)
);

CREATE INDEX IF NOT EXISTS idx_seen_at ON seen_updates (seen_at);
