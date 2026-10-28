-- Skema D1 untuk cf-dns-bot
-- Jalankan: npx wrangler d1 execute cf-dns-bot --remote --file=./schema.sql

CREATE TABLE IF NOT EXISTS accounts (
  user_id    TEXT NOT NULL,
  id         TEXT NOT NULL,          -- id internal bot, mis. "01"
  name       TEXT NOT NULL,          -- nama custom dari user
  token      TEXT NOT NULL,          -- API token Cloudflare (terenkripsi AES-GCM)
  zone_hint  TEXT,                   -- domain pertama saat verifikasi, hanya info
  active     INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, id)
);

CREATE INDEX IF NOT EXISTS idx_accounts_user ON accounts (user_id);

-- Sesi wizard / state navigasi per user
CREATE TABLE IF NOT EXISTS sessions (
  user_id    TEXT PRIMARY KEY,
  state      TEXT NOT NULL,          -- JSON: {s, p}
  updated_at INTEGER NOT NULL
);

-- Dedupe update Telegram
CREATE TABLE IF NOT EXISTS seen_updates (
  user_id    TEXT NOT NULL,
  update_id  INTEGER NOT NULL,
  seen_at    INTEGER NOT NULL,
  PRIMARY KEY (user_id, update_id)
);

CREATE INDEX IF NOT EXISTS idx_seen_at ON seen_updates (seen_at);
