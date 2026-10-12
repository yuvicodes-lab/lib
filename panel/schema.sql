-- CrackLib panel schema (D1). Apply: wrangler d1 execute crack --file=schema.sql

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE,
  pass_hash TEXT NOT NULL,
  pass_salt TEXT NOT NULL,
  ref_code TEXT NOT NULL UNIQUE,
  referred_by INTEGER,
  blocked INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_urls (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  panel_url TEXT NOT NULL DEFAULT '',
  endpoints TEXT NOT NULL DEFAULT '["/connect","/server","/api/verify","/api.php","/api/license"]',
  target TEXT NOT NULL DEFAULT '',
  refresh INTEGER NOT NULL DEFAULT 300,
  updated_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS pkgs (
  pkg TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS hits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  pkg TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hits_user ON hits(user_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_hits_time ON hits(created_at DESC);
