import sqlite3

from flask import current_app, g

SCHEMA = r"""
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, email TEXT, phone TEXT, verification_method TEXT NOT NULL,
 verification_code TEXT, verified INTEGER NOT NULL DEFAULT 0, role TEXT NOT NULL DEFAULT 'user',
 active INTEGER NOT NULL DEFAULT 1, avatar_path TEXT, otp_secret TEXT, otp_enabled INTEGER NOT NULL DEFAULT 0,
 oauth_provider TEXT, oauth_subject TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, session_id TEXT UNIQUE NOT NULL,
 ip TEXT, user_agent TEXT, client_geo TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 expires_at TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, last_seen_at TEXT,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS api_keys (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT NOT NULL, key_hash TEXT UNIQUE NOT NULL,
 key_prefix TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 last_used_at TEXT, FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS external_tokens (
 id INTEGER PRIMARY KEY AUTOINCREMENT, owner_user_id INTEGER, name TEXT NOT NULL, provider TEXT,
 token_ciphertext TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(owner_user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS uploads (
 id TEXT PRIMARY KEY, owner_user_id INTEGER NOT NULL, original_name TEXT NOT NULL, stored_name TEXT,
 content_type TEXT, size_bytes INTEGER NOT NULL DEFAULT 0, received_bytes INTEGER NOT NULL DEFAULT 0,
 status TEXT NOT NULL DEFAULT 'created', storage_backend TEXT NOT NULL DEFAULT 'local', object_key TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, completed_at TEXT, FOREIGN KEY(owner_user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS file_shares (
 id INTEGER PRIMARY KEY AUTOINCREMENT, upload_id TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL,
 expires_at TEXT, active INTEGER NOT NULL DEFAULT 1, created_by INTEGER NOT NULL,
 FOREIGN KEY(upload_id) REFERENCES uploads(id), FOREIGN KEY(created_by) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS request_logs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL, ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 user_id INTEGER, method TEXT, path TEXT, status_code INTEGER, remote_addr TEXT, duration_ms REAL
);
CREATE TABLE IF NOT EXISTS captures (
 id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, source TEXT NOT NULL,
 method TEXT, url TEXT, scheme TEXT, host TEXT, path TEXT, client_ip TEXT, user_agent TEXT, client_geo TEXT,
 request_headers TEXT, response_headers TEXT, cookies TEXT, query_params TEXT, body_params TEXT, status_code INTEGER
);
CREATE TABLE IF NOT EXISTS token_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, capture_id INTEGER, ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 token_hash TEXT NOT NULL, token_preview TEXT, token_kind TEXT, location TEXT, name TEXT, client_ip TEXT,
 user_agent TEXT, client_geo TEXT, expires_at TEXT, FOREIGN KEY(capture_id) REFERENCES captures(id)
);
CREATE TABLE IF NOT EXISTS findings (
 id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, capture_id INTEGER,
 rule_id TEXT NOT NULL, severity TEXT NOT NULL, category TEXT NOT NULL, title TEXT NOT NULL, evidence TEXT,
 recommendation TEXT, status TEXT NOT NULL DEFAULT 'open', FOREIGN KEY(capture_id) REFERENCES captures(id)
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS attack_tests (
 id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, attack_type TEXT NOT NULL,
 target TEXT NOT NULL, success INTEGER NOT NULL, details TEXT
);
"""
DEFAULT_SETTINGS={
 'rule.token_in_url':'1','rule.token_over_http':'1','rule.cookie_secure':'1','rule.cookie_httponly':'1',
 'rule.cookie_samesite':'1','rule.token_multi_client':'1','rule.expired_token_reuse':'1','rule.geo_change':'1',
 'session_ttl_minutes':'30','geo_change_enabled':'1','registration_enabled':'1'
}
def get_db():
    if 'db' not in g:
        g.db=sqlite3.connect(current_app.config['DATABASE']); g.db.row_factory=sqlite3.Row
    return g.db

def close_db(_=None):
    db=g.pop('db',None)
    if db is not None: db.close()

def _column(db, table, name, ddl):
    cols={r[1] for r in db.execute(f'PRAGMA table_info({table})')}
    if name not in cols: db.execute(f'ALTER TABLE {table} ADD COLUMN {name} {ddl}')

def init_db(app):
    with app.app_context():
        db=sqlite3.connect(app.config['DATABASE']); db.executescript(SCHEMA)
        for table,name,ddl in [('users','active','INTEGER NOT NULL DEFAULT 1'),('users','avatar_path','TEXT'),('users','otp_secret','TEXT'),('users','otp_enabled','INTEGER NOT NULL DEFAULT 0'),('users','oauth_provider','TEXT'),('users','oauth_subject','TEXT'),('sessions','last_seen_at','TEXT')]: _column(db,table,name,ddl)
        for k,v in DEFAULT_SETTINGS.items(): db.execute('INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)',(k,v))
        db.commit(); db.close()
    app.teardown_appcontext(close_db)
