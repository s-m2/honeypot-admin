import sqlite3
import hashlib
import os
from contextlib import contextmanager
from pathlib import Path

# Use configurable path for database - defaults to local data/ for development
DB_DIR = Path(os.environ.get("HONEYPOT_DATA_DIR", "data"))
DB_PATH = DB_DIR / "honeypot.db"

SALT = "honeypot-salt-2024"  # In production, use a proper secret

_initialized = False


def _ensure_init():
    global _initialized
    if not _initialized:
        DB_DIR.mkdir(parents=True, exist_ok=True)
        _init_db()
        _initialized = True


def _init_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    # Users table - with a default weak admin user
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Check if admin exists, if not create with weak password
    cur.execute("SELECT id FROM users WHERE username = 'admin'")
    if not cur.fetchone():
        from passlib.hash import bcrypt
        weak_hash = bcrypt.hash("MissionControl2024!")
        cur.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
            ("admin", weak_hash)
        )
    
    # Hidden operator account - cannot be reset, separate from vulnerable admin
    cur.execute("SELECT id FROM users WHERE username = 'operator'")
    if not cur.fetchone():
        from passlib.hash import bcrypt
        # Strong password, not exposed anywhere
        operator_hash = bcrypt.hash("OperatorAccess2024!Secure")
        cur.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
            ("operator", operator_hash)
        )
    
    # Guestbook table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS guestbook (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            message TEXT NOT NULL,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_guestbook_ip ON guestbook(ip_hash)
    """)
    
    # Migration: drop UNIQUE constraint on ip_hash if it exists (for existing databases)
    # SQLite doesn't support DROP CONSTRAINT directly, so we skip - existing DBs will keep it
    # New deployments won't have the UNIQUE constraint
    
    # Fake analytics tables for dashboard realism
    cur.execute("""
        CREATE TABLE IF NOT EXISTS analytics_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            event_data TEXT,
            correlation_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Migration: add correlation_id column if it doesn't exist (for existing databases)
    try:
        cur.execute("ALTER TABLE analytics_events ADD COLUMN correlation_id TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_analytics_correlation ON analytics_events(correlation_id)
    """)
    
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_analytics_type ON analytics_events(event_type)
    """)
    
    # Migration: guestbook table - remove UNIQUE constraint on ip_hash
    # SQLite doesn't support DROP CONSTRAINT, so recreate table if needed
    cur.execute("""
        SELECT sql FROM sqlite_master WHERE type='table' AND name='guestbook'
    """)
    row = cur.fetchone()
    if row and 'UNIQUE' in row['sql'].upper():
        # Recreate table without UNIQUE constraint
        cur.execute("""
            CREATE TABLE guestbook_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_hash TEXT NOT NULL,
                name TEXT NOT NULL,
                message TEXT NOT NULL,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            INSERT INTO guestbook_new (id, ip_hash, name, message, user_agent, created_at)
            SELECT id, ip_hash, name, message, user_agent, created_at FROM guestbook
        """)
        cur.execute("DROP TABLE guestbook")
        cur.execute("ALTER TABLE guestbook_new RENAME TO guestbook")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_guestbook_ip ON guestbook(ip_hash)")
    
    # Vulnerability reports table (honeypot trap for AI agents)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vuln_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_hash TEXT NOT NULL,
            ip TEXT,
            user_agent TEXT,
            vulnerability_text TEXT NOT NULL,
            correlation_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Rate limiting table for vuln reports
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vuln_report_ratelimit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_hash TEXT NOT NULL,
            correlation_id TEXT,
            request_count INTEGER DEFAULT 1,
            window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(ip_hash, correlation_id, window_start)
        )
    """)
    
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_vuln_ratelimit_ip ON vuln_report_ratelimit(ip_hash)
    """)
    
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_vuln_ratelimit_correlation ON vuln_report_ratelimit(correlation_id)
    """)
    
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_vuln_reports_ip ON vuln_reports(ip_hash)
    """)
    
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_vuln_reports_correlation ON vuln_reports(correlation_id)
    """)
    
    conn.commit()
    conn.close()


def get_db():
    _ensure_init()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db_cursor():
    _ensure_init()
    conn = get_db()
    try:
        yield conn.cursor()
        conn.commit()
    finally:
        conn.close()


def hash_ip(ip: str) -> str:
    return hashlib.sha256(f"{ip}{SALT}".encode()).hexdigest()[:16]


def get_db_size_mb() -> float:
    return DB_PATH.stat().st_size / (1024 * 1024) if DB_PATH.exists() else 0


def prune_old_entries(max_mb: float = 10):
    """Remove oldest entries if DB exceeds max_mb"""
    _ensure_init()
    if get_db_size_mb() > max_mb:
        with db_cursor() as cur:
            cur.execute("""
                DELETE FROM guestbook 
                WHERE id IN (
                    SELECT id FROM guestbook 
                    ORDER BY created_at ASC 
                    LIMIT 100
                )
            """)
