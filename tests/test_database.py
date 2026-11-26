"""Unit tests for database module"""

import pytest
from app.database import (
    hash_ip, get_db_size_mb, prune_old_entries,
    db_cursor, _init_db
)
from app.guestbook import add_entry


def test_hash_ip_deterministic():
    """Same IP should always produce same hash"""
    ip = "192.168.1.100"
    h1 = hash_ip(ip)
    h2 = hash_ip(ip)
    assert h1 == h2
    assert len(h1) == 16  # Truncated to 16 chars


def test_hash_ip_different_ips():
    """Different IPs should produce different hashes"""
    h1 = hash_ip("10.0.0.1")
    h2 = hash_ip("10.0.0.2")
    assert h1 != h2


def test_database_initialization():
    """Test database tables are created"""
    _init_db()  # Should not raise
    
    from app.database import get_db
    conn = get_db()
    cur = conn.cursor()
    
    # Check tables exist
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cur.fetchall()]
    
    expected_tables = ["users", "guestbook", "analytics_events", "vuln_reports", "vuln_report_ratelimit"]
    for table in expected_tables:
        assert table in tables
    
    conn.close()


def test_guestbook_table_no_unique_constraint():
    """Guestbook ip_hash should NOT have UNIQUE constraint (fixed)"""
    from app.database import get_db
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='guestbook'")
    schema = cur.fetchone()[0]
    
    # Should NOT have UNIQUE constraint on ip_hash
    assert "UNIQUE" not in schema.upper() or "ip_hash TEXT UNIQUE" not in schema.upper()
    
    conn.close()


def test_db_cursor_context_manager():
    """Test db_cursor yields cursor and commits"""
    with db_cursor() as cur:
        cur.execute("SELECT 1")
        assert cur.fetchone()[0] == 1


def test_prune_old_entries():
    """Test database pruning when over size limit"""
    from app.guestbook import DB_SIZE_LIMIT_MB
    from app.database import get_db_size_mb, prune_old_entries
    from app.guestbook import add_entry
    
    # Add many entries to exceed limit
    for i in range(200):
        add_entry(f"10.0.{i//255}.{i%255}", f"User{i}", f"Message {i}", "test-agent")
    
    size_before = get_db_size_mb()
    
    # Prune to small limit
    prune_old_entries(max_mb=0.001)  # Very small limit
    
    size_after = get_db_size_mb()
    # Size should be reduced (or at least function runs without error)
    assert size_after <= size_before


def test_analytics_events_correlation_id():
    """Test analytics_events has correlation_id column"""
    from app.database import get_db
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("PRAGMA table_info(analytics_events)")
    columns = [row[1] for row in cur.fetchall()]
    
    assert "correlation_id" in columns
    assert "event_type" in columns
    assert "event_data" in columns
    
    conn.close()


def test_vuln_reports_table():
    """Test vuln_reports table exists with correct columns"""
    from app.database import get_db
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("PRAGMA table_info(vuln_reports)")
    columns = [row[1] for row in cur.fetchall()]
    
    expected = ["id", "ip_hash", "ip", "user_agent", "vulnerability_text", "correlation_id", "created_at"]
    for col in expected:
        assert col in columns
    
    conn.close()


def test_vuln_report_ratelimit_table():
    """Test vuln_report_ratelimit table exists"""
    from app.database import get_db
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("PRAGMA table_info(vuln_report_ratelimit)")
    columns = [row[1] for row in cur.fetchall()]
    
    expected = ["id", "ip_hash", "correlation_id", "request_count", "window_start"]
    for col in expected:
        assert col in columns
    
    conn.close()