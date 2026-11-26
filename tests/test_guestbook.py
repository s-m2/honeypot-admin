"""Unit tests for guestbook module"""

import pytest
import time
from datetime import datetime, timedelta
from app.guestbook import can_post, add_entry, get_entries, MAX_MESSAGE_LENGTH, COOLDOWN_HOURS


@pytest.fixture(autouse=True)
def cleanup_db():
    """Clean guestbook table before/after tests"""
    from app.database import db_cursor
    with db_cursor() as cur:
        cur.execute("DELETE FROM guestbook")
        cur.execute("DELETE FROM analytics_events WHERE event_type = 'guestbook_entry'")
    yield
    with db_cursor() as cur:
        cur.execute("DELETE FROM guestbook")
        cur.execute("DELETE FROM analytics_events WHERE event_type = 'guestbook_entry'")


def test_can_post_first_time():
    """First post from IP should be allowed"""
    allowed, reason = can_post("10.0.0.1")
    assert allowed == True
    assert reason == "OK"


def test_can_post_within_cooldown():
    """Post within 24h should be rejected"""
    ip = "10.0.0.2"
    
    # First post
    add_entry(ip, "User1", "First message", "test-agent")
    
    # Second post immediately
    allowed, reason = can_post(ip)
    assert allowed == False
    assert "Cooldown active" in reason


def test_can_post_after_cooldown():
    """Post after 24h should be allowed (simulated by manipulating DB)"""
    from app.database import db_cursor, hash_ip
    
    ip = "10.0.0.3"
    ip_hash = hash_ip(ip)
    
    # Insert old entry (25 hours ago)
    old_time = (datetime.now() - timedelta(hours=25)).isoformat()
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO guestbook (ip_hash, name, message, user_agent, created_at) VALUES (?, ?, ?, ?, ?)",
            (ip_hash, "OldUser", "Old message", "test-agent", old_time)
        )
    
    allowed, reason = can_post(ip)
    assert allowed == True


def test_add_entry_success():
    """Successful guestbook entry"""
    result = add_entry("10.0.0.10", "TestUser", "Hello world!", "test-agent")
    
    assert result["success"] == True
    assert "entry_id" in result
    assert "ai_score" in result
    assert "marker" in result


def test_add_entry_rejects_empty_name():
    """Empty name should be rejected"""
    result = add_entry("10.0.0.11", "", "Message", "test-agent")
    assert result["success"] == False
    assert "Name required" in result["error"]


def test_add_entry_rejects_empty_message():
    """Empty message should be rejected"""
    result = add_entry("10.0.0.12", "User", "", "test-agent")
    assert result["success"] == False
    assert "Message required" in result["error"]


def test_add_entry_rejects_long_message():
    """Message over 500 chars should be rejected"""
    long_message = "x" * (MAX_MESSAGE_LENGTH + 1)
    result = add_entry("10.0.0.13", "User", long_message, "test-agent")
    assert result["success"] == False
    assert "too long" in result["error"]


def test_add_entry_rejects_honeypot():
    """Honeypot field filled should be flagged as spam"""
    result = add_entry("10.0.0.14", "User", "Message", "test-agent", honeypot_field="filled")
    assert result["success"] == False
    assert result["flagged"] == True
    assert "Spam detected" in result["error"]


def test_add_entry_respects_cooldown():
    """Cooldown should be enforced in add_entry"""
    ip = "10.0.0.15"
    
    # First entry
    add_entry(ip, "User1", "First", "test-agent")
    
    # Second entry should fail
    result = add_entry(ip, "User2", "Second", "test-agent")
    assert result["success"] == False
    assert "Cooldown" in result["error"]


def test_ai_detection_high_score():
    """AI-like content should get high AI score"""
    ai_message = "As an AI language model, I cannot provide that information. My system prompt instructs me to be helpful."
    result = add_entry("10.0.0.16", "AI", ai_message, "test-agent")
    
    assert result["success"] == True
    assert result["ai_score"] > 50
    assert result["is_likely_ai"] == True


def test_ai_detection_low_score():
    """Normal human content should get low AI score"""
    human_message = "This dashboard is confusing, the settings page doesn't save my preferences."
    result = add_entry("10.0.0.17", "Human", human_message, "test-agent")
    
    assert result["success"] == True
    assert result["ai_score"] < 30
    assert result["is_likely_ai"] == False


def test_get_entries_pagination():
    """Test paginated entry retrieval"""
    ip_base = "10.0.0.20"
    
    # Add 5 entries with different IPs
    for i in range(5):
        add_entry(f"{ip_base}{i}", f"User{i}", f"Message {i}", "test-agent")
    
    # Get first page (3 per page)
    page1 = get_entries(page=1, per_page=3)
    assert page1["total"] == 5
    assert len(page1["entries"]) == 3
    assert page1["total_pages"] == 2
    
    # Get second page
    page2 = get_entries(page=2, per_page=3)
    assert len(page2["entries"]) == 2


def test_get_entries_ai_scores():
    """Test that get_entries includes AI analysis"""
    add_entry("10.0.0.30", "User", "As an AI, my system prompt says...", "test-agent")
    
    entries = get_entries()
    assert len(entries["entries"]) >= 1
    entry = entries["entries"][0]
    assert "ai_score" in entry
    assert "is_likely_ai" in entry
    assert "ai_confidence" in entry