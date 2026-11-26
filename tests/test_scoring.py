"""Unit tests for behavioral scoring engine"""

import pytest
import time
from app.scoring import (
    BehavioralScoringEngine,
    SCORING_WEIGHTS,
    ATTACK_CHAINS,
    get_scoring_engine,
    process_analytics_event,
)


@pytest.fixture(autouse=True)
def reset_engine():
    """Reset scoring engine between tests"""
    engine = get_scoring_engine()
    engine.sessions.clear()
    yield
    engine.sessions.clear()


def test_scoring_weights_defined():
    """Verify all expected scoring weights exist"""
    expected_weights = [
        "login_failed", "login_success", "login_rate_limited", "login_sqli_detected",
        "fake_endpoint_access", "fake_endpoint_repeated", "fake_admin_api_access",
        "fake_ai_config_access", "robots_txt_access", "debug_endpoint_access",
        "guestbook_spam", "guestbook_ai_detected", "guestbook_honeypot_triggered",
        "reset_token_requested", "reset_token_used", "reset_token_operator_attempt",
        "rapid_requests", "user_agent_anomaly", "ip_reputation_bad",
        "credential_stuffing_pattern", "path_enumeration",
        "threat_score_high", "tor_exit_node", "vpn_detected", "proxy_detected", "hosting_provider",
    ]
    
    for weight in expected_weights:
        assert weight in SCORING_WEIGHTS, f"Missing weight: {weight}"
    
    # SQLi should be highest weight
    assert SCORING_WEIGHTS["login_sqli_detected"] == 50
    assert SCORING_WEIGHTS["login_failed"] == 5


def test_attack_chains_defined():
    """Verify all attack chain definitions exist"""
    expected_chains = [
        "credential_stuffing", "sql_injection", "reconnaissance",
        "ai_probing", "account_takeover", "spam_campaign"
    ]
    
    for chain in expected_chains:
        assert chain in ATTACK_CHAINS
        assert "min_indicators" in ATTACK_CHAINS[chain]
        assert "min_score" in ATTACK_CHAINS[chain]
    
    # SQL injection should need only 1 indicator (high confidence)
    assert ATTACK_CHAINS["sql_injection"]["min_indicators"] == 1
    assert ATTACK_CHAINS["sql_injection"]["min_score"] == 40


def test_session_creation_and_scoring():
    """Test creating session and adding events"""
    engine = get_scoring_engine()
    
    correlation_id = "test-correlation-1"
    ip = "10.0.0.1"
    
    # Add a failed login
    event = {"ip": ip, "username": "admin", "result": "failed"}
    process_analytics_event(correlation_id, "login_attempt", event)
    
    session = engine.get_session(correlation_id)
    assert session is not None
    assert session.correlation_id == correlation_id
    assert session.ip == ip
    assert session.total_score == SCORING_WEIGHTS["login_failed"]
    assert "login_failed" in session.scores


def test_multiple_events_accumulate_score():
    """Test score accumulates across multiple events"""
    engine = get_scoring_engine()
    
    correlation_id = "test-correlation-2"
    ip = "10.0.0.2"
    
    # Failed login
    process_analytics_event(correlation_id, "login_attempt", {"ip": ip, "result": "failed"})
    
    # Fake endpoint access
    process_analytics_event(correlation_id, "fake_endpoint_access", {"ip": ip, "endpoint": "/_internal/debug"})
    
    session = engine.get_session(correlation_id)
    expected = SCORING_WEIGHTS["login_failed"] + SCORING_WEIGHTS["fake_endpoint_access"]
    assert session.total_score == expected


def test_sql_injection_detected():
    """Test SQL injection event adds high score"""
    engine = get_scoring_engine()
    
    correlation_id = "test-correlation-sqli"
    ip = "10.0.0.3"
    
    # SQL injection attempt - pass request_body with SQLi in username
    process_analytics_event(correlation_id, "login_attempt", {
        "ip": ip, 
        "result": "failed",
        "request_body": {"username": "admin' OR '1'='1", "password": "anything"}
    })
    
    session = engine.get_session(correlation_id)
    # Should have both failed login + sqli score
    assert session.total_score >= SCORING_WEIGHTS["login_sqli_detected"]


def test_attack_chain_detection_credential_stuffing():
    """Test credential stuffing chain detection"""
    engine = get_scoring_engine()
    
    correlation_id = "test-chain-credstuff"
    ip = "10.0.0.4"
    
    # Multiple failed logins (credential stuffing pattern)
    for i in range(5):
        process_analytics_event(correlation_id, "login_attempt", {"ip": ip, "result": "failed"})
    
    session = engine.get_session(correlation_id)
    assert "credential_stuffing" in session.attack_chains


def test_attack_chain_detection_sql_injection():
    """Test SQL injection chain detection"""
    engine = get_scoring_engine()
    
    correlation_id = "test-chain-sqli"
    ip = "10.0.0.5"
    
    # SQL injection detected - pass request_body with SQLi
    process_analytics_event(correlation_id, "login_attempt", {
        "ip": ip,
        "request_body": {"username": "admin' OR '1'='1", "password": "anything"}
    })
    
    session = engine.get_session(correlation_id)
    assert "sql_injection" in session.attack_chains


def test_attack_chain_detection_reconnaissance():
    """Test reconnaissance chain detection"""
    engine = get_scoring_engine()
    
    correlation_id = "test-chain-recon"
    ip = "10.0.0.6"
    
    # Multiple fake endpoint accesses
    process_analytics_event(correlation_id, "fake_endpoint_access", {"ip": ip, "endpoint": "/_internal/debug"})
    process_analytics_event(correlation_id, "fake_endpoint_access", {"ip": ip, "endpoint": "/api/admin/users"})
    process_analytics_event(correlation_id, "fake_endpoint_access", {"ip": ip, "endpoint": "/.well-known/ai-config"})
    
    session = engine.get_session(correlation_id)
    assert "reconnaissance" in session.attack_chains


def test_get_all_sessions():
    """Test retrieving all sessions"""
    engine = get_scoring_engine()
    
    # Create multiple sessions
    for i in range(3):
        cid = f"session-{i}"
        process_analytics_event(cid, "login_attempt", {"ip": f"10.0.0.{i}", "result": "failed"})
    
    sessions = engine.get_all_sessions()
    assert len(sessions) >= 3


def test_get_high_risk_sessions():
    """Test filtering high-risk sessions"""
    engine = get_scoring_engine()
    
    # Low score session
    process_analytics_event("low-risk", "login_attempt", {"ip": "10.0.0.10", "result": "failed"})
    
    # High score session (SQLi)
    process_analytics_event("high-risk", "login_attempt", {
        "ip": "10.0.0.11",
        "request_body": {"username": "admin' OR '1'='1", "password": "anything"}
    })
    
    high_risk = engine.get_high_risk_sessions(50)
    assert len(high_risk) >= 1
    assert any(s.correlation_id == "high-risk" for s in high_risk)


def test_get_attack_chain_summary():
    """Test attack chain summary aggregation"""
    engine = get_scoring_engine()
    
    # Create sessions with different chains
    process_analytics_event("chain-1", "login_attempt", {
        "ip": "10.0.0.20",
        "request_body": {"username": "admin' OR '1'='1", "password": "anything"}
    })
    process_analytics_event("chain-2", "login_attempt", {"ip": "10.0.0.21", "result": "failed"})
    for i in range(5):
        process_analytics_event("chain-2", "login_attempt", {"ip": "10.0.0.21", "result": "failed"})
    
    summary = engine.get_attack_chain_summary()
    assert "sql_injection" in summary
    assert "credential_stuffing" in summary
    assert summary["sql_injection"] >= 1
    assert summary["credential_stuffing"] >= 1


def test_get_ip_summary():
    """Test IP-based summary"""
    engine = get_scoring_engine()
    
    # Same IP, multiple correlations
    process_analytics_event("ip-test-1", "login_attempt", {"ip": "10.0.0.30", "result": "failed"})
    process_analytics_event("ip-test-2", "fake_endpoint_access", {"ip": "10.0.0.30", "endpoint": "/_internal/debug"})
    
    ip_summary = engine.get_ip_summary()
    assert "10.0.0.30" in ip_summary
    data = ip_summary["10.0.0.30"]
    assert data["total_score"] > 0
    assert data["event_count"] >= 2


def test_session_to_dict():
    """Test session serialization"""
    engine = get_scoring_engine()
    
    process_analytics_event("serial-test", "login_attempt", {"ip": "10.0.0.40", "result": "failed"})
    
    session = engine.get_session("serial-test")
    data = session.to_dict()
    
    assert data["correlation_id"] == "serial-test"
    assert data["ip"] == "10.0.0.40"
    assert data["total_score"] == SCORING_WEIGHTS["login_failed"]
    assert "login_failed" in data["scores"]
    # first_seen/last_seen are serialized as ISO format strings
    assert isinstance(data["first_seen"], str)
    assert isinstance(data["last_seen"], str)
    assert "T" in data["first_seen"]  # ISO format