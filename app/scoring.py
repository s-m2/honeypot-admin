"""Behavioral Scoring Engine for attack chain detection"""

import json
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from datetime import datetime, timedelta
from .database import db_cursor

# Scoring weights
SCORING_WEIGHTS = {
    # Login-based scores
    "login_failed": 5,
    "login_success": -10,  # Legitimate user
    "login_rate_limited": 15,
    "login_sqli_detected": 50,
    
    # Fake endpoint scores
    "fake_endpoint_access": 10,
    "fake_endpoint_repeated": 5,  # Additional per repeat
    "fake_admin_api_access": 20,
    "fake_ai_config_access": 15,
    "robots_txt_access": 5,
    "debug_endpoint_access": 15,
    
    # Guestbook scores
    "guestbook_spam": 20,
    "guestbook_ai_detected": 10,
    "guestbook_honeypot_triggered": 30,
    
    # Reset token scores
    "reset_token_requested": 10,
    "reset_token_used": 25,
    "reset_token_operator_attempt": 50,
    
    # Behavioral patterns
    "rapid_requests": 20,  # > 10 req/min
    "user_agent_anomaly": 10,
    "ip_reputation_bad": 30,
    "credential_stuffing_pattern": 40,
    "path_enumeration": 25,
    
    # Threat intel
    "threat_score_high": 40,  # AbuseIPDB > 75
    "tor_exit_node": 35,
    "vpn_detected": 20,
    "proxy_detected": 15,
    "hosting_provider": 10,
}

# Attack chain patterns
ATTACK_CHAINS = {
    "credential_stuffing": {
        "description": "Credential stuffing attack",
        "indicators": ["login_failed", "rapid_requests", "credential_stuffing_pattern"],
        "min_indicators": 2,
        "min_score": 50,
    },
    "sql_injection": {
        "description": "SQL injection attempt",
        "indicators": ["login_sqli_detected", "fake_admin_api_access"],
        "min_indicators": 1,  # SQLi is high confidence
        "min_score": 40,
    },
    "reconnaissance": {
        "description": "Reconnaissance/path enumeration",
        "indicators": ["fake_endpoint_access", "robots_txt_access", "debug_endpoint_access", "path_enumeration"],
        "min_indicators": 2,
        "min_score": 30,
    },
    "ai_probing": {
        "description": "AI agent probing",
        "indicators": ["fake_ai_config_access", "fake_agent_report", "guestbook_ai_detected"],
        "min_indicators": 2,
        "min_score": 25,
    },
    "account_takeover": {
        "description": "Account takeover attempt",
        "indicators": ["reset_token_requested", "reset_token_used", "reset_token_operator_attempt"],
        "min_indicators": 2,
        "min_score": 40,
    },
    "spam_campaign": {
        "description": "Spam/content injection campaign",
        "indicators": ["guestbook_spam", "guestbook_honeypot_triggered", "guestbook_ai_detected"],
        "min_indicators": 2,
        "min_score": 30,
    },
}

@dataclass
class SessionActivity:
    """Activity for a single session/correlation chain"""
    correlation_id: str
    ip: str
    first_seen: float
    last_seen: float
    event_count: int = 0
    events: List[Dict[str, Any]] = field(default_factory=list)
    scores: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    total_score: int = 0
    attack_chains: List[str] = field(default_factory=list)
    ip_enrichment: Optional[Dict] = None
    
    def add_event(self, event: Dict[str, Any]):
        self.events.append(event)
        self.event_count += 1
        self.last_seen = event.get("timestamp", time.time())
        
        # Update scores based on event type and result
        event_type = event.get("event_type", "")
        event_data = event.get("event_data", {})
        
        # Handle login attempts with result-based scoring
        if event_type == "login_attempt":
            result = event_data.get("result", "")
            if result == "failed":
                self.scores["login_failed"] += SCORING_WEIGHTS["login_failed"]
                self.total_score += SCORING_WEIGHTS["login_failed"]
            elif result == "success":
                self.scores["login_success"] += SCORING_WEIGHTS["login_success"]
                self.total_score += SCORING_WEIGHTS["login_success"]
            elif result == "rate_limited":
                self.scores["login_rate_limited"] += SCORING_WEIGHTS["login_rate_limited"]
                self.total_score += SCORING_WEIGHTS["login_rate_limited"]
        elif event_type in SCORING_WEIGHTS:
            self.scores[event_type] += SCORING_WEIGHTS[event_type]
            self.total_score += SCORING_WEIGHTS[event_type]
        
        # Check for specific patterns
        self._check_patterns(event)
    
    def _check_patterns(self, event: Dict[str, Any]):
        """Check for attack patterns in event"""
        event_data = event.get("event_data", {})
        
        # SQLi detection in login
        if event.get("event_type") == "login_attempt":
            request_body = event_data.get("request_body", {})
            username = request_body.get("username", "")
            password = request_body.get("password", "")
            if self._detect_sqli(username) or self._detect_sqli(password):
                self.scores["login_sqli_detected"] += SCORING_WEIGHTS["login_sqli_detected"]
                self.total_score += SCORING_WEIGHTS["login_sqli_detected"]
        
        # Path enumeration - multiple fake endpoints
        if event.get("event_type") == "fake_endpoint_access":
            endpoint = event_data.get("endpoint", "")
            endpoints = set(e.get("event_data", {}).get("endpoint", "") for e in self.events 
                          if e.get("event_type") == "fake_endpoint_access")
            if len(endpoints) >= 3:
                self.scores["path_enumeration"] += SCORING_WEIGHTS["path_enumeration"]
                self.total_score += SCORING_WEIGHTS["path_enumeration"]
        
        # Credential stuffing - many failed logins
        if event.get("event_type") == "login_attempt" and event_data.get("result") == "failed":
            failed_count = sum(1 for e in self.events 
                             if e.get("event_type") == "login_attempt" 
                             and e.get("event_data", {}).get("result") == "failed")
            if failed_count >= 5:
                self.scores["credential_stuffing_pattern"] += SCORING_WEIGHTS["credential_stuffing_pattern"]
                self.total_score += SCORING_WEIGHTS["credential_stuffing_pattern"]
        
        # Rapid requests
        if len(self.events) >= 10:
            time_span = self.last_seen - self.first_seen
            if time_span < 60:  # 10+ requests in < 1 minute
                self.scores["rapid_requests"] += SCORING_WEIGHTS["rapid_requests"]
                self.total_score += SCORING_WEIGHTS["rapid_requests"]
        
        # IP reputation from enrichment
        ip_enrichment = event_data.get("ip_enrichment", {})
        if ip_enrichment:
            self.ip_enrichment = ip_enrichment
            if ip_enrichment.get("threat_score", 0) > 75:
                self.scores["threat_score_high"] += SCORING_WEIGHTS["threat_score_high"]
                self.total_score += SCORING_WEIGHTS["threat_score_high"]
            if ip_enrichment.get("is_tor"):
                self.scores["tor_exit_node"] += SCORING_WEIGHTS["tor_exit_node"]
                self.total_score += SCORING_WEIGHTS["tor_exit_node"]
            if ip_enrichment.get("is_vpn"):
                self.scores["vpn_detected"] += SCORING_WEIGHTS["vpn_detected"]
                self.total_score += SCORING_WEIGHTS["vpn_detected"]
            if ip_enrichment.get("is_proxy"):
                self.scores["proxy_detected"] += SCORING_WEIGHTS["proxy_detected"]
                self.total_score += SCORING_WEIGHTS["proxy_detected"]
            if ip_enrichment.get("is_hosting"):
                self.scores["hosting_provider"] += SCORING_WEIGHTS["hosting_provider"]
                self.total_score += SCORING_WEIGHTS["hosting_provider"]
        
        # Detect attack chains
        self._detect_attack_chains()
    
    def _detect_sqli(self, text: str) -> bool:
        """Simple SQLi detection"""
        if not text:
            return False
        sqli_patterns = [
            "' OR '1'='1", "' OR 1=1", "';--", "' OR '1'='1'--",
            "UNION SELECT", "DROP TABLE", "INSERT INTO", "DELETE FROM",
            "1=1", "1=2", "' OR 'x'='x", "admin'--", "' OR '1'='1' /*",
        ]
        text_lower = text.lower()
        return any(pattern.lower() in text_lower for pattern in sqli_patterns)
    
    def _detect_attack_chains(self):
        """Detect which attack chains are active"""
        for chain_name, chain_info in ATTACK_CHAINS.items():
            if chain_name not in self.attack_chains:
                matched = sum(1 for indicator in chain_info["indicators"] 
                            if self.scores.get(indicator, 0) > 0)
                required = chain_info.get("min_indicators", 2)
                if matched >= required:
                    self.attack_chains.append(chain_name)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "ip": self.ip,
            "first_seen": datetime.fromtimestamp(self.first_seen).isoformat(),
            "last_seen": datetime.fromtimestamp(self.last_seen).isoformat(),
            "event_count": self.event_count,
            "total_score": self.total_score,
            "scores": dict(self.scores),
            "attack_chains": self.attack_chains,
            "ip_enrichment": self.ip_enrichment,
            "events": self.events[-20:],  # Last 20 events
        }


class BehavioralScoringEngine:
    """Engine for scoring and tracking attacker behavior across sessions"""
    
    def __init__(self):
        self.sessions: Dict[str, SessionActivity] = {}
        self._load_from_db()
    
    def _load_from_db(self):
        """Load recent sessions from database"""
        try:
            with db_cursor() as cur:
                cur.execute("""
                    SELECT correlation_id, event_type, event_data, created_at
                    FROM analytics_events
                    WHERE correlation_id IS NOT NULL
                    AND created_at > datetime('now', '-24 hours')
                    ORDER BY created_at ASC
                """)
                for row in cur.fetchall():
                    self._process_event(row)
        except Exception:
            pass
    
    def _process_event(self, row):
        """Process a single event row"""
        correlation_id, event_type, event_data_json, created_at = row
        if not correlation_id:
            return
        
        try:
            event_data = json.loads(event_data_json) if event_data_json else {}
        except json.JSONDecodeError:
            event_data = {}
        
        event = {
            "event_type": event_type,
            "event_data": event_data,
            "timestamp": created_at if isinstance(created_at, float) else time.time(),
        }
        
        if correlation_id not in self.sessions:
            ip = event_data.get("ip", "unknown")
            self.sessions[correlation_id] = SessionActivity(
                correlation_id=correlation_id,
                ip=ip,
                first_seen=event["timestamp"],
                last_seen=event["timestamp"],
            )
        
        self.sessions[correlation_id].add_event(event)
    
    def process_event(self, correlation_id: str, event_type: str, event_data: Dict[str, Any]):
        """Process a new event in real-time"""
        if not correlation_id:
            return
        
        event = {
            "event_type": event_type,
            "event_data": event_data,
            "timestamp": time.time(),
        }
        
        if correlation_id not in self.sessions:
            ip = event_data.get("ip", "unknown")
            self.sessions[correlation_id] = SessionActivity(
                correlation_id=correlation_id,
                ip=ip,
                first_seen=event["timestamp"],
                last_seen=event["timestamp"],
            )
        
        self.sessions[correlation_id].add_event(event)
    
    def get_session(self, correlation_id: str) -> Optional[SessionActivity]:
        """Get session by correlation ID"""
        return self.sessions.get(correlation_id)
    
    def get_high_risk_sessions(self, min_score: int = 50) -> List[SessionActivity]:
        """Get sessions with score above threshold"""
        return [s for s in self.sessions.values() if s.total_score >= min_score]
    
    def get_all_sessions(self) -> List[SessionActivity]:
        """Get all sessions sorted by score"""
        return sorted(self.sessions.values(), key=lambda s: s.total_score, reverse=True)
    
    def get_attack_chain_summary(self) -> Dict[str, int]:
        """Get count of sessions per attack chain"""
        summary = defaultdict(int)
        for session in self.sessions.values():
            for chain in session.attack_chains:
                summary[chain] += 1
        return dict(summary)
    
    def get_ip_summary(self) -> Dict[str, Dict]:
        """Get summary by IP"""
        ip_summary = defaultdict(lambda: {
            "total_score": 0,
            "event_count": 0,
            "sessions": 0,
            "attack_chains": set(),
            "first_seen": float('inf'),
            "last_seen": 0,
        })
        
        for session in self.sessions.values():
            ip = session.ip
            ip_summary[ip]["total_score"] += session.total_score
            ip_summary[ip]["event_count"] += session.event_count
            ip_summary[ip]["sessions"] += 1
            ip_summary[ip]["attack_chains"].update(session.attack_chains)
            ip_summary[ip]["first_seen"] = min(ip_summary[ip]["first_seen"], session.first_seen)
            ip_summary[ip]["last_seen"] = max(ip_summary[ip]["last_seen"], session.last_seen)
        
        # Convert sets to lists
        for ip, data in ip_summary.items():
            data["attack_chains"] = list(data["attack_chains"])
            if data["first_seen"] == float('inf'):
                data["first_seen"] = 0
        
        return dict(ip_summary)


# Global instance
_scoring_engine: Optional[BehavioralScoringEngine] = None

def get_scoring_engine() -> BehavioralScoringEngine:
    global _scoring_engine
    if _scoring_engine is None:
        _scoring_engine = BehavioralScoringEngine()
    return _scoring_engine


def process_analytics_event(correlation_id: str, event_type: str, event_data: Dict[str, Any]):
    """Process an analytics event through the scoring engine"""
    get_scoring_engine().process_event(correlation_id, event_type, event_data)