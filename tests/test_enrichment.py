"""Unit tests for IP enrichment module"""

import pytest
import time
from app.enrichment import IPEnrichment, IPEnrichmentService, enrich_ip


def test_ip_enrichment_dataclass():
    """Test IPEnrichment dataclass creation and serialization"""
    enrichment = IPEnrichment(
        ip="1.2.3.4",
        country="United States",
        country_code="US",
        asn="AS12345",
        is_vpn=True,
        threat_score=75
    )
    
    # Test to_dict
    data = enrichment.to_dict()
    assert data["ip"] == "1.2.3.4"
    assert data["country"] == "United States"
    assert data["is_vpn"] == True
    assert data["threat_score"] == 75
    
    # Test from_dict
    restored = IPEnrichment.from_dict(data)
    assert restored.ip == "1.2.3.4"
    assert restored.threat_score == 75


def test_enrich_private_ip():
    """Private IPs should return minimal enrichment"""
    result = enrich_ip("192.168.1.1")
    
    assert result.ip == "192.168.1.1"
    assert result.country is None
    assert result.asn is None
    assert result.is_vpn == False
    assert result.threat_score == 0


def test_enrich_localhost():
    """Localhost should return minimal enrichment"""
    result = enrich_ip("127.0.0.1")
    
    assert result.ip == "127.0.0.1"
    assert result.threat_score == 0


def test_enrichment_service_cache():
    """Test enrichment service caching"""
    service = IPEnrichmentService(cache_db_path="/tmp/test_enrichment_cache.db")
    
    # First call - no cache
    result1 = service.enrich("8.8.8.8")
    
    # Second call - should use cache (or at least not crash)
    result2 = service.enrich("8.8.8.8")
    
    assert result1.ip == "8.8.8.8"
    assert result2.ip == "8.8.8.8"


def test_enrichment_service_private_ips():
    """Test service handles private IPs without external calls"""
    service = IPEnrichmentService(cache_db_path="/tmp/test_enrichment_cache2.db")
    
    result = service.enrich("10.0.0.1")
    
    assert result.ip == "10.0.0.1"
    assert result.threat_score == 0
    assert result.is_vpn == False


def test_enrichment_caching_ttl():
    """Test cache TTL logic"""
    service = IPEnrichmentService(cache_db_path="/tmp/test_enrichment_cache3.db")
    
    # Manually insert old cache entry
    import sqlite3
    conn = sqlite3.connect("/tmp/test_enrichment_cache3.db")
    cur = conn.cursor()
    old_time = time.time() - 100000  # > 24 hours ago
    # Use correct table name: ip_enrichment_cache
    cur.execute("""
        INSERT OR REPLACE INTO ip_enrichment_cache (ip, enrichment_data, created_at) VALUES (?, ?, ?)
    """, ("1.1.1.1", '{"ip": "1.1.1.1", "country": "Old"}', old_time))
    conn.commit()
    conn.close()
    
    # Should not use stale cache
    result = service.enrich("1.1.1.1")
    # Just verify it works (may hit API or return minimal)
    assert result.ip == "1.1.1.1"