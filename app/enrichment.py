"""IP Enrichment Service for honeypot analytics"""

import json
import time
import urllib.request
import urllib.error
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import sqlite3
from .database import db_cursor

# Cache TTL in seconds (24 hours)
CACHE_TTL = 86400

@dataclass
class IPEnrichment:
    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    is_hosting: bool = False
    threat_score: int = 0
    threat_categories: list = None
    enriched_at: float = None
    
    def __post_init__(self):
        if self.threat_categories is None:
            self.threat_categories = []
        if self.enriched_at is None:
            self.enriched_at = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IPEnrichment':
        return cls(**data)


class IPEnrichmentService:
    """Service for enriching IP addresses with GeoIP, ASN, and threat intelligence"""
    
    def __init__(self, cache_db_path: str = "/home/honeypot/app/data/ip_cache.db"):
        self.cache_db_path = cache_db_path
        self._init_cache_db()
    
    def _init_cache_db(self):
        """Initialize the IP enrichment cache database"""
        conn = sqlite3.connect(self.cache_db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ip_enrichment_cache (
                ip TEXT PRIMARY KEY,
                enrichment_data TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        conn.commit()
        conn.close()
    
    def _get_from_cache(self, ip: str) -> Optional[IPEnrichment]:
        """Get enrichment from cache if not expired"""
        conn = sqlite3.connect(self.cache_db_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT enrichment_data, created_at FROM ip_enrichment_cache WHERE ip = ?",
            (ip,)
        )
        row = cur.fetchone()
        conn.close()
        
        if row:
            enrichment_data, created_at = row
            if time.time() - created_at < CACHE_TTL:
                return IPEnrichment.from_dict(json.loads(enrichment_data))
        return None
    
    def _save_to_cache(self, enrichment: IPEnrichment):
        """Save enrichment to cache"""
        conn = sqlite3.connect(self.cache_db_path)
        cur = conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO ip_enrichment_cache (ip, enrichment_data, created_at) VALUES (?, ?, ?)",
            (enrichment.ip, json.dumps(enrichment.to_dict()), time.time())
        )
        conn.commit()
        conn.close()
    
    def enrich(self, ip: str, force_refresh: bool = False) -> IPEnrichment:
        """Enrich an IP address with GeoIP, ASN, and threat intel"""
        # Check cache first
        if not force_refresh:
            cached = self._get_from_cache(ip)
            if cached:
                return cached
        
        # Private/reserved IPs don't need enrichment
        if self._is_private_ip(ip):
            enrichment = IPEnrichment(ip=ip, is_hosting=False)
            self._save_to_cache(enrichment)
            return enrichment
        
        # Try multiple enrichment sources
        enrichment = IPEnrichment(ip=ip)
        
        # Try ip-api.com (free, no key needed)
        self._enrich_from_ipapi(enrichment)
        
        # Try ipinfo.io if available
        self._enrich_from_ipinfo(enrichment)
        
        # Try AbuseIPDB for threat intel (requires API key, skip if not configured)
        self._enrich_from_abuseipdb(enrichment)
        
        # Save to cache
        self._save_to_cache(enrichment)
        return enrichment
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/reserved"""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved
        except ValueError:
            return True
    
    def _enrich_from_ipapi(self, enrichment: IPEnrichment):
        """Enrich using ip-api.com (free tier: 45 req/min)"""
        try:
            url = f"http://ip-api.com/json/{enrichment.ip}?fields=status,country,countryCode,region,city,lat,lon,as,isp,org,proxy,hosting"
            req = urllib.request.Request(url, headers={'User-Agent': 'HoneypotAdmin/1.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                if data.get('status') == 'success':
                    enrichment.country = data.get('country')
                    enrichment.country_code = data.get('countryCode')
                    enrichment.region = data.get('region')
                    enrichment.city = data.get('city')
                    enrichment.latitude = data.get('lat')
                    enrichment.longitude = data.get('lon')
                    enrichment.asn = data.get('as', '').split(' ')[0] if data.get('as') else None
                    enrichment.asn_name = data.get('as')
                    enrichment.isp = data.get('isp')
                    enrichment.organization = data.get('org')
                    enrichment.is_proxy = data.get('proxy', False)
                    enrichment.is_hosting = data.get('hosting', False)
        except Exception:
            pass  # Silently fail, use other sources
    
    def _enrich_from_ipinfo(self, enrichment: IPEnrichment):
        """Enrich using ipinfo.io (free tier available)"""
        try:
            url = f"https://ipinfo.io/{enrichment.ip}/json"
            req = urllib.request.Request(url, headers={'User-Agent': 'HoneypotAdmin/1.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                # Fill in missing fields
                if not enrichment.country and data.get('country'):
                    enrichment.country = data.get('country')
                if not enrichment.city and data.get('city'):
                    enrichment.city = data.get('city')
                if not enrichment.region and data.get('region'):
                    enrichment.region = data.get('region')
                if not enrichment.organization and data.get('org'):
                    enrichment.organization = data.get('org')
                # Parse ASN from org field if not set
                if not enrichment.asn and data.get('org'):
                    parts = data.get('org', '').split(' ', 1)
                    if parts[0].startswith('AS'):
                        enrichment.asn = parts[0]
                        enrichment.asn_name = data.get('org')
        except Exception:
            pass
    
    def _enrich_from_abuseipdb(self, enrichment: IPEnrichment):
        """Enrich using AbuseIPDB (requires API key)"""
        # API key would be in environment variable
        import os
        api_key = os.environ.get('ABUSEIPDB_API_KEY')
        if not api_key:
            return
        
        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={enrichment.ip}&maxAgeInDays=90&verbose"
            req = urllib.request.Request(
                url,
                headers={
                    'Key': api_key,
                    'Accept': 'application/json',
                    'User-Agent': 'HoneypotAdmin/1.0'
                }
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                if 'data' in data:
                    d = data['data']
                    enrichment.threat_score = d.get('abuseConfidenceScore', 0)
                    enrichment.is_tor = d.get('isTor', False)
                    enrichment.is_vpn = d.get('isVpn', False)
                    enrichment.is_proxy = d.get('isProxy', False) or enrichment.is_proxy
                    enrichment.is_hosting = d.get('isHosting', False) or enrichment.is_hosting
                    # Threat categories
                    categories = []
                    if d.get('isTor'): categories.append('tor')
                    if d.get('isVpn'): categories.append('vpn')
                    if d.get('isProxy'): categories.append('proxy')
                    if d.get('isHosting'): categories.append('hosting')
                    if d.get('abuseConfidenceScore', 0) > 50: categories.append('abuse')
                    enrichment.threat_categories = categories
        except Exception:
            pass


# Global instance
_enrichment_service: Optional[IPEnrichmentService] = None

def get_enrichment_service() -> IPEnrichmentService:
    global _enrichment_service
    if _enrichment_service is None:
        _enrichment_service = IPEnrichmentService()
    return _enrichment_service


def enrich_ip(ip: str) -> IPEnrichment:
    """Convenience function to enrich an IP"""
    return get_enrichment_service().enrich(ip)


def enrich_analytics_event(event_data: Dict[str, Any]) -> Dict[str, Any]:
    """Add IP enrichment to an analytics event"""
    ip = event_data.get('ip')
    if not ip:
        return event_data
    
    enrichment = enrich_ip(ip)
    event_data['ip_enrichment'] = enrichment.to_dict()
    return event_data