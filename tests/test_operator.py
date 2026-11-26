"""Unit tests for operator dashboard"""

import pytest
from httpx import AsyncClient, ASGITransport


# Use async_client fixture instead of client
async def login_operator(async_client):
    """Helper to login as operator"""
    # Reset rate limit for test IP
    from app.auth import login_attempts
    login_attempts.clear()
    
    resp = await async_client.post(
        "/admin",
        data={"username": "operator", "password": "OperatorAccess2024!Secure"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        follow_redirects=False
    )
    # Get session cookie
    cookie = resp.headers.get("set-cookie", "")
    session_cookie = cookie.split(";")[0] if cookie else ""
    return session_cookie


class TestOperatorDashboard:
    """Test operator dashboard routes"""
    
    async def test_operator_dashboard_requires_auth(self, async_client):
        resp = await async_client.get("/admin/operator")
        # Should return 401 when not authenticated
        assert resp.status_code == 401
    
    async def test_operator_dashboard_with_auth(self, async_client):
        cookie = await login_operator(async_client)
        resp = await async_client.get("/admin/operator", headers={"Cookie": cookie})
        assert resp.status_code == 200
        assert "Operator Dashboard" in resp.text
    
    async def test_operator_visitors(self, async_client):
        cookie = await login_operator(async_client)
        resp = await async_client.get("/admin/operator/visitors", headers={"Cookie": cookie})
        assert resp.status_code == 200
        assert "Visitor Log" in resp.text
    
    async def test_operator_traps(self, async_client):
        cookie = await login_operator(async_client)
        resp = await async_client.get("/admin/operator/traps", headers={"Cookie": cookie})
        assert resp.status_code == 200
        assert "Trap Analysis" in resp.text
    
    async def test_operator_timeline(self, async_client):
        cookie = await login_operator(async_client)
        resp = await async_client.get("/admin/operator/timeline", headers={"Cookie": cookie})
        assert resp.status_code == 200
        assert "Event Timeline" in resp.text
    
    async def test_operator_scoring(self, async_client):
        cookie = await login_operator(async_client)
        resp = await async_client.get("/admin/operator/scoring", headers={"Cookie": cookie})
        assert resp.status_code == 200
        assert "Behavioral Scoring" in resp.text
    
    async def test_operator_vuln_reports(self, async_client):
        cookie = await login_operator(async_client)
        resp = await async_client.get("/admin/operator/vuln-reports", headers={"Cookie": cookie})
        assert resp.status_code == 200
        assert "Vulnerability Reports" in resp.text


class TestOperatorAPI:
    """Test operator API endpoints"""
    
    async def test_scoring_sessions_api(self, async_client):
        cookie = await login_operator(async_client)
        resp = await async_client.get("/admin/operator/scoring/sessions", headers={"Cookie": cookie})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
    
    async def test_scoring_attack_chains_api(self, async_client):
        cookie = await login_operator(async_client)
        resp = await async_client.get("/admin/operator/scoring/attack-chains", headers={"Cookie": cookie})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
    
    async def test_scoring_ip_summary_api(self, async_client):
        cookie = await login_operator(async_client)
        resp = await async_client.get("/admin/operator/scoring/ip-summary", headers={"Cookie": cookie})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
    
    async def test_scoring_high_risk_api(self, async_client):
        cookie = await login_operator(async_client)
        resp = await async_client.get("/admin/operator/scoring/high-risk?min_score=50", headers={"Cookie": cookie})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
    
    async def test_export_sessions_csv(self, async_client):
        cookie = await login_operator(async_client)
        resp = await async_client.get("/admin/operator/export/sessions.csv", headers={"Cookie": cookie})
        assert resp.status_code == 200
        assert "text/csv" in resp.headers.get("content-type", "")
        assert "Correlation ID" in resp.text
    
    async def test_export_attack_chains_csv(self, async_client):
        cookie = await login_operator(async_client)
        resp = await async_client.get("/admin/operator/export/attack-chains.csv", headers={"Cookie": cookie})
        assert resp.status_code == 200
        assert "text/csv" in resp.headers.get("content-type", "")
    
    async def test_export_ip_summary_csv(self, async_client):
        cookie = await login_operator(async_client)
        resp = await async_client.get("/admin/operator/export/ip-summary.csv", headers={"Cookie": cookie})
        assert resp.status_code == 200
        assert "text/csv" in resp.headers.get("content-type", "")
    
    async def test_export_events_csv(self, async_client):
        cookie = await login_operator(async_client)
        resp = await async_client.get("/admin/operator/export/events.csv?hours=24", headers={"Cookie": cookie})
        assert resp.status_code == 200
        assert "text/csv" in resp.headers.get("content-type", "")