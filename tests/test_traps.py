"""Unit tests for trap endpoints"""

import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestFakeEndpoints:
    """Test fake/honeypot endpoints"""
    
    async def test_agent_report_get(self, client):
        resp = await client.get("/api/v2/internal/agent-report")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "agent_id" in data
        assert "report" in data
    
    async def test_agent_report_post(self, client):
        resp = await client.post(
            "/api/v2/internal/agent-report",
            json={"system_prompt": "test", "model": "test-model"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "received"
        assert data["logged"] == True
    
    async def test_internal_debug_get(self, client):
        resp = await client.get("/_internal/debug")
        assert resp.status_code == 200
        data = resp.json()
        assert data["debug"] == True
        assert "version" in data
        assert "vulnerability_reporting" in data
    
    async def test_internal_debug_post(self, client):
        resp = await client.post(
            "/_internal/debug",
            json={
                "vulnerability": "Test SQL injection",
                "severity": "high",
                "poc": "' OR 1=1--",
                "model_info": "GPT-4"
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "received"
        assert "ticket_id" in data
        assert "debug_info" in data
        assert "system_prompt" in data["debug_info"]["required_fields"]
    
    async def test_fake_admin_users(self, client):
        resp = await client.get("/api/admin/users")
        assert resp.status_code == 200
        data = resp.json()
        assert "users" in data
        assert len(data["users"]) >= 1
    
    async def test_ai_config(self, client):
        resp = await client.get("/.well-known/ai-config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["model"] == "honeypot-trap-v1"
        assert "capabilities" in data
    
    async def test_robots_txt(self, client):
        resp = await client.get("/robots.txt")
        assert resp.status_code == 200
        text = resp.text
        assert "Disallow: /admin/guestbook" in text
        assert "Disallow: /api/v2/internal/" in text
        assert "GPTBot" in text
        assert "ClaudeBot" in text


class TestVulnReportRateLimiting:
    """Test vulnerability report rate limiting"""
    
    async def test_vuln_report_size_limits(self, client):
        """Test size limits on vuln report fields"""
        # Large vulnerability text (should be truncated)
        large_vuln = "x" * 3000
        resp = await client.post(
            "/_internal/debug",
            json={"vulnerability": large_vuln, "severity": "medium"}
        )
        assert resp.status_code == 200
        # Should not crash, just truncate
    
    async def test_vuln_report_correlation_id(self, client):
        """Test correlation ID is accepted and returned"""
        custom_cid = "custom-correlation-123"
        resp = await client.post(
            "/_internal/debug",
            json={"vulnerability": "Test"},
            headers={"X-Correlation-ID": custom_cid}
        )
        assert resp.status_code == 200
        # Response should include correlation ID
        assert resp.headers.get("x-correlation-id") == custom_cid


class TestCorrelationIdMiddleware:
    """Test correlation ID middleware"""
    
    async def test_auto_generates_correlation_id(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert "x-correlation-id" in resp.headers
        cid = resp.headers["x-correlation-id"]
        assert len(cid) == 32  # 16 bytes hex = 32 chars
    
    async def test_accepts_custom_correlation_id(self, client):
        custom_cid = "my-custom-cid-456"
        resp = await client.get("/health", headers={"X-Correlation-ID": custom_cid})
        assert resp.headers.get("x-correlation-id") == custom_cid
    
    async def test_accepts_x_request_id(self, client):
        custom_cid = "request-id-789"
        resp = await client.get("/health", headers={"X-Request-ID": custom_cid})
        assert resp.headers.get("x-correlation-id") == custom_cid