"""Pytest configuration and shared fixtures"""

import pytest
import tempfile
import os
import sys
from pathlib import Path

# Add app to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Set test database location BEFORE importing app modules
os.environ["HONEYPOT_DATA_DIR"] = "/tmp/honeypot-test-data"


@pytest.fixture(autouse=True)
def setup_test_db():
    """Clean test database before each test"""
    test_db_dir = Path("/tmp/honeypot-test-data")
    test_db = test_db_dir / "honeypot.db"
    test_cache = test_db_dir / "ip_cache.db"
    
    # Remove old test databases
    for f in [test_db, test_cache]:
        if f.exists():
            f.unlink()
    
    # Re-initialize database with test path
    import app.database as db_module
    db_module.DB_DIR = test_db_dir
    db_module.DB_PATH = test_db_dir / "honeypot.db"
    db_module._initialized = False
    db_module._init_db()
    
    # Re-initialize enrichment service with test cache path
    import app.enrichment as enrich_module
    enrich_module._enrichment_service = None
    enrich_module.get_enrichment_service(cache_db_path=str(test_cache))
    
    yield
    
    # Cleanup after
    for f in [test_db, test_cache]:
        if f.exists():
            f.unlink()


@pytest.fixture
def app():
    """Create FastAPI test app - use main app but patch trusted hosts"""
    from app.main import app
    from fastapi.middleware.trustedhost import TrustedHostMiddleware
    
    # Patch TrustedHostMiddleware to allow testserver
    for middleware in app.user_middleware:
        if middleware.cls.__name__ == "TrustedHostMiddleware":
            hosts = middleware.kwargs.get("allowed_hosts", [])
            if "testserver" not in hosts:
                hosts.append("testserver")
            if "test" not in hosts:
                hosts.append("test")
            print(f"Patched allowed_hosts: {hosts}")
    return app


@pytest.fixture
async def async_client(app):
    """Async test client"""
    from httpx import AsyncClient, ASGITransport
    transport = ASGITransport(app=app)
    # Use localhost which is in TrustedHostMiddleware allowed_hosts
    async with AsyncClient(transport=transport, base_url="http://localhost") as client:
        yield client


@pytest.fixture
def client(app):
    """Sync test client"""
    from httpx import Client
    # Use localhost which is in TrustedHostMiddleware allowed_hosts
    with Client(app=app, base_url="http://localhost") as client:
        yield client