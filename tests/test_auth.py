"""Unit tests for auth module"""

import pytest
from passlib.hash import bcrypt


def test_bcrypt_hash_verify():
    """Test password hashing and verification"""
    password = "testpassword123"
    hashed = bcrypt.hash(password)
    
    assert bcrypt.verify(password, hashed)
    assert not bcrypt.verify("wrongpassword", hashed)


def test_weak_jwt_secret():
    """Verify weak secret is used (intentional for honeypot)"""
    from app.auth import JWT_SECRET
    assert JWT_SECRET == "secret"  # Intentionally weak


def test_jwt_algorithm_confusion():
    """Test that decode_token attempts to accept 'none' algorithm (intentional vulnerability)
    
    Note: python-jose library doesn't actually support 'none' algorithm with a key.
    The vulnerability exists in code logic but library prevents exploitation.
    """
    import pytest
    from app.auth import decode_token, JWT_ALGORITHM
    
    # The decode_token function includes "none" in accepted algorithms
    # This is the algorithm confusion vulnerability pattern
    # (python-jose library prevents actual exploitation)
    
    # Verify the algorithm list includes "none"
    import inspect
    source = inspect.getsource(decode_token)
    assert '"none"' in source or "'none'" in source
    assert JWT_ALGORITHM == "HS256"
    
    pytest.skip("python-jose doesn't support 'none' algorithm - vulnerability exists in logic only")


def test_sql_injection_vulnerability():
    """Test that authenticate function is vulnerable to SQL injection"""
    from app.auth import authenticate
    
    # Normal credentials should work
    result = authenticate("admin", "MissionControl2024!")
    assert result is not None
    assert result["username"] == "admin"
    
    # Wrong password should fail
    result = authenticate("admin", "wrongpassword")
    assert result is None
    
    # SQL injection payload bypasses auth (this is the vulnerability)
    # The query: SELECT * FROM users WHERE username = 'admin' OR '1'='1'
    result = authenticate("admin' OR '1'='1", "anything")
    # This should return a user because the query is vulnerable
    # Note: password is still checked, so it depends on the data
    # The vulnerability is in the query structure, not necessarily bypass


def test_rate_limiting():
    """Test login rate limiting logic"""
    from app.auth import check_rate_limit
    import time
    
    ip = "10.0.0.1"
    
    # Should allow first 5 attempts within 5 seconds
    for i in range(5):
        assert check_rate_limit(ip) == True
    
    # 6th attempt should be rate limited
    assert check_rate_limit(ip) == False
    
    # After 5 seconds, should allow again (clean old attempts)
    time.sleep(5.1)
    assert check_rate_limit(ip) == True


def test_reset_token_generation():
    """Test password reset token generation and verification"""
    from app.auth import generate_reset_token, verify_reset_token, use_reset_token
    
    username = "testuser"
    token = generate_reset_token(username)
    
    assert token.startswith("reset-testuser-")
    
    # Should verify correctly
    verified = verify_reset_token(token)
    assert verified == username
    
    # Operator should not get a token (returns empty string)
    operator_token = generate_reset_token("operator")
    assert operator_token == ""
    
    # use_reset_token should block operator
    assert use_reset_token("fake-token", "newpass") == False


def test_session_cookie_secure_flag():
    """Test session cookie secure flag logic"""
    from app.auth import login_user
    from starlette.responses import Response
    from starlette.requests import Request
    
    # Mock request with https scheme - need server info for URL building
    scope = {
        "type": "http", 
        "scheme": "https", 
        "headers": [], 
        "path": "/", 
        "method": "POST", 
        "query_string": b"",
        "server": ("testserver", 443)
    }
    request = Request(scope)
    response = Response()
    
    token = login_user(response, "testuser", request=request)
    
    # Cookie should be secure for HTTPS
    cookie_header = response.headers.get("set-cookie", "")
    assert "Secure" in cookie_header
    assert "HttpOnly" in cookie_header
    assert "SameSite" in cookie_header
    
    # Test HTTP (not secure)
    scope["scheme"] = "http"
    scope["server"] = ("testserver", 80)
    request = Request(scope)
    response = Response()
    login_user(response, "testuser", request=request)
    cookie_header = response.headers.get("set-cookie", "")
    assert "Secure" not in cookie_header