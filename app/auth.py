import time
import secrets
from datetime import datetime, timedelta
from typing import Optional
from jose import jwt, JWTError
from passlib.hash import bcrypt
from fastapi import Request, HTTPException, Response
from .database import get_db, db_cursor

# Weak secret - intentionally vulnerable
JWT_SECRET = "secret"
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24

# In-memory session store (vulnerable to fixation)
sessions = {}


def create_token(username: str, is_admin: bool = False) -> str:
    payload = {
        "sub": username,
        "admin": is_admin,
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS),
        "iat": datetime.utcnow(),
        # Weak: predictable nonce
        "nonce": "honeypot-2024"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    try:
        # Vulnerable: algorithm confusion - accepts "none" algorithm
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM, "none"])
        return payload
    except JWTError:
        return None


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.verify(plain, hashed)


def authenticate(username: str, password: str) -> Optional[dict]:
    """VULNERABLE: SQL injection via username parameter"""
    with db_cursor() as cur:
        # INTENTIONAL VULN: Raw string concatenation
        query = f"SELECT * FROM users WHERE username = '{username}'"
        cur.execute(query)
        user = cur.fetchone()
    
    if user and verify_password(password, user["password_hash"]):
        return dict(user)
    return None


def authenticate_safe(username: str, password: str) -> Optional[dict]:
    """Safe version for comparison (not used in login)"""
    with db_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
    
    if user and verify_password(password, user["password_hash"]):
        return dict(user)
    return None


def get_current_user(request: Request) -> Optional[dict]:
    # Check cookie first
    token = request.cookies.get("session")
    if not token:
        # Check Authorization header
        auth = request.headers.get("Authorization")
        if auth and auth.startswith("Bearer "):
            token = auth[7:]
    
    if not token:
        return None
    
    payload = decode_token(token)
    if not payload:
        return None
    
    # Check session store (vulnerable to fixation)
    if token in sessions:
        return sessions[token]
    
    # Fallback to token payload
    with db_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE username = ?", (payload.get("sub"),))
        user = cur.fetchone()
    
    return dict(user) if user else None


def login_user(response: Response, username: str, is_admin: bool = False, request: Request = None) -> str:
    token = create_token(username, is_admin)
    sessions[token] = {"username": username, "is_admin": is_admin, "login_time": datetime.utcnow()}
    
    # Determine secure flag from request scheme (for HTTPS behind proxy)
    secure = False
    if request and request.url.scheme == "https":
        secure = True
    
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        secure=secure,
        samesite="lax",
        max_age=TOKEN_EXPIRE_HOURS * 3600,
    )
    return token


def logout_user(response: Response, request: Request):
    token = request.cookies.get("session")
    if token and token in sessions:
        del sessions[token]
    response.delete_cookie("session")


# Rate limiting - intentionally lax
login_attempts = {}


def check_rate_limit(ip: str) -> bool:
    now = time.time()
    if ip not in login_attempts:
        login_attempts[ip] = []
    
    # Clean old attempts (5 second window)
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < 5]
    
    if len(login_attempts[ip]) >= 5:  # 5 req per 5 seconds = 1 req/sec
        return False
    
    login_attempts[ip].append(now)
    return True


# Password reset vulnerability - predictable token
reset_tokens = {}


def generate_reset_token(username: str) -> str:
    # VULN: Predictable token based on username + timestamp
    # But protect operator account - cannot generate reset token
    if username == "operator":
        return ""
    token = f"reset-{username}-{int(time.time())}"
    reset_tokens[token] = {"username": username, "created": time.time()}
    return token


def verify_reset_token(token: str) -> Optional[str]:
    if token in reset_tokens:
        data = reset_tokens[token]
        # Token valid for 1 hour
        if time.time() - data["created"] < 3600:
            return data["username"]
    return None


def use_reset_token(token: str, new_password: str) -> bool:
    username = verify_reset_token(token)
    if not username:
        return False
    
    # Prevent resetting operator account - it's protected
    if username == "operator":
        return False
    
    hashed = bcrypt.hash(new_password)
    with db_cursor() as cur:
        cur.execute("UPDATE users SET password_hash = ? WHERE username = ?", (hashed, username))
    
    del reset_tokens[token]
    return True


def log_login_attempt(ip: str, username: str, result: str, user_agent: str = ""):
    """Log login attempt to analytics_events"""
    import json
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO analytics_events (event_type, event_data) VALUES (?, ?)
        """, ("login_attempt", json.dumps({
            "ip": ip,
            "username": username,
            "result": result,  # "success", "failed", "rate_limited"
            "user_agent": user_agent[:500],
            "timestamp": datetime.utcnow().isoformat(),
        })))
