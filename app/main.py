from fastapi import FastAPI, Request, Response, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
import secrets
from .auth import (
    authenticate, login_user, logout_user, get_current_user,
    check_rate_limit, generate_reset_token, verify_reset_token, use_reset_token,
    log_login_attempt
)
from .guestbook import (
    add_entry, get_entries, get_all_entries, get_trap_content, can_post
)
from .traps.endpoints import router as traps_router
from .operator import router as operator_router


app = FastAPI(title="Mission Control Admin Portal")

# Session middleware (weak secret)
app.add_middleware(SessionMiddleware, secret_key="weak-session-secret-2024")

# Static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Templates
templates = Jinja2Templates(directory="app/templates")

# Include trap endpoints
app.include_router(traps_router)

# Include operator dashboard (hidden)
app.include_router(operator_router)


# Dependency for current user
async def require_auth(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


# --- Public Routes ---

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return RedirectResponse(url="/admin")


@app.get("/admin", response_class=HTMLResponse)
async def admin_login(request: Request):
    """Login page - looks like legitimate corporate admin"""
    user = get_current_user(request)
    if user:
        return RedirectResponse(url="/admin/dashboard")
    
    client_ip = request.client.host if request.client else "unknown"
    
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": request.query_params.get("error"),
        "client_ip": client_ip,
    })


@app.post("/admin", response_class=HTMLResponse)
async def admin_login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    """Login handler - multiple vulnerabilities"""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    
    # Rate limiting (lax)
    if not check_rate_limit(client_ip):
        log_login_attempt(client_ip, username, "rate_limited", user_agent)
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Too many attempts. Please wait.",
            "client_ip": client_ip,
        }, status_code=429)
    
    # Vulnerable authentication (SQLi possible via username)
    user = authenticate(username, password)
    
    if user:
        log_login_attempt(client_ip, username, "success", user_agent)
        response = RedirectResponse(url="/admin/dashboard", status_code=302)
        token = login_user(response, user["username"], user["is_admin"])
        response.headers["X-Session-Token"] = token  # Leak token in header (vuln)
        return response
    
    # Timing attack vector: username enumeration via response time
    # (The authenticate function already does this via SQL)
    log_login_attempt(client_ip, username, "failed", user_agent)
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": "Invalid credentials",
        "client_ip": client_ip,
    }, status_code=401)


@app.get("/admin/forgot", response_class=HTMLResponse)
async def forgot_password(request: Request):
    """Forgot password - logic flaw vulnerability"""
    return templates.TemplateResponse("forgot.html", {"request": request})


@app.post("/admin/forgot", response_class=HTMLResponse)
async def forgot_password_post(request: Request, username: str = Form(...)):
    """Generate reset token - predictable token vulnerability"""
    # VULN: Token generated even for non-existent users (enumeration)
    token = generate_reset_token(username)
    
    # In real app, would email. Here we leak it in response (vuln)
    return templates.TemplateResponse("forgot.html", {
        "request": request,
        "message": "If the account exists, a reset link has been sent.",
        "debug_token": token,  # LEAKED for honeypot purposes
    })


@app.get("/admin/reset", response_class=HTMLResponse)
async def reset_password(request: Request, token: str = ""):
    """Reset password page"""
    valid = verify_reset_token(token) is not None
    return templates.TemplateResponse("reset.html", {
        "request": request,
        "token": token,
        "valid": valid,
    })


@app.post("/admin/reset", response_class=HTMLResponse)
async def reset_password_post(request: Request, token: str = Form(...), password: str = Form(...)):
    """Use reset token"""
    if use_reset_token(token, password):
        return RedirectResponse(url="/admin?reset=success", status_code=302)
    return templates.TemplateResponse("reset.html", {
        "request": request,
        "error": "Invalid or expired token",
        "token": token,
    })


# --- Protected Routes ---

@app.get("/admin/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user: dict = Depends(require_auth)):
    """Fake SaaS dashboard"""
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "page": "overview",
    })


@app.get("/admin/analytics", response_class=HTMLResponse)
async def analytics(request: Request, user: dict = Depends(require_auth)):
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "page": "analytics",
    })


@app.get("/admin/users", response_class=HTMLResponse)
async def users_page(request: Request, user: dict = Depends(require_auth)):
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "page": "users",
    })


@app.get("/admin/settings", response_class=HTMLResponse)
async def settings_page(request: Request, user: dict = Depends(require_auth)):
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "page": "settings",
    })


@app.get("/admin/logs", response_class=HTMLResponse)
async def logs_page(request: Request, user: dict = Depends(require_auth)):
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "page": "logs",
    })


# --- Guestbook (The Trap) ---

@app.get("/admin/guestbook", response_class=HTMLResponse)
async def guestbook_page(request: Request, user: dict = Depends(require_auth)):
    """Guestbook page with AI traps"""
    client_ip = request.client.host if request.client else "unknown"
    allowed, reason = can_post(client_ip)
    
    traps = get_trap_content(request)
    
    return templates.TemplateResponse("guestbook.html", {
        "request": request,
        "user": user,
        "can_post": allowed,
        "cooldown_reason": reason if not allowed else None,
        "traps": traps,
        "max_length": 500,
    })


@app.post("/admin/guestbook", response_class=HTMLResponse)
async def guestbook_post(
    request: Request,
    user: dict = Depends(require_auth),
    name: str = Form(...),
    message: str = Form(...),
    website: str = Form(""),  # Honeypot field
):
    """Handle guestbook submission"""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    
    result = add_entry(client_ip, name, message, user_agent, website)
    
    traps = get_trap_content(request)
    allowed, reason = can_post(client_ip)
    
    return templates.TemplateResponse("guestbook.html", {
        "request": request,
        "user": user,
        "result": result,
        "can_post": allowed,
        "cooldown_reason": reason if not allowed else None,
        "traps": traps,
        "max_length": 500,
    })


@app.get("/admin/guestbook/export", include_in_schema=False)
async def guestbook_export(request: Request, user: dict = Depends(require_auth)):
    """Export all entries as JSON"""
    entries = get_all_entries()
    return JSONResponse(content={
        "total": len(entries),
        "entries": entries,
    })


# --- Auth ---

@app.get("/admin/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/admin")
    logout_user(response, request)
    return response


# --- Health ---
@app.get("/health")
async def health():
    return {"status": "ok", "service": "acme-corp-admin"}


# --- LLM Guide (llms.txt standard) ---
@app.get("/llms.txt", response_class=PlainTextResponse)
async def llms_txt():
    """LLM guide file - llms.txt standard for AI agent guidance"""
    with open("app/static/llms.txt", "r") as f:
        return f.read()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
