"""
Operator Dashboard - Hidden analytics for honeypot operator
Not linked anywhere, only accessible via obscure path
"""
from fastapi import APIRouter, Request, Depends, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from typing import Optional
from datetime import datetime, timedelta
from collections import defaultdict
import json

from .database import get_db, db_cursor
from .auth import get_current_user
from .traps.endpoints import fake_endpoint_logs, get_fake_logs
from .guestbook import get_all_entries
from .traps.markers import calculate_ai_score

router = APIRouter(prefix="/admin/operator", tags=[], include_in_schema=False)
templates = Jinja2Templates(directory="app/templates")


async def require_operator(request: Request):
    user = get_current_user(request)
    if not user:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


@router.get("", response_class=HTMLResponse)
async def operator_dashboard(request: Request, user: dict = Depends(require_operator)):
    """Main operator dashboard"""
    stats = get_operator_stats()
    return templates.TemplateResponse("operator_dashboard.html", {
        "request": request,
        "user": user,
        "stats": stats,
    })


@router.get("/visitors", response_class=HTMLResponse)
async def operator_visitors(
    request: Request, 
    user: dict = Depends(require_operator),
    page: int = 1,
    per_page: int = 50,
    filter_type: str = "all"
):
    """Visitor log with filtering"""
    visitors = get_visitor_log(page, per_page, filter_type)
    return templates.TemplateResponse("operator_visitors.html", {
        "request": request,
        "user": user,
        "visitors": visitors["entries"],
        "page": visitors["page"],
        "total_pages": visitors["total_pages"],
        "total": visitors["total"],
        "filter_type": filter_type,
    })


@router.get("/traps", response_class=HTMLResponse)
async def operator_traps(request: Request, user: dict = Depends(require_operator)):
    """Trap trigger analysis"""
    trap_data = get_trap_analysis()
    return templates.TemplateResponse("operator_traps.html", {
        "request": request,
        "user": user,
        "traps": trap_data,
    })


@router.get("/timeline", response_class=HTMLResponse)
async def operator_timeline(
    request: Request, 
    user: dict = Depends(require_operator),
    hours: int = 24
):
    """Event timeline"""
    events = get_event_timeline(hours)
    return templates.TemplateResponse("operator_timeline.html", {
        "request": request,
        "user": user,
        "events": events,
        "hours": hours,
    })


@router.get("/export")
async def operator_export(request: Request, user: dict = Depends(require_operator), format: str = "json"):
    """Export all data"""
    data = {
        "exported_at": datetime.utcnow().isoformat(),
        "stats": get_operator_stats(),
        "visitors": get_all_visitors(),
        "guestbook": get_all_entries(),
        "fake_endpoint_logs": get_fake_logs(1000),
        "trap_triggers": get_trap_trigger_details(),
    }
    if format == "json":
        return JSONResponse(content=data)
    return templates.TemplateResponse("operator_export.html", {
        "request": request,
        "user": user,
        "data": json.dumps(data, indent=2),
    })


def get_operator_stats() -> dict:
    """Get overall statistics"""
    with db_cursor() as cur:
        # Guestbook stats
        cur.execute("SELECT COUNT(*) as total FROM guestbook")
        guestbook_total = cur.fetchone()["total"]
        
        # Calculate AI stats by analyzing messages (since ai_score is computed at query time)
        cur.execute("SELECT message FROM guestbook")
        messages = [row["message"] for row in cur.fetchall()]
        guestbook_ai = 0
        for msg in messages:
            analysis = calculate_ai_score(msg)
            if analysis["score"] >= 50:
                guestbook_ai += 1
        
        # Visitor stats from analytics_events
        cur.execute("SELECT COUNT(*) as total FROM analytics_events WHERE event_type = 'fake_endpoint_access'")
        trap_hits = cur.fetchone()["total"]
        
        cur.execute("SELECT COUNT(DISTINCT json_extract(event_data, '$.ip')) as unique_ips FROM analytics_events WHERE event_type = 'fake_endpoint_access'")
        unique_attackers = cur.fetchone()["unique_ips"] or 0
        
        # Login attempts
        cur.execute("SELECT COUNT(*) as total FROM analytics_events WHERE event_type = 'login_attempt'")
        login_attempts = cur.fetchone()["total"]
        
        # Unique IPs overall
        cur.execute("""
            SELECT COUNT(DISTINCT ip) as total FROM (
                SELECT json_extract(event_data, '$.ip') as ip FROM analytics_events WHERE event_type = 'fake_endpoint_access'
                UNION
                SELECT json_extract(event_data, '$.ip') as ip FROM analytics_events WHERE event_type = 'login_attempt'
            )
        """)
        total_unique_ips = cur.fetchone()["total"] or 0
        
        # Recent activity (last 24h)
        since = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        cur.execute("SELECT COUNT(*) as total FROM analytics_events WHERE created_at > ?", (since,))
        recent_events = cur.fetchone()["total"]
        
        return {
            "guestbook_total": guestbook_total,
            "guestbook_ai_detected": guestbook_ai,
            "trap_hits": trap_hits,
            "unique_attackers": unique_attackers,
            "login_attempts": login_attempts,
            "total_unique_ips": total_unique_ips,
            "recent_events_24h": recent_events,
        }


def get_visitor_log(page: int, per_page: int, filter_type: str) -> dict:
    """Get paginated visitor log"""
    offset = (page - 1) * per_page
    
    where_clause = ""
    params = []
    
    if filter_type == "trap_hits":
        where_clause = "WHERE event_type = 'fake_endpoint_access'"
    elif filter_type == "login":
        where_clause = "WHERE event_type = 'login_attempt'"
    elif filter_type == "guestbook":
        where_clause = "WHERE event_type = 'guestbook_entry'"
    elif filter_type == "ai_detected":
        where_clause = "WHERE event_type = 'guestbook_entry' AND json_extract(event_data, '$.ai_score') >= 50"
    
    with db_cursor() as cur:
        cur.execute(f"SELECT COUNT(*) as total FROM analytics_events {where_clause}", params)
        total = cur.fetchone()["total"]
        
        cur.execute(f"""
            SELECT * FROM analytics_events 
            {where_clause}
            ORDER BY created_at DESC 
            LIMIT ? OFFSET ?
        """, params + [per_page, offset])
        entries = [dict(row) for row in cur.fetchall()]
    
    # Parse event_data JSON for display
    for entry in entries:
        try:
            entry["parsed_data"] = json.loads(entry["event_data"])
        except:
            entry["parsed_data"] = {}
    
    return {
        "entries": entries,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page,
    }


def get_all_visitors() -> list:
    """Get all visitor events for export"""
    with db_cursor() as cur:
        cur.execute("SELECT * FROM analytics_events ORDER BY created_at DESC")
        entries = [dict(row) for row in cur.fetchall()]
    
    for entry in entries:
        try:
            entry["parsed_data"] = json.loads(entry["event_data"])
        except:
            entry["parsed_data"] = {}
    
    return entries


def get_trap_analysis() -> dict:
    """Analyze trap effectiveness"""
    with db_cursor() as cur:
        # Trap endpoint hits
        cur.execute("""
            SELECT 
                json_extract(event_data, '$.endpoint') as endpoint,
                COUNT(*) as hits,
                COUNT(DISTINCT json_extract(event_data, '$.ip')) as unique_ips
            FROM analytics_events 
            WHERE event_type = 'fake_endpoint_access'
            GROUP BY endpoint
            ORDER BY hits DESC
        """)
        endpoint_stats = [dict(row) for row in cur.fetchall()]
        
        # User agents hitting traps
        cur.execute("""
            SELECT 
                json_extract(event_data, '$.user_agent') as ua,
                COUNT(*) as hits
            FROM analytics_events 
            WHERE event_type = 'fake_endpoint_access'
            GROUP BY ua
            ORDER BY hits DESC
            LIMIT 20
        """)
        ua_stats = [dict(row) for row in cur.fetchall()]
        
        # Guestbook AI scores distribution (computed on the fly)
        cur.execute("SELECT message FROM guestbook")
        messages = [row["message"] for row in cur.fetchall()]
        ai_distribution = {"high": 0, "medium": 0, "low": 0, "none": 0}
        for msg in messages:
            analysis = calculate_ai_score(msg)
            score = analysis["score"]
            if score >= 70:
                ai_distribution["high"] += 1
            elif score >= 40:
                ai_distribution["medium"] += 1
            elif score > 0:
                ai_distribution["low"] += 1
            else:
                ai_distribution["none"] += 1
        
        # Honeypot field triggers
        cur.execute("""
            SELECT COUNT(*) as flagged FROM guestbook 
            WHERE message LIKE '%flagged%' OR message LIKE '%automated%'
        """)
        honeypot_flagged = cur.fetchone()["flagged"]
        
        return {
            "endpoint_stats": endpoint_stats,
            "ua_stats": ua_stats,
            "ai_distribution": ai_distribution,
            "honeypot_flagged": honeypot_flagged,
        }


def get_trap_trigger_details() -> list:
    """Get detailed trap triggers for export"""
    with db_cursor() as cur:
        cur.execute("""
            SELECT * FROM analytics_events 
            WHERE event_type = 'fake_endpoint_access'
            ORDER BY created_at DESC
        """)
        return [dict(row) for row in cur.fetchall()]


def get_event_timeline(hours: int = 24) -> list:
    """Get chronological event timeline"""
    since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
    
    with db_cursor() as cur:
        cur.execute("""
            SELECT * FROM analytics_events 
            WHERE created_at > ?
            ORDER BY created_at ASC
        """, (since,))
        events = [dict(row) for row in cur.fetchall()]
    
    # Parse and enrich
    for event in events:
        try:
            data = json.loads(event["event_data"])
            event["parsed"] = data
            
            # Classify event
            if event["event_type"] == "fake_endpoint_access":
                event["class"] = "trap_hit"
                event["icon"] = "🎯"
                event["summary"] = f"Trap hit: {data.get('endpoint', 'unknown')} from {data.get('ip', 'unknown')}"
            elif event["event_type"] == "login_attempt":
                event["class"] = "login"
                event["icon"] = "🔑"
                event["summary"] = f"Login: {data.get('username', 'unknown')} from {data.get('ip', 'unknown')} - {data.get('result', 'unknown')}"
            elif event["event_type"] == "guestbook_entry":
                event["class"] = "guestbook"
                event["icon"] = "📝"
                ai = data.get("ai_score", 0)
                event["summary"] = f"Guestbook: {data.get('name', 'unknown')} (AI: {ai}%)"
            else:
                event["class"] = "other"
                event["icon"] = "📌"
                event["summary"] = f"{event['event_type']}"
        except:
            event["parsed"] = {}
            event["class"] = "other"
            event["icon"] = "❓"
            event["summary"] = event["event_type"]
    
    return events
