# Nginx Reverse Proxy Configuration

This document describes the required nginx configuration to properly proxy requests to the honeypot-admin service when deployed behind a reverse proxy (e.g., at `reburner.io/admin`).

## Required Nginx Configuration

Add the following location blocks to your nginx server block:

```nginx
server {
    listen 443 ssl http2;
    server_name reburner.io www.reburner.io;

    # ... your SSL config ...

    # Main admin panel
    location /admin {
        proxy_pass http://localhost:8000/admin;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Static assets
    location /static {
        proxy_pass http://localhost:8000/static;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # ============================================================
    # TRAP ENDPOINTS - Exact matches only (won't conflict with real API)
    # ============================================================

    # Debug endpoint trap
    location = /_internal/debug {
        proxy_pass http://localhost:8000/_internal/debug;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Agent report trap
    location = /api/v2/internal/agent-report {
        proxy_pass http://localhost:8000/api/v2/internal/agent-report;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Fake admin users API trap
    location = /api/admin/users {
        proxy_pass http://localhost:8000/api/admin/users;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # AI config well-known trap
    location = /.well-known/ai-config {
        proxy_pass http://localhost:8000/.well-known/ai-config;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Robots.txt trap
    location = /robots.txt {
        proxy_pass http://localhost:8000/robots.txt;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Key Points

1. **Use `=` for exact match** - The `=` prefix ensures only these exact paths are proxied to the honeypot. Your real `/api/` endpoints remain unaffected.

2. **`X-Forwarded-Proto` header** - Critical for the honeypot to detect HTTPS and set secure cookies properly.

3. **`X-Real-IP` and `X-Forwarded-For`** - Required for IP enrichment, threat intel, and behavioral scoring.

4. **Trap endpoints are at root paths** - Not under `/admin`. They must be proxied separately.

## Docker Configuration

Ensure your `docker-compose.yml` or `docker run` includes:

```yaml
services:
  honeypot-admin:
    command: >
      uvicorn app.main:app
      --host 0.0.0.0
      --port 8000
      --proxy-headers
      --forwarded-allow-ips '*'
```

The `--proxy-headers` and `--forwarded-allow-ips '*'` flags tell Uvicorn to trust the `X-Forwarded-*` headers from nginx.

## Testing the Configuration

After reloading nginx (`nginx -s reload`), verify:

```bash
# Main admin panel
curl -I https://reburner.io/admin

# Trap endpoints (should return honeypot responses, not 404)
curl -I https://reburner.io/_internal/debug
curl -I https://reburner.io/api/v2/internal/agent-report
curl -I https://reburner.io/api/admin/users
curl -I https://reburner.io/.well-known/ai-config
curl -I https://reburner.io/robots.txt

# Your real API should still work
curl -I https://reburner.io/api/your-real-endpoint
```

All trap endpoints should return `200 OK` or honeypot responses (not nginx 404).