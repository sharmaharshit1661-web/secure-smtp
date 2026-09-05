# 🚀 Production Readiness Guide — Secure SMTP

**Making Secure SMTP enterprise-grade and production-deployable.**

This guide covers **every single thing** you must do — from infrastructure and security to CI/CD, monitoring, and scaling — to take this project from a hackathon demo to a production-ready platform.

---

## Table of Contents

1. [Current State Assessment](#1-current-state-assessment)
2. [Environment & Configuration Management](#2-environment--configuration-management)
3. [Security Hardening](#3-security-hardening)
4. [Database (MongoDB) Production Setup](#4-database-mongodb-production-setup)
5. [FastAPI Backend Hardening](#5-fastapi-backend-hardening)
6. [Streamlit Dashboard Production Deployment](#6-streamlit-dashboard-production-deployment)
7. [Task Queue & Background Processing](#7-task-queue--background-processing)
8. [Containerization (Docker)](#8-containerization-docker)
9. [CI/CD Pipeline](#9-cicd-pipeline)
10. [Logging, Monitoring & Observability](#10-logging-monitoring--observability)
11. [Testing Strategy Expansion](#11-testing-strategy-expansion)
12. [Performance & Scalability](#12-performance--scalability)
13. [File Storage & Uploads](#13-file-storage--uploads)
14. [ML Model Management](#14-ml-model-management)
15. [API Documentation & Versioning](#15-api-documentation--versioning)
16. [Backup & Disaster Recovery](#16-backup--disaster-recovery)
17. [Compliance & Audit Trail](#17-compliance--audit-trail)
18. [Domain, DNS & TLS Certificates](#18-domain-dns--tls-certificates)
19. [Deployment Architecture Options](#19-deployment-architecture-options)
20. [Pre-Launch Checklist](#20-pre-launch-checklist)

---

## 1. Current State Assessment

### What's Working (Demo-Grade)
| Component | Current State | Production Gap |
|---|---|---|
| FastAPI Backend | `uvicorn` with `--reload`, CORS `allow_origins=["*"]` | No HTTPS, no rate limiting, wide-open CORS |
| MongoDB | Bare `localhost:27017`, no auth | No authentication, no replica set, no backups |
| Streamlit Dashboard | Dev server, XSRF protection **disabled** | Not suited for multi-user production |
| File Uploads | Saved to `/tmp/` | Ephemeral, no size limits, no virus scan |
| Reports | Saved to `/tmp/` | Lost on reboot, no CDN/storage |
| Background Tasks | `FastAPI BackgroundTasks` | No retry, no persistence, no queue monitoring |
| Secrets/Config | Hardcoded defaults, env vars read at import | No secrets manager, no config validation |
| Logging | Basic `logging` module | No structured logging, no centralized collection |
| Tests | 1 test file (`test_pipeline.py`) | No integration tests, no load tests, no security tests |
| ML Models | Trained in-memory per analysis run | No model versioning, no registry |

---

## 2. Environment & Configuration Management

### 2.1 Create a Proper Settings Module

Replace scattered `os.environ.get()` calls with a centralized, validated config using **Pydantic Settings**:

```bash
pip install pydantic-settings
```

Create `src/secure_smtp/config.py`:

```python
"""Centralized, validated configuration for Secure SMTP."""

from pydantic_settings import BaseSettings
from pydantic import Field, MongoDsn, field_validator


class Settings(BaseSettings):
    """All app configuration, validated at startup."""

    # ── Application ──
    APP_NAME: str = "Secure SMTP"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"  # development | staging | production
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # ── API Server ──
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_WORKERS: int = 4
    ALLOWED_ORIGINS: list[str] = ["https://yourdomain.com"]

    # ── MongoDB ──
    MONGO_URI: str = "mongodb://localhost:27017"
    MONGO_DB_NAME: str = "secure_smtp"
    MONGO_MIN_POOL_SIZE: int = 5
    MONGO_MAX_POOL_SIZE: int = 50

    # ── File Storage ──
    UPLOAD_DIR: str = "/var/securesmtp/uploads"
    REPORTS_DIR: str = "/var/securesmtp/reports"
    MAX_UPLOAD_SIZE_MB: int = 500

    # ── Security ──
    API_KEY_HEADER: str = "X-API-Key"
    API_KEYS: list[str] = []  # Populated from secrets manager
    JWT_SECRET: str = ""
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_MINUTES: int = 60

    # ── Redis / Celery ──
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"

    # ── Optional LLM ──
    ANTHROPIC_API_KEY: str = ""

    # ── Sentry ──
    SENTRY_DSN: str = ""

    model_config = {
        "env_prefix": "SECURESMTP_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


settings = Settings()
```

### 2.2 Environment Files

Create environment-specific `.env` files (**.env files must NEVER be committed to git**):

```bash
# .env.example (commit this one — it's the template)
SECURESMTP_ENVIRONMENT=production
SECURESMTP_DEBUG=false
SECURESMTP_LOG_LEVEL=WARNING
SECURESMTP_MONGO_URI=mongodb://admin:CHANGE_ME@mongo-primary:27017,mongo-secondary:27017/secure_smtp?replicaSet=rs0&authSource=admin
SECURESMTP_MONGO_DB_NAME=secure_smtp
SECURESMTP_ALLOWED_ORIGINS=["https://securesmtp.yourdomain.com"]
SECURESMTP_UPLOAD_DIR=/var/securesmtp/uploads
SECURESMTP_REPORTS_DIR=/var/securesmtp/reports
SECURESMTP_MAX_UPLOAD_SIZE_MB=500
SECURESMTP_API_KEYS=["sk-prod-xxxxxxxxxxxxx"]
SECURESMTP_JWT_SECRET=CHANGE_ME_TO_64_CHAR_RANDOM_STRING
SECURESMTP_REDIS_URL=redis://redis:6379/0
SECURESMTP_SENTRY_DSN=https://xxxx@sentry.io/yyyy
SECURESMTP_ANTHROPIC_API_KEY=sk-ant-xxxxx
```

### 2.3 Update `.gitignore`

Add these lines to your `.gitignore`:

```gitignore
# Secrets - NEVER commit
.env
.env.production
.env.staging
*.pem
*.key

# Production artifacts
/var/securesmtp/
```

---

## 3. Security Hardening

### 3.1 Fix CORS — Currently Wide Open

**Current (INSECURE)** — `main.py` line 59:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # ← Anyone can call your API
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Production Fix:**
```python
from secure_smtp.config import settings

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)
```

### 3.2 Add API Authentication

Create `src/secure_smtp/api/auth.py`:

```python
"""API authentication middleware."""

from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader
from secure_smtp.config import settings

api_key_header = APIKeyHeader(name=settings.API_KEY_HEADER, auto_error=False)


async def verify_api_key(api_key: str = Security(api_key_header)) -> str:
    """Validate the API key from the request header."""
    if not api_key or api_key not in settings.API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return api_key
```

Then protect your endpoints:
```python
from secure_smtp.api.auth import verify_api_key

@app.post("/api/analyze", dependencies=[Depends(verify_api_key)])
async def analyze_pcap(...):
    ...
```

### 3.3 Rate Limiting

```bash
pip install slowapi
```

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/api/analyze")
@limiter.limit("10/minute")
async def analyze_pcap(request: Request, ...):
    ...
```

### 3.4 Input Validation & Upload Security

```python
# In analyze_pcap endpoint
MAX_UPLOAD_BYTES = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024

@app.post("/api/analyze")
async def analyze_pcap(file: UploadFile = File(...)):
    # 1. Validate file extension
    ext = Path(file.filename).suffix.lower()
    if ext not in (".pcap", ".pcapng"):
        raise HTTPException(400, "Unsupported format")

    # 2. Validate file size (read in chunks to avoid memory bomb)
    content = bytearray()
    while chunk := await file.read(1024 * 1024):  # 1MB chunks
        content.extend(chunk)
        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, f"File exceeds {settings.MAX_UPLOAD_SIZE_MB}MB limit")

    # 3. Validate PCAP magic bytes
    PCAP_MAGIC = [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4']  # Little/Big endian
    PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'
    if bytes(content[:4]) not in PCAP_MAGIC and bytes(content[:4]) != PCAPNG_MAGIC:
        raise HTTPException(400, "File is not a valid PCAP/PCAPNG")

    # 4. Sanitize filename
    import re
    safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', file.filename)
    ...
```

### 3.5 Fix Streamlit Security Settings

**Current (INSECURE)** — `.streamlit/config.toml` line 15-16:
```toml
enableCORS = false
enableXsrfProtection = false
```

**Production Fix:**
```toml
[server]
headless = true
enableCORS = true
enableXsrfProtection = true
```

### 3.6 HTTP Security Headers

```python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response


app.add_middleware(SecurityHeadersMiddleware)
```

### 3.7 Secrets Management

Never store secrets in environment variables directly on the host. Use:

| Option | Best For |
|---|---|
| **HashiCorp Vault** | Self-hosted, maximum control |
| **AWS Secrets Manager** | AWS deployments |
| **GCP Secret Manager** | GCP deployments |
| **Azure Key Vault** | Azure deployments |
| **Doppler** | Multi-cloud, developer friendly |

---

## 4. Database (MongoDB) Production Setup

### 4.1 Enable Authentication

The current code connects to `mongodb://localhost:27017` — **no username, no password**. This must change.

```bash
# Create an admin user in MongoDB
mongosh
> use admin
> db.createUser({
    user: "securesmtp_admin",
    pwd: "STRONG_PASSWORD_HERE",
    roles: [
      { role: "readWrite", db: "secure_smtp" },
      { role: "dbAdmin", db: "secure_smtp" }
    ]
  })
```

Update connection URI:
```
mongodb://securesmtp_admin:STRONG_PASSWORD_HERE@localhost:27017/secure_smtp?authSource=admin
```

### 4.2 Deploy a Replica Set

A single MongoDB instance is a **single point of failure**. Production requires at minimum a 3-node replica set:

```yaml
# docker-compose.mongodb.yml
services:
  mongo-primary:
    image: mongo:7
    command: mongod --replSet rs0 --bind_ip_all --auth --keyFile /data/keyfile
    volumes:
      - mongo-primary-data:/data/db
      - ./mongo-keyfile:/data/keyfile:ro
    ports:
      - "27017:27017"

  mongo-secondary1:
    image: mongo:7
    command: mongod --replSet rs0 --bind_ip_all --auth --keyFile /data/keyfile
    volumes:
      - mongo-secondary1-data:/data/db
      - ./mongo-keyfile:/data/keyfile:ro

  mongo-secondary2:
    image: mongo:7
    command: mongod --replSet rs0 --bind_ip_all --auth --keyFile /data/keyfile
    volumes:
      - mongo-secondary2-data:/data/db
      - ./mongo-keyfile:/data/keyfile:ro

volumes:
  mongo-primary-data:
  mongo-secondary1-data:
  mongo-secondary2-data:
```

**Or use a managed service**: MongoDB Atlas (recommended for simplicity — handles replication, backups, monitoring automatically).

### 4.3 Connection Pooling

Update `mongodb.py` to use proper pool settings:

```python
_client = MongoClient(
    target_uri,
    serverSelectionTimeoutMS=5000,
    connectTimeoutMS=5000,
    socketTimeoutMS=30000,
    maxPoolSize=settings.MONGO_MAX_POOL_SIZE,
    minPoolSize=settings.MONGO_MIN_POOL_SIZE,
    retryWrites=True,
    retryReads=True,
    w="majority",             # Write concern for data durability
    readPreference="secondaryPreferred",  # Read from secondaries when possible
    tz_aware=True,
)
```

### 4.4 Database Indexes (Already Partially Done)

Your `init_db_indexes()` is good. Add these for production performance:

```python
# TTL index for analysis jobs (auto-expire old jobs)
jobs.create_index(
    [("created_at", ASCENDING)],
    expireAfterSeconds=30 * 24 * 3600,  # 30 days
    name="ttl_jobs_30d"
)

# Compound index for session queries
sessions.create_index([("host_id", ASCENDING), ("risk_score.score_0_100", DESCENDING)])

# Text index for search
sessions.create_index([("pcap_source", "text"), ("dst_ip", "text")])
```

### 4.5 Automated Backups

```bash
#!/bin/bash
# backup_mongodb.sh — run via cron daily at 2 AM
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/mongodb/$TIMESTAMP"
mongodump --uri="$SECURESMTP_MONGO_URI" --out="$BACKUP_DIR" --gzip
# Upload to S3/GCS
aws s3 sync "$BACKUP_DIR" "s3://securesmtp-backups/mongodb/$TIMESTAMP/"
# Retain only last 30 days locally
find /backups/mongodb -maxdepth 1 -mtime +30 -exec rm -rf {} \;
```

Cron entry:
```
0 2 * * * /opt/securesmtp/backup_mongodb.sh >> /var/log/securesmtp/backup.log 2>&1
```

---

## 5. FastAPI Backend Hardening

### 5.1 Production ASGI Server

Replace the dev server with a production Gunicorn + Uvicorn Workers setup:

```bash
pip install gunicorn
```

```bash
# Production launch command
gunicorn secure_smtp.api.main:app \
  --worker-class uvicorn.workers.UvicornWorker \
  --workers 4 \
  --bind 0.0.0.0:8000 \
  --timeout 300 \
  --keep-alive 5 \
  --access-logfile /var/log/securesmtp/access.log \
  --error-logfile /var/log/securesmtp/error.log \
  --log-level warning
```

### 5.2 Reverse Proxy with Nginx

**Never expose Gunicorn/Uvicorn directly to the internet.** Place Nginx in front:

```nginx
# /etc/nginx/sites-available/securesmtp-api
upstream securesmtp_api {
    server 127.0.0.1:8000;
}

server {
    listen 443 ssl http2;
    server_name api.securesmtp.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/securesmtp.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/securesmtp.yourdomain.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers on;

    client_max_body_size 500M;  # For PCAP uploads

    location /api/ {
        proxy_pass http://securesmtp_api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;  # Long timeout for PCAP analysis
    }

    location /docs {
        # Disable Swagger in production or restrict to internal IPs
        deny all;
        # OR: allow 10.0.0.0/8; deny all;
    }
}

server {
    listen 80;
    server_name api.securesmtp.yourdomain.com;
    return 301 https://$host$request_uri;
}
```

### 5.3 Disable Debug Features in Production

```python
# In main.py
from secure_smtp.config import settings

app = FastAPI(
    title="Secure SMTP",
    version=settings.APP_VERSION,
    docs_url="/docs" if settings.DEBUG else None,      # Hide Swagger
    redoc_url="/redoc" if settings.DEBUG else None,     # Hide ReDoc
    openapi_url="/openapi.json" if settings.DEBUG else None,
)
```

### 5.4 Replace `@app.on_event("startup")` (Deprecated)

```python
# Replace the deprecated decorator:
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db_indexes()
    logger.info("Secure SMTP API started in %s mode", settings.ENVIRONMENT)
    yield
    # Shutdown
    if _client:
        _client.close()
    logger.info("Secure SMTP API shut down")

app = FastAPI(lifespan=lifespan, ...)
```

### 5.5 Global Exception Handling

```python
from fastapi import Request
from fastapi.responses import JSONResponse
import traceback

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(
        "Unhandled exception: %s\nPath: %s\n%s",
        str(exc), request.url.path, traceback.format_exc()
    )
    # Don't leak internal error details in production
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc) if settings.DEBUG else "An unexpected error occurred",
        },
    )
```

---

## 6. Streamlit Dashboard Production Deployment

### 6.1 The Problem with Streamlit in Production

Streamlit is **excellent for prototyping** but has real limitations for multi-user production:
- No built-in authentication
- No session management across users
- Resource-heavy (full Python process per session)
- Limited customization

### 6.2 Option A: Keep Streamlit (Quick Path)

If you keep Streamlit, harden it:

1. **Put it behind Nginx with HTTP Basic Auth or OAuth**:
```nginx
server {
    listen 443 ssl http2;
    server_name dashboard.securesmtp.yourdomain.com;

    # Basic Auth
    auth_basic "Secure SMTP Dashboard";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:8501;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";  # WebSocket support
        proxy_set_header Host $host;
        proxy_read_timeout 86400;  # Keep WebSocket alive
    }
}
```

2. **Use `streamlit-authenticator`** for in-app auth:
```bash
pip install streamlit-authenticator
```

3. **Limit concurrent sessions** via process management (systemd `LimitNPROC`).

### 6.3 Option B: Migrate to a React Frontend (Recommended for Scale)

For true production scale, replace Streamlit with a React/Next.js frontend that calls your existing FastAPI endpoints. This gives you:
- Full control over authentication (OAuth2/OIDC)
- Proper session management
- CDN-deployable static assets
- Unlimited concurrent users
- Professional UI/UX control

---

## 7. Task Queue & Background Processing

### 7.1 The Problem

`FastAPI BackgroundTasks` is in-process — if the worker crashes mid-analysis:
- The PCAP analysis is **lost with no retry**
- Job status stays `running` forever
- No visibility into what's queued or running

### 7.2 Solution: Celery + Redis

```bash
pip install celery[redis] redis
```

Create `src/secure_smtp/tasks/worker.py`:

```python
"""Celery worker for background PCAP analysis."""

from celery import Celery
from secure_smtp.config import settings

celery_app = Celery(
    "secure_smtp",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    task_track_started=True,
    task_time_limit=3600,       # Hard limit: 1 hour
    task_soft_time_limit=3000,  # Soft limit: 50 minutes (raises SoftTimeLimitExceeded)
    worker_max_tasks_per_child=50,  # Restart worker after 50 tasks (memory leak prevention)
    task_acks_late=True,        # Don't ack until task is done (crash safety)
    worker_prefetch_multiplier=1,
)


@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def analyze_pcap_task(self, job_id: str, pcap_path: str):
    """Run PCAP analysis with retry support."""
    try:
        from secure_smtp.api.main import _run_analysis
        _run_analysis(job_id, pcap_path)
    except Exception as exc:
        self.retry(exc=exc)
```

Update the API endpoint:
```python
@app.post("/api/analyze")
async def analyze_pcap(file: UploadFile = File(...)):
    ...
    # Replace: background_tasks.add_task(_run_analysis, job_id, str(pcap_path))
    # With:
    from secure_smtp.tasks.worker import analyze_pcap_task
    analyze_pcap_task.delay(job_id, str(pcap_path))
    ...
```

Launch the Celery worker:
```bash
celery -A secure_smtp.tasks.worker worker --loglevel=info --concurrency=4
```

### 7.3 Monitor with Flower

```bash
pip install flower
celery -A secure_smtp.tasks.worker flower --port=5555
```

---

## 8. Containerization (Docker)

### 8.1 Dockerfile (Multi-Stage Build)

Create `Dockerfile`:

```dockerfile
# ── Stage 1: Builder ──
FROM python:3.11-slim AS builder

WORKDIR /build
COPY pyproject.toml ./
COPY src/ ./src/

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    && pip install --no-cache-dir build wheel \
    && pip install --no-cache-dir -e ".[dev]" \
    && apt-get purge -y build-essential \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*


# ── Stage 2: Production Runtime ──
FROM python:3.11-slim AS runtime

# Security: run as non-root user
RUN groupadd -r securesmtp && useradd -r -g securesmtp securesmtp

# Install runtime system dependencies (weasyprint needs these)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi8 \
    libcairo2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY src/ ./src/
COPY dashboard/ ./dashboard/
COPY pyproject.toml ./

# Create directories
RUN mkdir -p /var/securesmtp/uploads /var/securesmtp/reports /var/log/securesmtp \
    && chown -R securesmtp:securesmtp /var/securesmtp /var/log/securesmtp /app

USER securesmtp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/hosts || exit 1

EXPOSE 8000

ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

CMD ["gunicorn", "secure_smtp.api.main:app", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--workers", "4", \
     "--bind", "0.0.0.0:8000", \
     "--timeout", "300"]
```

### 8.2 Docker Compose (Full Stack)

Create `docker-compose.yml`:

```yaml
version: "3.9"

services:
  # ── FastAPI Backend ──
  api:
    build: .
    ports:
      - "8000:8000"
    env_file: .env
    volumes:
      - uploads:/var/securesmtp/uploads
      - reports:/var/securesmtp/reports
    depends_on:
      mongo:
        condition: service_healthy
      redis:
        condition: service_healthy
    restart: unless-stopped

  # ── Celery Worker ──
  worker:
    build: .
    command: celery -A secure_smtp.tasks.worker worker --loglevel=info --concurrency=4
    env_file: .env
    volumes:
      - uploads:/var/securesmtp/uploads
      - reports:/var/securesmtp/reports
    depends_on:
      - api
      - redis
    restart: unless-stopped

  # ── Streamlit Dashboard ──
  dashboard:
    build: .
    command: streamlit run dashboard/app.py --server.port 8501 --server.headless true
    ports:
      - "8501:8501"
    env_file: .env
    depends_on:
      - api
    restart: unless-stopped

  # ── MongoDB (Standalone for Dev; Replica Set for Prod) ──
  mongo:
    image: mongo:7
    ports:
      - "27017:27017"
    volumes:
      - mongo-data:/data/db
    environment:
      MONGO_INITDB_ROOT_USERNAME: securesmtp_admin
      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_PASSWORD}
    healthcheck:
      test: echo 'db.runCommand("ping").ok' | mongosh --quiet
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  # ── Redis (Celery Broker) ──
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    healthcheck:
      test: redis-cli ping
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  # ── Celery Flower (Task Monitor) ──
  flower:
    build: .
    command: celery -A secure_smtp.tasks.worker flower --port=5555
    ports:
      - "5555:5555"
    env_file: .env
    depends_on:
      - worker
      - redis

  # ── Nginx Reverse Proxy ──
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/certs:/etc/nginx/certs:ro
    depends_on:
      - api
      - dashboard
    restart: unless-stopped

volumes:
  mongo-data:
  redis-data:
  uploads:
  reports:
```

### 8.3 `.dockerignore`

```
.git
.venv
venv
__pycache__
*.pyc
.pytest_cache
.ruff_cache
.env
*.db
*.sqlite
.DS_Store
.claude
.codex
.cursor
.impeccable
secure_smtp.db
tests/
scripts/
*.md
```

---

## 9. CI/CD Pipeline

### 9.1 GitHub Actions

Create `.github/workflows/ci.yml`:

```yaml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  # ── Lint & Type Check ──
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install ruff mypy
      - run: ruff check src/
      - run: ruff format --check src/

  # ── Unit Tests ──
  test:
    runs-on: ubuntu-latest
    services:
      mongo:
        image: mongo:7
        ports:
          - 27017:27017
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -e ".[dev]"
      - run: pytest tests/ -v --tb=short --cov=secure_smtp --cov-report=xml
      - uses: codecov/codecov-action@v4
        with:
          file: coverage.xml

  # ── Security Scan ──
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install bandit safety
      - run: bandit -r src/ -ll
      - run: safety check

  # ── Docker Build & Push ──
  build:
    needs: [lint, test, security]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v5
        with:
          push: true
          tags: |
            ghcr.io/${{ github.repository }}:latest
            ghcr.io/${{ github.repository }}:${{ github.sha }}

  # ── Deploy to Staging ──
  deploy-staging:
    needs: build
    runs-on: ubuntu-latest
    environment: staging
    steps:
      - name: Deploy to staging
        run: |
          ssh deploy@staging.securesmtp.com "
            cd /opt/securesmtp &&
            docker compose pull &&
            docker compose up -d --remove-orphans
          "
```

---

## 10. Logging, Monitoring & Observability

### 10.1 Structured Logging

Replace basic logging with structured JSON logs:

```bash
pip install structlog python-json-logger
```

Create `src/secure_smtp/logging_config.py`:

```python
"""Production logging configuration."""

import logging
import structlog


def configure_logging(log_level: str = "INFO", json_output: bool = True):
    """Configure structured logging for production."""

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer() if json_output
            else structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level.upper(), logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
```

Usage:
```python
import structlog
logger = structlog.get_logger()

logger.info("analysis_started", job_id=job_id, pcap_size=file_size, streams=len(streams))
logger.error("analysis_failed", job_id=job_id, error=str(e), duration_ms=elapsed)
```

### 10.2 Application Performance Monitoring (APM)

```bash
pip install sentry-sdk[fastapi]
```

```python
import sentry_sdk
from secure_smtp.config import settings

if settings.SENTRY_DSN:
    sentry_sdk.init(
        dsn=settings.SENTRY_DSN,
        environment=settings.ENVIRONMENT,
        traces_sample_rate=0.1,  # 10% of requests
        profiles_sample_rate=0.1,
    )
```

### 10.3 Health Check Endpoint

```python
@app.get("/health")
async def health_check():
    """Health check for load balancers and orchestrators."""
    checks = {}

    # MongoDB
    try:
        get_mongo_client().admin.command("ping")
        checks["mongodb"] = "healthy"
    except Exception as e:
        checks["mongodb"] = f"unhealthy: {e}"

    # Redis (if using Celery)
    try:
        import redis
        r = redis.from_url(settings.REDIS_URL)
        r.ping()
        checks["redis"] = "healthy"
    except Exception as e:
        checks["redis"] = f"unhealthy: {e}"

    all_healthy = all(v == "healthy" for v in checks.values())
    return JSONResponse(
        status_code=200 if all_healthy else 503,
        content={"status": "healthy" if all_healthy else "degraded", "checks": checks},
    )
```

### 10.4 Prometheus Metrics

```bash
pip install prometheus-fastapi-instrumentator
```

```python
from prometheus_fastapi_instrumentator import Instrumentator

Instrumentator().instrument(app).expose(app, endpoint="/metrics")
```

### 10.5 Grafana Dashboard

Deploy Grafana + Prometheus stack to visualize:
- Request latency (p50, p95, p99)
- Error rates (4xx, 5xx)
- PCAP analysis duration
- MongoDB query performance
- Celery queue depth and task durations
- System metrics (CPU, RAM, disk)

---

## 11. Testing Strategy Expansion

### 11.1 Current Gap

You have **1 test file** (`test_pipeline.py`). Production needs much more:

### 11.2 Required Test Categories

| Category | What to Test | Tool |
|---|---|---|
| **Unit Tests** | Each module in isolation (rule engine, TLS parser, fingerprinting, risk scoring) | `pytest` |
| **Integration Tests** | Full pipeline: PCAP → MongoDB → API response | `pytest` + test MongoDB |
| **API Tests** | Every endpoint, auth, error cases, edge cases | `pytest` + `httpx.AsyncClient` |
| **Security Tests** | SQL/NoSQL injection, auth bypass, file upload attacks | `bandit`, manual |
| **Load Tests** | Concurrent uploads, many sessions, response times | `locust` or `k6` |
| **Contract Tests** | API schema backwards compatibility | `schemathesis` |

### 11.3 Example: API Integration Test

```python
# tests/integration/test_api.py
import pytest
from httpx import AsyncClient, ASGITransport
from secure_smtp.api.main import app


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_list_hosts_returns_200(client):
    response = await client.get("/api/hosts")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_analyze_rejects_non_pcap(client):
    response = await client.post(
        "/api/analyze",
        files={"file": ("malware.exe", b"MZ\x90\x00", "application/octet-stream")},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_missing_session_returns_404(client):
    response = await client.get("/api/sessions/999999")
    assert response.status_code == 404
```

### 11.4 Load Testing with Locust

```python
# tests/load/locustfile.py
from locust import HttpUser, task, between


class SecureSMTPUser(HttpUser):
    wait_time = between(1, 5)

    @task(10)
    def list_hosts(self):
        self.client.get("/api/hosts")

    @task(5)
    def get_session(self):
        self.client.get("/api/sessions/1")

    @task(1)
    def upload_pcap(self):
        with open("tests/fixtures/pcaps/good_tls13.pcap", "rb") as f:
            self.client.post("/api/analyze", files={"file": f})
```

```bash
locust -f tests/load/locustfile.py --host=http://localhost:8000
```

---

## 12. Performance & Scalability

### 12.1 PCAP Processing Optimization

Currently, the full pipeline runs **synchronously in one thread per PCAP**. For large PCAPs:

```python
# Use multiprocessing for stream-level parallelism
from concurrent.futures import ProcessPoolExecutor

def _run_analysis(job_id: str, pcap_path: str):
    ...
    with ProcessPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(process_single_stream, stream, rule_engine)
            for stream in packet_streams
        ]
        for future in futures:
            session_data = future.result()
            sessions_col.insert_one(session_data)
```

### 12.2 MongoDB Query Optimization

- Use **projection** to fetch only needed fields:
  ```python
  hosts_col.find({}, {"ip_or_hostname": 1, "aggregate_risk_score": 1, "_id": 0})
  ```
- Use **aggregation pipeline** for host rollups instead of fetching all documents:
  ```python
  pipeline = [
      {"$group": {"_id": "$host_id", "avg_score": {"$avg": "$risk_score.score_0_100"}}}
  ]
  ```

### 12.3 Caching with Redis

```python
import redis
import json

r = redis.from_url(settings.REDIS_URL)

def get_hosts_cached():
    cached = r.get("hosts_list")
    if cached:
        return json.loads(cached)
    hosts = list(hosts_col.find({}, {"_id": 0}))
    r.setex("hosts_list", 60, json.dumps(hosts, default=str))  # Cache 60s
    return hosts
```

### 12.4 Horizontal Scaling

```
                    ┌──────────────┐
                    │   Nginx LB   │
                    └──────┬───────┘
                ┌──────────┼──────────┐
                ▼          ▼          ▼
           ┌────────┐ ┌────────┐ ┌────────┐
           │ API #1 │ │ API #2 │ │ API #3 │
           └────────┘ └────────┘ └────────┘
                ║          ║          ║
                ╠══════════╩══════════╣
                ▼                     ▼
         ┌────────────┐       ┌────────────┐
         │   Redis    │       │  MongoDB   │
         │  (Celery)  │       │ Replica Set│
         └────────────┘       └────────────┘
                ║
        ┌───────╨───────┐
        ▼               ▼
   ┌──────────┐   ┌──────────┐
   │ Worker#1 │   │ Worker#2 │
   └──────────┘   └──────────┘
```

---

## 13. File Storage & Uploads

### 13.1 The Problem

Currently uploads and reports go to `/tmp/`. This means:
- **Lost on reboot**
- No persistence across container restarts
- No access control
- No deduplication

### 13.2 Solution Options

| Option | When to Use |
|---|---|
| **Local persistent volume** | Single server, low traffic |
| **AWS S3 / GCS / Azure Blob** | Cloud deployment, any scale |
| **MinIO** | Self-hosted S3-compatible (for on-prem) |

### 13.3 Example: S3 Integration

```bash
pip install boto3
```

```python
# src/secure_smtp/storage.py
import boto3
from secure_smtp.config import settings

s3 = boto3.client("s3")

def upload_pcap(job_id: str, file_content: bytes, filename: str) -> str:
    key = f"uploads/{job_id}/{filename}"
    s3.put_object(Bucket="securesmtp-data", Key=key, Body=file_content)
    return key

def upload_report(job_id: str, report_path: str, format: str) -> str:
    key = f"reports/{job_id}/report.{format}"
    s3.upload_file(report_path, "securesmtp-data", key)
    return key

def get_report_url(job_id: str, format: str) -> str:
    key = f"reports/{job_id}/report.{format}"
    return s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": "securesmtp-data", "Key": key},
        ExpiresIn=3600  # 1 hour
    )
```

---

## 14. ML Model Management

### 14.1 Current Issue

The Isolation Forest and risk model are **retrained from scratch on every PCAP upload**. This is fine for a demo but wasteful and inconsistent in production.

### 14.2 Solution: Model Registry

```python
# src/secure_smtp/ai/model_registry.py
import joblib
from pathlib import Path
from datetime import datetime

MODEL_DIR = Path("/var/securesmtp/models")
MODEL_DIR.mkdir(parents=True, exist_ok=True)


def save_model(model, name: str, version: str):
    """Save a trained model with version metadata."""
    path = MODEL_DIR / f"{name}_v{version}.joblib"
    joblib.dump({
        "model": model,
        "version": version,
        "trained_at": datetime.utcnow().isoformat(),
    }, path)
    return path


def load_latest_model(name: str):
    """Load the most recent version of a model."""
    models = sorted(MODEL_DIR.glob(f"{name}_v*.joblib"), reverse=True)
    if not models:
        return None
    data = joblib.load(models[0])
    return data["model"]
```

### 14.3 Scheduled Retraining

```python
# Retrain the anomaly model weekly with accumulated data
# Add to Celery beat schedule:
celery_app.conf.beat_schedule = {
    "retrain-anomaly-model": {
        "task": "secure_smtp.tasks.worker.retrain_anomaly_model",
        "schedule": crontab(hour=3, minute=0, day_of_week=0),  # Sunday 3 AM
    },
}
```

---

## 15. API Documentation & Versioning

### 15.1 API Versioning

Prefix all endpoints with a version:

```python
from fastapi import APIRouter

v1_router = APIRouter(prefix="/api/v1")

@v1_router.get("/hosts")
async def list_hosts():
    ...

app.include_router(v1_router)
```

This lets you introduce `/api/v2/` without breaking existing clients.

### 15.2 Proper OpenAPI Metadata

```python
app = FastAPI(
    title="Secure SMTP API",
    description="Passive Cryptographic Posture Intelligence & Explainable AI Risk Attribution",
    version="1.0.0",
    contact={"name": "Harshit Sharma", "email": "harshit@yourdomain.com"},
    license_info={"name": "MIT"},
    servers=[
        {"url": "https://api.securesmtp.yourdomain.com", "description": "Production"},
        {"url": "https://staging-api.securesmtp.yourdomain.com", "description": "Staging"},
    ],
)
```

### 15.3 Response Models

Define explicit Pydantic response models for every endpoint:

```python
from pydantic import BaseModel

class HostResponse(BaseModel):
    host_id: int
    ip: str
    aggregate_risk_score: float
    session_count: int

@app.get("/api/v1/hosts", response_model=list[HostResponse])
async def list_hosts():
    ...
```

---

## 16. Backup & Disaster Recovery

### 16.1 What Must Be Backed Up

| Data | Frequency | Retention |
|---|---|---|
| MongoDB (sessions, hosts, findings) | Daily + hourly WAL/oplog | 90 days |
| Uploaded PCAPs | Per upload (store in S3) | Per policy (30-365 days) |
| Generated Reports | Per generation | 1 year |
| ML Models | Per training run | Last 5 versions |
| Application config / secrets | On change | Versioned in secrets manager |

### 16.2 Recovery Procedures

Document and **test** these runbooks:

1. **Database restore from backup**: `mongorestore --uri="..." --gzip /backups/mongodb/latest/`
2. **Application rollback**: `docker compose pull && docker compose up -d` with previous image tag
3. **Data corruption**: Restore from last known good backup + replay PCAPs from S3

### 16.3 RTO/RPO Targets

| Metric | Target |
|---|---|
| **RPO** (Recovery Point Objective) | ≤ 1 hour (max data loss) |
| **RTO** (Recovery Time Objective) | ≤ 30 minutes (time to restore) |

---

## 17. Compliance & Audit Trail

### 17.1 Audit Logging

Log every sensitive action:

```python
# src/secure_smtp/audit.py
import structlog

audit_logger = structlog.get_logger("audit")

def log_pcap_upload(user: str, job_id: str, filename: str, file_size: int):
    audit_logger.info(
        "pcap_uploaded",
        user=user, job_id=job_id, filename=filename,
        file_size_bytes=file_size, action="UPLOAD"
    )

def log_report_download(user: str, job_id: str, format: str):
    audit_logger.info(
        "report_downloaded",
        user=user, job_id=job_id, format=format, action="DOWNLOAD"
    )

def log_data_deletion(user: str, entity: str, entity_id: str):
    audit_logger.warning(
        "data_deleted",
        user=user, entity=entity, entity_id=entity_id, action="DELETE"
    )
```

### 17.2 Data Retention Policy

```python
# Automated data cleanup — run via Celery Beat
@celery_app.task
def cleanup_expired_data():
    """Remove data older than retention period."""
    cutoff = datetime.utcnow() - timedelta(days=90)

    # Remove old sessions
    sessions_col = get_sessions_col()
    result = sessions_col.delete_many({"created_at": {"$lt": cutoff}})

    # Remove orphaned uploads
    for f in Path(settings.UPLOAD_DIR).iterdir():
        if f.stat().st_mtime < cutoff.timestamp():
            f.unlink()
```

---

## 18. Domain, DNS & TLS Certificates

### 18.1 DNS Setup

```
securesmtp.yourdomain.com          → Nginx Load Balancer IP
api.securesmtp.yourdomain.com      → Nginx (proxies to FastAPI)
dashboard.securesmtp.yourdomain.com → Nginx (proxies to Streamlit)
```

### 18.2 TLS Certificates

Use **Let's Encrypt** (free) with auto-renewal:

```bash
# Install Certbot
apt install certbot python3-certbot-nginx

# Obtain certificate
certbot --nginx -d securesmtp.yourdomain.com \
                -d api.securesmtp.yourdomain.com \
                -d dashboard.securesmtp.yourdomain.com

# Auto-renewal (added automatically by certbot)
# Verify: systemctl status certbot.timer
```

> **Irony check**: You're building a tool that detects expired TLS certificates — make sure your own certificates are managed properly! Set up monitoring for your own cert expiry.

---

## 19. Deployment Architecture Options

### Option A: Single VPS (Budget / Low Traffic)

```
┌─────────────────────────────────────┐
│            VPS (4GB+ RAM)           │
│                                     │
│   Nginx → FastAPI (Gunicorn)       │
│         → Streamlit                │
│   MongoDB (standalone)              │
│   Redis                            │
│   Celery Worker                    │
└─────────────────────────────────────┘
```

**Cost**: ~$20-40/month (DigitalOcean, Hetzner, Linode)
**Pros**: Simple, cheap
**Cons**: Single point of failure, limited scale

### Option B: Docker Compose on a Dedicated Server (Mid-Scale)

Full `docker-compose.yml` from §8.2, on a dedicated server or large VM (8GB+ RAM).

**Cost**: ~$50-100/month
**Pros**: Reproducible, easy to scale vertically
**Cons**: Still single host

### Option C: Kubernetes (Enterprise Scale)

```
┌──────────────────────────────────────────┐
│              Kubernetes Cluster          │
│                                          │
│  ┌───────────┐  ┌───────────┐           │
│  │ API Pod x3│  │Worker Pod │           │
│  │ (FastAPI) │  │(Celery)x2 │           │
│  └───────────┘  └───────────┘           │
│  ┌───────────┐  ┌───────────┐           │
│  │ Dashboard │  │  Nginx    │           │
│  │  Pod x2   │  │ Ingress   │           │
│  └───────────┘  └───────────┘           │
│                                          │
│  External: MongoDB Atlas + Redis Cloud   │
└──────────────────────────────────────────┘
```

**Cost**: ~$200-500+/month
**Pros**: Auto-scaling, self-healing, rolling deployments
**Cons**: Complexity, K8s expertise required

### Option D: Serverless / PaaS (Fastest Path)

| Service | Component |
|---|---|
| **Railway / Render / Fly.io** | FastAPI + Celery Worker |
| **MongoDB Atlas** | Database (free tier available) |
| **Redis Cloud** | Celery broker |
| **Streamlit Cloud** | Dashboard (free for public apps) |
| **AWS S3** | File storage |

**Cost**: $0-50/month for low traffic
**Pros**: Zero infrastructure management
**Cons**: Vendor lock-in, less control

---

## 20. Pre-Launch Checklist

Use this checklist to verify production readiness before going live:

### Security
- [ ] CORS restricted to specific origins (not `*`)
- [ ] API authentication implemented (API keys or JWT)
- [ ] Rate limiting enabled on all public endpoints
- [ ] HTTPS enforced everywhere (HTTP → HTTPS redirect)
- [ ] Security headers added (HSTS, CSP, X-Frame-Options)
- [ ] File upload validation (size, type, magic bytes)
- [ ] Streamlit XSRF protection re-enabled
- [ ] Swagger/ReDoc disabled in production
- [ ] No hardcoded secrets in code
- [ ] Secrets stored in a secrets manager
- [ ] Dependency vulnerability scan passes (`safety check`)
- [ ] Static analysis passes (`bandit -r src/`)

### Infrastructure
- [ ] MongoDB has authentication enabled
- [ ] MongoDB deployed as replica set (or Atlas)
- [ ] Automated database backups configured
- [ ] Redis deployed for task queue
- [ ] Celery workers running with retry and timeout
- [ ] Gunicorn replaces dev `uvicorn --reload`
- [ ] Nginx reverse proxy in front of app servers
- [ ] TLS certificates provisioned and auto-renewing
- [ ] DNS records configured
- [ ] Docker images built and pushed to registry
- [ ] Health check endpoints responding

### Observability
- [ ] Structured logging configured (JSON format)
- [ ] Centralized log collection (ELK, CloudWatch, Datadog)
- [ ] Error tracking enabled (Sentry)
- [ ] Prometheus metrics exposed
- [ ] Grafana dashboards created
- [ ] Alerting rules configured (PagerDuty, Slack, email)
- [ ] Uptime monitoring configured (UptimeRobot, Pingdom)

### Testing
- [ ] Unit test coverage > 80%
- [ ] Integration tests pass against staging
- [ ] API contract tests pass
- [ ] Load test results acceptable
- [ ] Security scan passes
- [ ] Manual smoke test completed

### Operations
- [ ] CI/CD pipeline fully automated
- [ ] Rollback procedure documented and tested
- [ ] Disaster recovery plan documented and tested
- [ ] Runbook for common incidents written
- [ ] On-call rotation established
- [ ] Data retention policy implemented
- [ ] Audit logging enabled

### Documentation
- [ ] API documentation (OpenAPI) is accurate and versioned
- [ ] Architecture diagram up to date
- [ ] Deployment guide written
- [ ] Environment variables documented (`.env.example`)
- [ ] CHANGELOG maintained

---

## Summary of New Dependencies to Add

Add these to your `pyproject.toml` under `[project.dependencies]`:

```toml
[project.optional-dependencies]
production = [
    "gunicorn>=21.2",
    "celery[redis]>=5.3",
    "redis>=5.0",
    "pydantic-settings>=2.0",
    "structlog>=23.1",
    "python-json-logger>=2.0",
    "sentry-sdk[fastapi]>=1.35",
    "prometheus-fastapi-instrumentator>=6.0",
    "slowapi>=0.1.8",
    "boto3>=1.29",
    "flower>=2.0",
    "joblib>=1.3",
]
```

Install for production:
```bash
pip install -e ".[production]"
```

---

## Priority Order (What to Do First)

| Priority | Task | Effort | Impact |
|---|---|---|---|
| 🔴 P0 | Fix CORS + add API auth | 2 hours | Prevents unauthorized access |
| 🔴 P0 | Enable MongoDB auth | 1 hour | Prevents data breach |
| 🔴 P0 | Move secrets to env vars / secrets manager | 2 hours | Prevents credential leaks |
| 🟠 P1 | Dockerize the application | 4 hours | Reproducible deployments |
| 🟠 P1 | Replace BackgroundTasks with Celery | 4 hours | Reliable job processing |
| 🟠 P1 | Add Nginx reverse proxy + HTTPS | 2 hours | Encrypted traffic |
| 🟠 P1 | Fix file storage (out of `/tmp/`) | 2 hours | Data persistence |
| 🟡 P2 | Set up CI/CD pipeline | 3 hours | Automated testing & deployment |
| 🟡 P2 | Add structured logging + Sentry | 2 hours | Debuggability |
| 🟡 P2 | Expand test coverage | 8 hours | Reliability |
| 🟢 P3 | Set up monitoring (Prometheus + Grafana) | 4 hours | Operational visibility |
| 🟢 P3 | Add load testing | 3 hours | Performance validation |
| 🟢 P3 | ML model registry | 4 hours | Consistent predictions |
| 🔵 P4 | Kubernetes migration | 16+ hours | Enterprise scale |

---

> **Bottom line**: Your core analysis pipeline is solid. The biggest gaps are all operational — security, infrastructure, and observability. Address the P0 items before any public or client-facing deployment. The P1 items should follow within the first sprint. Everything else can be rolled out iteratively.
