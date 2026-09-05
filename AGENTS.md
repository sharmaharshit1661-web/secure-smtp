# AGENTS.md — Secure SMTP Project Context

> This file is auto-loaded at the start of every AI conversation in this workspace.
> It provides full context about the project so the agent can give accurate, codebase-aware answers.

---

## Project Identity

**Name:** Secure SMTP (SecureMailScope)
**Author:** Harshit Sharma
**License:** MIT
**Python:** 3.11+
**Package name:** `securemailscope`

**What it does:** An enterprise-grade passive network forensic platform that ingests PCAP files containing email traffic (SMTP, IMAP, POP3), reconstructs TLS handshakes and certificate chains, evaluates cryptographic security posture against compliance standards (NIST SP 800-52r2, PCI-DSS v4.0, RFC 8996), and produces AI-explained risk scores with anomaly detection — all without decrypting message content.

---

## Architecture — 6-Stage Pipeline

```
[1: PCAP Ingest] → [2: Protocol/STARTTLS ID] → [3: TLS Handshake + Cert Parsing]
                                                          ↓
[4: Rule Engine] → [5: AI Risk Scoring + Anomaly Detection] → [6: Reports + Dashboard]
```

- **Stages 1–3** = deterministic forensic reconstruction (must be exactly correct)
- **Stages 4–6** = intelligence layer (sits on top of stage 1–3 facts)

---

## Tech Stack

| Component | Technology | File(s) |
|---|---|---|
| PCAP Parsing | Scapy | `src/securemailscope/ingest/pcap_reader.py`, `tcp_stream.py`, `protocol_id.py` |
| TLS & Certs | `cryptography` (X.509) | `src/securemailscope/tls/handshake_parser.py`, `cert_parser.py` |
| Fingerprinting | JA3, JA3S, JA4, JA4S | `src/securemailscope/tls/fingerprint.py` |
| Rule Engine | YAML + safe evaluator | `src/securemailscope/rules/engine.py`, `ruleset.yaml` |
| AI / ML | scikit-learn (Isolation Forest) + SHAP | `src/securemailscope/ai/risk_model.py`, `anomaly_model.py`, `explain.py`, `features.py` |
| Database | MongoDB (PyMongo) | `src/securemailscope/db/mongodb.py`, `models.py` |
| API Backend | FastAPI + Uvicorn | `src/securemailscope/api/main.py` |
| Dashboard | Streamlit + Plotly | `dashboard/app.py` |
| Reporting | WeasyPrint + Jinja2 | `src/securemailscope/reporting/json_export.py`, `html_export.py`, `pdf_export.py` |

---

## Project Structure

```
Secure HTTP/
├── src/securemailscope/         # Main Python package
│   ├── __init__.py              # Version: 0.1.0
│   ├── ingest/                  # Stage 1-2: PCAP reading, TCP reassembly, protocol detection
│   ├── tls/                     # Stage 3: TLS handshake parsing, cert extraction, JA3/JA4
│   ├── rules/                   # Stage 4: YAML-driven crypto weakness rule engine
│   │   ├── engine.py            # Rule evaluator (safe eval, no raw eval())
│   │   └── ruleset.yaml         # 11 rules: deprecated TLS, weak cipher, no FS, cert issues, STARTTLS strip
│   ├── ai/                      # Stage 5: Risk scoring, Isolation Forest anomaly detection, SHAP
│   ├── reporting/               # Stage 6: JSON, HTML, PDF report generation
│   ├── api/                     # FastAPI REST endpoints
│   │   └── main.py              # 721 lines — all endpoints + background analysis pipeline
│   └── db/
│       ├── models.py            # Pydantic v2 models: Session, TLSHandshake, Certificate, Finding, RiskScore, AnomalyScore, Host, AnalysisJob
│       ├── mongodb.py           # MongoDB connection (singleton client), collection accessors, indexes, serialization
│       └── session.py           # Legacy SQLite session helper (not used in current MongoDB flow)
├── dashboard/
│   └── app.py                   # Streamlit SOC dashboard (~69KB, glassmorphic dark theme)
├── tests/
│   ├── unit/test_pipeline.py    # ~120 unit tests
│   └── fixtures/pcaps/          # Test PCAP files
├── scripts/
│   └── seed_demo_data.py        # Seeds MongoDB with fixture PCAPs for demos
├── .streamlit/config.toml       # Streamlit theme + server config
├── pyproject.toml               # Dependencies and build config
├── start_demo.sh                # 1-command launcher (FastAPI + Streamlit + seed)
├── PRODUCTION_READY.md          # Comprehensive production readiness guide (20 sections)
├── 01_PRD.md                    # Product Requirements Document
├── 02_TAD.md                    # Technical Architecture Document
├── 03_IMPLEMENTATION_PLAN.md    # Phased build plan
├── DEMO_GUIDE.md                # Live pitch guide
└── securemailscope.db           # Legacy SQLite file (ignored; MongoDB is the active DB)
```

---

## Key Data Models (Pydantic v2 — `db/models.py`)

```
Session         → id, src/dst IP:port, protocol (smtp|imap|pop3), tls_mode (implicit|starttls|none)
TLSHandshake    → versions, cipher, key exchange, forward secrecy, JA3/JA4 fingerprints
Certificate     → subject, issuer, SAN, expiry, key algo/length, signature algo, self-signed, chain validity
Finding         → rule_id, severity (info|low|medium|high|critical), evidence, message, recommendation
RiskScore       → score_0_100, tier (low|medium|high|critical), SHAP feature_attribution
AnomalyScore    → anomaly_score, is_anomalous, baseline_reference
Host            → ip_or_hostname, session_count, aggregate_risk_score
AnalysisJob     → job_id, status (queued|running|done|failed), timestamps
```

---

## API Endpoints (`/api/...`)

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/analyze` | Upload PCAP for analysis → returns `{job_id}` |
| GET | `/api/analyze/{job_id}/status` | Job status |
| GET | `/api/hosts` | All hosts sorted by risk |
| GET | `/api/hosts/{host_id}` | Host detail + sessions |
| GET | `/api/sessions/{session_id}` | Full session telemetry |
| GET | `/api/sessions/{session_id}/explain` | SHAP feature attribution |
| GET | `/api/reports/{job_id}.json` | JSON report download |
| GET | `/api/reports/{job_id}.pdf` | PDF report download |
| GET | `/api/reports/{job_id}.html` | HTML report download |

---

## MongoDB Configuration

- **URI env var:** `SECURE_SMTP_MONGO_URI` (default: `mongodb://localhost:27017`)
- **DB name env var:** `SECURE_SMTP_MONGO_DB` (default: `secure_smtp`)
- **Collections:** `hosts`, `sessions`, `analysis_jobs`, `counters`
- **Integer IDs** via atomic counter sequence (`counters` collection)
- **Indexes:** unique on `hosts.id`, `hosts.ip_or_hostname`, `sessions.id`, `analysis_jobs.job_id`; secondary on `sessions.host_id`, `hosts.aggregate_risk_score`

---

## How to Run

```bash
# Quick start (seeds data + launches both servers)
./start_demo.sh

# Manual
source .venv/bin/activate
PYTHONPATH=src uvicorn securemailscope.api.main:app --reload --port 8000
PYTHONPATH=src streamlit run dashboard/app.py  # separate terminal

# Tests
pytest tests/ -v

# Seed demo data
PYTHONPATH=src python scripts/seed_demo_data.py
```

- Dashboard: http://localhost:8501
- API: http://localhost:8000
- Swagger: http://localhost:8000/docs

---

## Current State & Known Production Gaps

This project is currently **demo/hackathon grade**. See `PRODUCTION_READY.md` for the full guide. Critical gaps:

### 🔴 P0 — Must Fix Before Any Deployment
- **CORS is `allow_origins=["*"]`** — wide open (`main.py` line 60)
- **MongoDB has no authentication** — connects to bare `localhost:27017`
- **Streamlit XSRF protection disabled** (`.streamlit/config.toml` line 16)
- **File uploads go to `/tmp/`** — ephemeral, lost on reboot (`main.py` line 67-68)
- **No API authentication** — any client can call any endpoint
- **No secrets management** — hardcoded defaults

### 🟠 P1 — Needed for Reliability
- Background tasks use in-process `FastAPI BackgroundTasks` (no retry, no persistence)
- No Docker containerization
- No reverse proxy (Nginx) or HTTPS
- Dev server (`uvicorn --reload`) instead of production Gunicorn
- `@app.on_event("startup")` is deprecated — should use `lifespan`

### 🟡 P2 — Needed for Operational Maturity
- Only 1 test file — no integration, load, or security tests
- No structured logging or centralized log collection
- No error tracking (Sentry)
- No CI/CD pipeline
- No health check endpoint

---

## Coding Conventions

- **Python 3.11+**, type hints everywhere
- **Pydantic v2** for all data models (use `model_dump()`, not `dict()`)
- **Ruff** for linting (line length 100, rules: E, F, W, I, UP)
- **Enums** for protocol types, TLS modes, severities, risk tiers, key exchange types
- **MongoDB** document storage (not SQLite — `session.py` is legacy)
- JSON-encoded fields for lists/dicts stored in Pydantic models (e.g., `tls_version_offered`, `extensions`, `feature_attribution`)
- Import from `securemailscope.db.mongodb` for DB access, never instantiate `MongoClient` directly
- Use `get_next_sequence("name")` for integer ID generation
- Rule engine conditions in `ruleset.yaml` use a safe evaluator — never `eval()`
- SHAP explanations stored as JSON in `RiskScore.feature_attribution`
- All datetime operations use `datetime.now(UTC)` (timezone-aware)

---

## Dependencies (from `pyproject.toml`)

**Core:** scapy, cryptography, pyyaml, scikit-learn, xgboost, shap, numpy, pandas, fastapi, uvicorn, python-multipart, weasyprint, reportlab, jinja2, pymongo, sqlmodel, streamlit, httpx, plotly

**Dev:** pytest, pytest-asyncio, ruff

**Optional:** anthropic (LLM narrative enrichment)
