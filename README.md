# SecureMailScope

**AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**

SecureMailScope is a passive network forensic tool that ingests PCAP files containing SMTP, IMAP, and POP3 traffic and automatically assesses the cryptographic security posture of the email infrastructure — without ever decrypting message content.

## 🔒 What It Does

1. **Reconstructs** email protocol sessions from raw packet captures
2. **Parses** TLS handshakes, cipher suites, and X.509 certificate chains
3. **Evaluates** crypto posture against a declarative YAML rule engine
4. **Scores** risk using AI (XGBoost + SHAP explainability) and detects anomalies (Isolation Forest)
5. **Reports** findings through an interactive dashboard and exportable reports (JSON/PDF/HTML)

## ⚡ Quick Start

### Prerequisites

- Python 3.11+
- pip

### Setup & Quick Run (1-Command Launch)

```bash
# Clone or enter the project directory
cd "Secure HTTP"

# Launch everything (FastAPI + Streamlit with auto-seeded demo data)
./start_demo.sh
```

### Manual Setup (Alternative)

```bash
# Create virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Start the API backend
uvicorn securemailscope.api.main:app --reload --port 8000

# In another terminal, start the dashboard
source .venv/bin/activate
streamlit run dashboard/app.py
```

Then open `http://localhost:8501` in your browser.

### Usage

1. **Upload** a `.pcap` or `.pcapng` file through the dashboard
2. Wait for analysis to complete (typically seconds for small PCAPs)
3. Navigate to **Fleet Overview** to see host-level risk scores
4. Click into **Session Explorer** to drill into individual sessions
5. **Export** reports as JSON, PDF, or HTML

## 🏗️ Architecture

Six-stage pipeline:

```
[PCAP Ingest] → [Protocol/STARTTLS ID] → [TLS Handshake + Cert Parsing]
                                            ↓
[Rule Engine] → [AI Risk Scoring + Anomaly Detection] → [Reports + Dashboard]
```

**Stages 1–3** (Forensic Reconstruction): Deterministic, must be exactly correct.
**Stages 4–6** (Intelligence Layer): Sits on top of stage 1–3 facts, never replaces them.

### Tech Stack

| Component | Technology |
|---|---|
| PCAP Parsing | scapy |
| TLS/Cert Parsing | cryptography |
| Rule Engine | YAML + safe Python evaluator |
| ML Scoring | XGBoost + scikit-learn + SHAP |
| Anomaly Detection | Isolation Forest |
| API | FastAPI |
| Dashboard | Streamlit + Plotly |
| Reports | Jinja2 + WeasyPrint |
| Database | SQLite (SQLModel) |

## 📁 Project Structure

```
src/securemailscope/
├── ingest/         # PCAP reading, TCP reassembly, protocol detection
├── tls/            # TLS handshake parsing, certificate extraction, fingerprinting
├── rules/          # YAML-driven crypto weakness rule engine
├── ai/             # Risk scoring, anomaly detection, SHAP explanations
├── reporting/      # JSON, HTML, PDF report generation
├── api/            # FastAPI application
└── db/             # SQLModel database models
dashboard/          # Streamlit dashboard
tests/              # Test suite
```

## 🔍 Rule Engine

Rules are defined in [`src/securemailscope/rules/ruleset.yaml`](src/securemailscope/rules/ruleset.yaml). Add new rules without code changes:

```yaml
- id: your-rule-id
  applies_to: handshake.tls_version_negotiated
  condition: "value in ['SSLv3']"
  severity: critical
  message: "SSLv3 detected: {value}"
  recommendation: "Upgrade to TLS 1.2+"
```

## 📊 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/analyze` | Upload PCAP for analysis |
| GET | `/api/analyze/{job_id}/status` | Check analysis progress |
| GET | `/api/hosts` | List all hosts with risk scores |
| GET | `/api/hosts/{id}` | Host detail + sessions |
| GET | `/api/sessions/{id}` | Full session detail |
| GET | `/api/sessions/{id}/explain` | SHAP explanation |
| GET | `/api/reports/{job_id}.json` | JSON report |
| GET | `/api/reports/{job_id}.pdf` | PDF report |
| GET | `/api/reports/{job_id}.html` | HTML report |

## 📋 Documentation

- [`01_PRD.md`](01_PRD.md) — Product Requirements
- [`02_TAD.md`](02_TAD.md) — Technical Architecture
- [`03_IMPLEMENTATION_PLAN.md`](03_IMPLEMENTATION_PLAN.md) — Build Phases

## License

MIT
