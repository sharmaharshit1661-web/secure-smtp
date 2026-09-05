# 🛡️ Secure SMTP

**Passive Cryptographic Posture Intelligence & Explainable AI Risk Attribution for SMTP, IMAP & POP3**

Secure SMTP is an enterprise-grade passive network forensic and posture assessment platform. It ingests network packet capture (PCAP) files containing email traffic and automatically assesses the cryptographic security posture of the mail infrastructure — without ever decrypting message content or violating privacy.

---

## 🔒 Core Capabilities

1. **Passive Reconstruction**: Reassembles bi-directional TCP sessions from raw packet captures (SMTP, IMAP, POP3) without decrypting payloads.
2. **Cryptographic Deep Inspection**: Parses TLS ClientHello / ServerHello handshakes, cipher suites, key exchange methods, and full X.509 certificate chains. Computes **JA3, JA3S, JA4, and JA4S** fingerprints.
3. **Declarative Rule Engine**: Evaluates sessions against a YAML rulebook mapped to **NIST SP 800-52r2**, **PCI-DSS v4.0**, and **RFC 8996**.
4. **Explainable AI Risk Scoring & Anomaly Detection**: Calculates rule-weighted risk scores (0–100) with **SHAP feature attribution** and detects statistical cryptographic anomalies using **Isolation Forest**.
5. **MongoDB Document Storage**: High-performance persistence for deep nested session dossiers, certificates, and compliance findings.
6. **Executive Reporting**: Generates instant boardroom-ready audit reports in **PDF, HTML, and JSON**.

---

## ⚡ Quick Start

### Prerequisites

- Python 3.11+
- MongoDB (running locally on `localhost:27017`)
- pip

### 1-Command Launch

```bash
# Clone or enter the project directory
cd "Secure HTTP"

# Launch everything (FastAPI backend + React frontend with auto-seeded demo data)
./start_demo.sh
```

### Manual Setup

```bash
# Create virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Start the API backend
PYTHONPATH=src uvicorn secure_smtp.api.main:app --reload --port 8000

# In another terminal, start the React frontend
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` to access the Secure SMTP Security Operations Console.

---

## 🏗️ Technical Architecture

```
[ PCAP Ingest ] → [ Protocol / STARTTLS Identification ] → [ TLS Handshake & Cert Parsing ]
                                                                      ↓
[ Rule Engine ] → [ Explainable AI Risk Scoring + Isolation Forest ] → [ MongoDB + Web UI + Reports ]
```

### Tech Stack

| Component | Technology | Description |
|---|---|---|
| **Packet Parsing** | Scapy | Reassembles bi-directional TCP streams |
| **TLS & Certificates** | `cryptography` (X.509) | Key lengths, signature algorithms, chain validation |
| **Fingerprinting** | JA3, JA3S, JA4, JA4S | Client and server cryptographic fingerprinting |
| **Rule Engine** | YAML + Safe Evaluator | Mapped to NIST SP 800-52r2, PCI-DSS v4.0 |
| **AI / ML** | scikit-learn + SHAP | Isolation Forest anomaly detection & SHAP attributions |
| **Database** | MongoDB (PyMongo) | Document-oriented persistence |
| **API Backend** | FastAPI + Uvicorn | Async REST endpoints |
| **Frontend Console** | React 19 + Vite | Command-Cartography dark-mode SOC console |
| **Reporting** | WeasyPrint + Jinja2 | Exportable PDF, HTML, and JSON audit dossiers |

---

## 📁 Project Structure

```
src/secure_smtp/
├── ingest/         # PCAP reading, TCP stream reassembly, protocol detection
├── tls/            # TLS handshake parsing, certificate extraction, JA3/JA4 fingerprinting
├── rules/          # YAML-driven crypto weakness rule engine
├── ai/             # Risk scoring, Isolation Forest anomaly detection, SHAP explanations
├── db/             # MongoDB connection manager and Pydantic v2 document models
├── reporting/      # JSON, HTML, PDF report generation
└── api/            # FastAPI REST endpoints
frontend/           # Modern React + Vite web console
scripts/            # PCAP generators and MongoDB demo data seeders
tests/              # Comprehensive test suite (120 unit tests)
```

---

## 📊 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/analyze` | Upload PCAP file for real-time analysis |
| `GET` | `/api/analyze/{job_id}/status` | Check analysis status |
| `GET` | `/api/hosts` | List all hosts with aggregate risk scores |
| `GET` | `/api/hosts/{id}` | Host detail + associated session streams |
| `GET` | `/api/sessions/{id}` | Full deep session telemetry document |
| `GET` | `/api/sessions/{id}/explain` | SHAP feature attribution breakdown |
| `GET` | `/api/reports/{job_id}.json` | Download JSON audit report |
| `GET` | `/api/reports/{job_id}.pdf` | Download PDF audit report |
| `GET` | `/api/reports/{job_id}.html` | Download HTML audit report |

---

## 📋 Documentation

- [`DEMO_GUIDE.md`](DEMO_GUIDE.md) — Live Pitch & Demonstration Guide

---

## 👤 Author & Ownership

This project belongs to **Harshit Sharma** ([@sharmaharshit1661-web](https://github.com/sharmaharshit1661-web)).

---

## License

MIT
