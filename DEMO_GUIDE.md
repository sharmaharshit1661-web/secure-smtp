# 🔒 SecureMailScope — Judge Presentation & Demo Guide

> **AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**

---

## 🎯 1. Executive Summary & Problem Statement

Email protocols (**SMTP, IMAP, POP3**) secure the majority of enterprise communications, yet email infrastructure is notoriously vulnerable to **silent cryptographic degradation**:
- **STARTTLS Stripping / Downgrade Attacks**: Active on-path attackers strip the `STARTTLS` keyword from SMTP `EHLO` responses, forcing transmission into unencrypted plaintext without user notice.
- **Legacy Protocol & Cipher Inertia**: Servers still negotiating deprecated `TLS 1.0/1.1`, RC4, 3DES, or RSA key exchange without forward secrecy.
- **Certificate Hygiene Gaps**: Expired certificates, weak signature algorithms (SHA-1/MD5), insufficient RSA key lengths (<2048-bit), or self-signed certs in production.
- **TLS 1.3 Inspection Challenges**: TLS 1.3 encrypts certificates post-ServerHello; systems must gracefully handle limited visibility while inspecting ClientHello/ServerHello negotiations and extensions.

**SecureMailScope** solves this by providing passive, forensic PCAP-based security posture analysis, extracting cryptographic facts, evaluating declarative security rules, computing explainable AI risk scores with SHAP attribution, and flagging protocol anomalies via Isolation Forests.

---

## 🏗️ 2. Architectural Pipeline

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  PCAP / Live │ ──> │ TCP Stream   │ ──> │ Protocol &   │
│  Traffic     │     │ Reassembly   │     │ STARTTLS ID  │
└──────────────┘     └──────────────┘     └──────────────┘
                                                 │
                                                 ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Declarative  │ <── │ X.509 Cert   │ <── │ TLS Handshake│
│ Rule Engine  │     │ Chain Parser │     │ & JA3/JA4 FP │
└──────────────┘     └──────────────┘     └──────────────┘
       │
       ▼
┌────────────────────────────────────────────────────────┐
│ Stage 5: Dual-Layer Explainable AI & ML Scoring        │
│  • Layer 1: Rule-weighted Base Risk (0–100)            │
│  • Layer 2: XGBoost Calibration + SHAP Feature Weights │
│  • Layer 3: Isolation Forest Unsupervised Anomalies    │
└────────────────────────────────────────────────────────┘
       │
       ▼
┌────────────────────────────────────────────────────────┐
│ Stage 6: FastAPI Backend + Streamlit Executive UI      │
│  • Interactive Dashboard (Fleet + Session Deep-Dive)   │
│  • Multi-Format Export (JSON, HTML, Multi-Page PDF)    │
└────────────────────────────────────────────────────────┘
```

---

## 🚀 3. Quick Start (1-Command Launch)

```bash
# Launch both FastAPI (:8000) and Streamlit (:8501) with auto-seeded demo data:
./start_demo.sh
```

- **Streamlit Dashboard**: [http://localhost:8501](http://localhost:8501)
- **FastAPI Interactive Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Test Suite**: `python -m pytest tests/unit/test_pipeline.py -v` (120/120 passing tests)

---

## 🎬 4. Step-by-Step Judge Demonstration (3-Minute Script)

### Step 1: Fleet Overview Tab (`http://localhost:8501`)
1. Open the **Streamlit Dashboard** and navigate to **🌐 Fleet Overview**.
2. **Point out the High-Level Metrics**:
   - Total Hosts Analyzed, Total Sessions, Fleet Average Risk Score, and Critical Hosts.
3. **Show Risk Distribution Bar Chart**:
   - Point to high-risk hosts (`192.168.1.20` running TLS 1.0 + RC4, `192.168.1.30` stripped STARTTLS, `192.168.1.31` plaintext).
   - Point to pristine hosts (`192.168.1.10` TLS 1.2 ECDHE, `192.168.1.11` modern TLS 1.3).

### Step 2: Session Explorer Deep-Dive
1. Navigate to **🔍 Session Explorer** on the sidebar.
2. Select Host **`192.168.1.20`** (Legacy Server):
   - **Risk Gauge**: High Risk Score (>50/100).
   - **TLS Details Tab**: Displays negotiated `TLS 1.0`, cipher `TLS_RSA_WITH_RC4_128_SHA`, No Forward Secrecy, JA3 fingerprint.
   - **Findings Tab**: Flags `deprecated-tls-version`, `weak-cipher`, `no-forward-secrecy` with actionable remediation guidance.
   - **Explanation Tab**: Shows feature contribution percentage breakdown and feature vector.
3. Select Host **`192.168.1.30`** (STARTTLS Stripping Demo):
   - Note that STARTTLS was advertised in `EHLO` but never initiated — classified as `NONE (Plaintext)` with Critical Risk.
4. Select Host **`192.168.1.11`** (TLS 1.3 Modern Server):
   - Shows `TLS 1.3`, `TLS_AES_128_GCM_SHA256`, forward secrecy enabled, and note on `visibility_limited=True` gracefully handled.

### Step 3: PCAP Upload & Real-Time Analysis
1. Navigate to **📤 Upload & Analyze**.
2. Drag and drop any individual test PCAP from `tests/fixtures/pcaps/` (e.g., `smtp_expired_cert.pcap` or `pop3_sha1_cert.pcap`).
3. Click **🚀 Start Analysis** — watch real-time background processing, instant completion, and celebratory confirmation.
4. Download the generated **JSON**, **HTML**, or **PDF** executive reports directly from the download buttons.

---

## 🧪 5. Included Test Fixture Scenarios

All scenarios are deterministically generated via Scapy in `scripts/generate_test_pcaps.py` and labeled in `tests/fixtures/pcaps/labels.json`:

| PCAP Scenario | Protocol | TLS Config | Key Attack / Weakness Tested | Expected Findings |
| :--- | :--- | :--- | :--- | :--- |
| `smtp_tls12_good.pcap` | SMTP (25) | TLS 1.2 / ECDHE | Baseline Good TLS | Clean (Self-signed test cert) |
| `smtp_tls13_good.pcap` | SMTP (465) | TLS 1.3 / AES-GCM | Modern TLS 1.3 / Encrypted Cert | Clean / Zero Findings |
| `smtp_tls10_rc4.pcap` | SMTP (25) | TLS 1.0 / RC4 | Deprecated Version + Broken Cipher | `deprecated-tls-version`, `weak-cipher`, `no-forward-secrecy` |
| `smtp_expired_cert.pcap` | SMTP (25) | TLS 1.2 | Expired X.509 Certificate | `cert-expired` |
| `smtp_self_signed_weak_key.pcap` | SMTP (25) | TLS 1.2 / RSA | 1024-bit RSA Key + No FS | `weak-cert-key-rsa`, `no-forward-secrecy` |
| `smtp_starttls_stripped.pcap` | SMTP (25) | None | MitM STARTTLS Stripping Attack | `no-tls` |
| `smtp_plaintext.pcap` | SMTP (25) | None | Unencrypted Mail Flow | `no-tls` |
| `imap_tls12_good.pcap` | IMAP (993) | TLS 1.2 / Implicit | Implicit TLS Mail Retrieval | Clean Baseline |
| `pop3_sha1_cert.pcap` | POP3 (110) | TLS 1.2 / STLS | SHA-1 Signature in Cert | `weak-cert-signature` |
| `smtp_no_forward_secrecy.pcap` | SMTP (465) | TLS 1.2 / RSA | RSA Static Key Exchange | `no-forward-secrecy` |
| `demo_composite.pcap` | Multi | Multi-Session | Full Fleet Multi-Host Simulation | Comprehensive Multi-Host Assessment |

---

## 💡 6. Judge Q&A Cheat Sheet

**Q: How is this different from generic network scanners (like Nmap/testssl.sh)?**
> *A: Active scanners actively probe endpoints and can be blocked by firewalls or rate-limiters. SecureMailScope performs **passive forensic analysis on actual network captures**, analyzing real sessions, client-server negotiation dynamics, STARTTLS stripping, and JA3/JA4 client fingerprints without emitting a single probe packet.*

**Q: How does the AI explainability work?**
> *A: SecureMailScope uses a two-tier explainability engine. First, every finding provides deterministic rule-weighted contributions with exact percentage breakdown. Second, when trained on labeled baseline data, our XGBoost calibration model integrates SHAP (SHapley Additive exPlanations) values to output mathematically rigorous feature attributions.*

**Q: How are false positives prevented (PRD NFR-2)?**
> *A: Our test suite enforces strict negative testing (`test_expected_rules_silent`). In 120 automated test assertions, modern TLS 1.2 and 1.3 configurations are verified to never fire false alarms on deprecation, cipher strength, or key length.*

**Q: What happens with TLS 1.3 where certificates are encrypted?**
> *A: In TLS 1.3, handshake encryption begins immediately after ServerHello. SecureMailScope detects this via `Supported Versions` extension parsing, marks `visibility_limited=True`, extracts client/server cipher negotiations, and avoids raising false alarms on inaccessible certificate payloads.*
