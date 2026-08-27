# Technical Architecture Document (TAD)
## SecureMailScope

**Companion docs:** `01_PRD.md` (requirements this satisfies), `03_IMPLEMENTATION_PLAN.md` (build order)
**Audience:** whoever/whatever (including an AI coding agent) implements this system. Every section is written to be directly actionable — concrete libraries, concrete schemas, concrete file layout.

---

## 1. System overview

Six-stage pipeline, two halves:

```
[1: PCAP ingest] -> [2: Protocol/STARTTLS ID] -> [3: TLS handshake + cert reconstruction]
        (deterministic forensic reconstruction — must be exactly correct)
                              |
                              v
[4: Crypto rule engine] -> [5: AI risk scoring + anomaly detection] -> [6: Reports + dashboard]
        (intelligence layer — sits on top of stage 1-3 facts, never replaces them)
```

Golden rule for implementation order: **stages 1–3 must be validated correct before any code in stage 5 is trusted.** The ML layer is only as good as the facts it scores.

## 2. Tech stack

| Layer | Choice | Notes |
|---|---|---|
| Language | Python 3.11+ | Single language across the whole pipeline minimizes glue code |
| PCAP parsing / TCP reassembly | `scapy` | Easiest to hand-roll the "plaintext until STARTTLS, then switch to TLS parsing" state machine. Fall back to `dpkt` only if profiling shows scapy is too slow on large files |
| TLS record/handshake parsing | `scapy.layers.tls` (or manual parsing via `cryptography` primitives if scapy's TLS layer proves insufficient) | Only need to *read* handshake fields, never decrypt |
| Certificate parsing/validation | `cryptography` (`cryptography.x509`) | Chain, expiry, key length/algorithm, signature algorithm |
| JA3/JA4 fingerprinting | Existing maintained OSS implementation (e.g. a Python JA3 lib) for JA3/JA3S; shell out to Zeek's `ja4` package or a maintained JA4 CLI for JA4/JA4S if a pure-Python implementation isn't readily available — do not hand-roll the hashing spec | See TAD §4.3 |
| Optional NSM shortcut | Zeek or Suricata run in offline/pcap mode | Both natively emit `ssl.log` / `eve.json` with TLS version, cipher, JA3/JA4, and cert fields already parsed. Use as an accelerant for stage 3 if hand-parsing TLS becomes the bottleneck — treat their output as an alternate/validating data source, not a replacement for owning the pipeline logic |
| Rule engine | Plain Python module driven by a YAML ruleset (see §5) | Declarative — new rules added without code changes |
| ML | `scikit-learn` (Isolation Forest, Logistic Regression) + `xgboost` or `lightgbm` for the calibrated risk model; `shap` for explainability | See §6 |
| Backend/API | `FastAPI` | See §7 for the contract |
| Reports | `weasyprint` (HTML→PDF), `jinja2` (HTML templates), `json` (native) | |
| Dashboard | `Streamlit` (fastest path to a working demo) — or a React + Recharts frontend against the FastAPI backend if UI polish matters more than speed | Pick based on team frontend bandwidth (see PRD persona/timeline) |
| Storage | SQLite (via `sqlmodel` or plain `sqlite3`) | Zero setup; swap for Postgres later if needed, schema is small |

## 3. Repository layout

```
securemailscope/
├── 01_PRD.md
├── 02_TAD.md
├── 03_IMPLEMENTATION_PLAN.md
├── pyproject.toml
├── src/
│   └── securemailscope/
│       ├── ingest/            # Stage 1-2: pcap read, TCP reassembly, protocol/STARTTLS ID
│       │   ├── pcap_reader.py
│       │   ├── tcp_stream.py
│       │   └── protocol_id.py
│       ├── tls/                # Stage 3: handshake + cert parsing, fingerprinting
│       │   ├── handshake_parser.py
│       │   ├── cert_parser.py
│       │   └── fingerprint.py  # JA3/JA3S/JA4/JA4S
│       ├── rules/              # Stage 4: rule engine
│       │   ├── engine.py
│       │   └── ruleset.yaml
│       ├── ai/                 # Stage 5: risk scoring + anomaly detection
│       │   ├── features.py
│       │   ├── risk_model.py
│       │   ├── anomaly_model.py
│       │   └── explain.py      # SHAP wiring
│       ├── reporting/          # Stage 6: exporters
│       │   ├── json_export.py
│       │   ├── pdf_export.py
│       │   ├── html_export.py
│       │   └── templates/
│       ├── api/                # FastAPI app (see §7)
│       │   └── main.py
│       └── db/
│           ├── models.py       # see §4
│           └── session.py
├── dashboard/                   # Streamlit app or React app (per stack choice)
├── tests/
│   ├── unit/
│   └── fixtures/
│       └── pcaps/              # labeled test PCAPs, see §7 of PRD / §9 below
└── scripts/
    └── generate_test_pcaps.sh  # spins up Docker mail servers + captures traffic, see §9
```

## 4. Data model

Core entities (as SQLModel/dataclass — exact ORM is an implementation detail, the shape is not):

```
Session
  id, pcap_source, src_ip, dst_ip, src_port, dst_port
  protocol            # smtp | imap | pop3
  tls_mode            # implicit | starttls | none
  starttls_completed  # bool — false + advertised = potential stripping (FR-4)
  handshake: TLSHandshake (1:1, nullable if tls_mode == none)
  findings: [Finding]  (1:many, from rule engine)
  risk_score: RiskScore (1:1)
  anomaly_score: AnomalyScore (1:1)

TLSHandshake
  session_id (FK)
  tls_version_offered   # list, from ClientHello
  tls_version_negotiated
  cipher_suite_negotiated
  key_exchange_type     # ecdhe | dhe | rsa | unknown
  forward_secrecy: bool
  ja3, ja3s, ja4, ja4s
  extensions: JSON
  visibility_limited: bool   # true if TLS1.3/ECH hid fields we'd normally extract (FR-19)

Certificate
  handshake_id (FK), chain_position
  subject, issuer, san: [str]
  not_before, not_after
  public_key_algorithm, key_length_bits
  signature_algorithm
  self_signed: bool
  chain_valid: bool

Finding
  session_id (FK)
  rule_id             # references ruleset.yaml entry
  severity            # info | low | medium | high | critical
  evidence            # structured — which field(s) triggered it
  recommendation_text

RiskScore
  session_id (FK)
  score_0_100
  tier                # low | medium | high | critical
  feature_attribution: JSON   # SHAP values, for FR-18 explainability
  host_rollup_id (FK, optional)

AnomalyScore
  session_id (FK)
  anomaly_score
  is_anomalous: bool
  baseline_reference   # what host/environment baseline this was scored against

Host (rollup)
  id, ip_or_hostname
  session_count
  aggregate_risk_score
```

## 5. Rule engine schema

Declarative YAML — this directly satisfies FR-10 / NFR-5 (extensible without code changes):

```yaml
# ruleset.yaml
- id: deprecated-tls-version
  applies_to: tls_version_negotiated
  condition: "value in ['SSLv2', 'SSLv3', 'TLS1.0', 'TLS1.1']"
  severity: high
  message: "Deprecated TLS version negotiated: {value}"
  recommendation: "Disable {value} on the server; require TLS 1.2 minimum, prefer TLS 1.3."

- id: weak-cipher
  applies_to: cipher_suite_negotiated
  condition: "value in WEAK_CIPHER_LIST"   # RC4, DES, 3DES, NULL, export-grade
  severity: high
  message: "Weak cipher suite negotiated: {value}"
  recommendation: "Restrict server cipher list to AEAD ciphers (AES-GCM, ChaCha20-Poly1305)."

- id: no-forward-secrecy
  applies_to: key_exchange_type
  condition: "value == 'rsa'"
  severity: medium
  message: "RSA key exchange used — no forward secrecy"
  recommendation: "Configure server to prefer ECDHE/DHE key exchange."

- id: weak-cert-key
  applies_to: certificate.key_length_bits
  condition: "certificate.public_key_algorithm == 'RSA' and value < 2048"
  severity: high
  message: "Certificate RSA key length {value} bits is below 2048"
  recommendation: "Reissue certificate with an RSA key >= 2048 bits, or switch to ECDSA."

- id: weak-cert-signature
  applies_to: certificate.signature_algorithm
  condition: "value in ['md5', 'sha1']"
  severity: high
  message: "Certificate signed with weak algorithm: {value}"
  recommendation: "Reissue certificate signed with SHA-256 or stronger."

- id: cert-expired
  applies_to: certificate.not_after
  condition: "value < now"
  severity: critical
  message: "Certificate expired on {value}"
  recommendation: "Renew certificate immediately."

- id: cert-expiring-soon
  applies_to: certificate.not_after
  condition: "0 <= (value - now).days <= 30"
  severity: low
  message: "Certificate expires within 30 days ({value})"
  recommendation: "Schedule certificate renewal."

- id: starttls-stripped
  applies_to: session.starttls_completed
  condition: "session.tls_mode == 'starttls' and value == false and session.starttls_advertised == true"
  severity: critical
  message: "STARTTLS was advertised but never completed — possible downgrade/stripping attack"
  recommendation: "Investigate for an on-path attacker; consider MTA-STS/DANE enforcement."
```

The rule engine (`rules/engine.py`) loads this file, evaluates each rule's `condition` against the relevant `Session`/`TLSHandshake`/`Certificate` object, and emits `Finding` rows for every match. Keep the condition language intentionally simple (a small safe-eval subset or a tiny custom DSL) — do not use raw `eval()` on untrusted input.

## 6. AI/ML layer detail

### 6.1 Feature vector (per session — input to both models in §6.2/6.3)

```
tls_version_ordinal, cipher_strength_score, forward_secrecy (0/1),
cert_key_length, cert_sig_algo_weak (0/1), days_to_cert_expiry,
cert_chain_length, cert_self_signed (0/1), ja4_hash (categorical),
extension_count, starttls_expected_but_absent (0/1),
rule_finding_count, rule_finding_max_severity_ordinal
```

### 6.2 Risk scoring model (FR-12, FR-18)

Two-layer approach:
1. **Base score**: weighted sum of rule findings (each rule in §5 carries an implicit severity weight — info=0, low=2, medium=5, high=8, critical=10 — sum and normalize to 0–100). This alone is fully explainable and works with zero training data — **build and ship this first**.
2. **Calibration layer** (only after base score works end-to-end): train `xgboost`/`lightgbm` on the feature vector to predict analyst-assigned risk tier using the self-generated labeled PCAPs (PRD §9 / TAD §9). Blend or replace the base score with the model's output, and always compute SHAP values (`shap.TreeExplainer`) so FR-18 (explainability) holds for every score. If training data is too thin to trust the model (see PRD Key Risks), fall back to the rule-weighted base score and say so in the UI rather than emitting an overconfident ML number.

### 6.3 Anomaly detection (FR-13)

- Default: `sklearn.ensemble.IsolationForest` on the numeric feature vector — fast, no labels needed.
- Baseline **per host** where enough sessions exist for that host (e.g. ≥ 20 prior sessions); fall back to a global baseline otherwise. Per-host baselining is what makes this catch downgrade attacks specifically (a host's own TLS1.3/ECDHE norm suddenly dropping to TLS1.0 is a much stronger signal than a global rule).
- Optional stretch: a small autoencoder (`torch` or `keras`, feedforward, 2-3 hidden layers) using reconstruction error as the anomaly score, if time allows and a "deep learning" component is desired for the ML story.

### 6.4 Mitigation recommendation generation (FR-15)

- Primary path: `recommendation` field already present per rule in the YAML ruleset (§5) — deterministic, always available, zero extra infra.
- Optional enrichment: pass the structured `Finding` list for a session to an LLM (e.g. via the Claude API) to synthesize a natural-language executive summary across all findings for that session/host. The LLM only **narrates** findings the rule engine already produced with certainty — it must never be the thing deciding whether a weakness exists.

## 7. API contract (FastAPI)

```
POST   /api/analyze                 multipart file upload (.pcap) -> {job_id}
GET    /api/analyze/{job_id}/status -> {status: queued|running|done|failed}
GET    /api/hosts                   -> [{host_id, ip, aggregate_risk_score, session_count}]
GET    /api/hosts/{host_id}         -> host detail + session list
GET    /api/sessions/{session_id}   -> full session detail: handshake, certs, findings, risk_score, anomaly_score
GET    /api/sessions/{session_id}/explain -> SHAP feature attribution for that session's risk score
GET    /api/reports/{job_id}.json
GET    /api/reports/{job_id}.pdf
GET    /api/reports/{job_id}.html
```

Analysis runs as a background task (FastAPI `BackgroundTasks` is sufficient for hackathon scale; a task queue like `celery`/`rq` only if PCAPs are large enough to need it — don't add infra you don't need yet).

## 8. Local dev / run instructions

```bash
# backend
cd securemailscope
python -m venv .venv && source .venv/bin/activate
pip install -e .
uvicorn securemailscope.api.main:app --reload

# dashboard (if Streamlit)
streamlit run dashboard/app.py

# tests
pytest tests/
```

No cloud dependency required for the core pipeline (NFR-6). Optional LLM narrative enrichment (§6.4) needs an API key supplied via environment variable, and must degrade gracefully (skip narrative section) if absent.

## 9. Test data strategy

Cannot legally capture real mail traffic for this project — generate labeled PCAPs instead:

1. Docker Compose stack with Postfix/Dovecot (or `openssl s_server` stand-ins) configured across a deliberate spectrum: TLS1.3-only/strong ciphers (good), TLS1.0+RC4 (bad), expired self-signed cert (bad), STARTTLS with a simulated stripping proxy (bad), implicit TLS on 465 (good), etc.
2. Capture with `tcpdump`/`dumpcap` while a test client (`swaks` for SMTP, `openssl s_client`, or a real client) connects to each config — this produces clean, ground-truth-labeled PCAPs, checked into `tests/fixtures/pcaps/` with a `labels.json` alongside describing the expected findings per PCAP.
3. Supplement with public sample captures (Wireshark's sample capture repository has SMTP/IMAP/POP3 examples) for realism/diversity, but treat these as unlabeled/exploratory, not part of the automated pass/fail test suite.

Every rule in §5 needs at least one PCAP in the fixture set that should trigger it, and at least one that should not (to catch false positives — see PRD NFR-2).

## 10. Known limitations to surface in the product, not hide

- TLS 1.3 encrypts more of the handshake (encrypted extensions, encrypted certificate message) than TLS 1.2 — full certificate extraction from a passively captured TLS 1.3 session is limited without a decryption key. Mark these sessions `visibility_limited: true` (see §4) rather than mis-scoring them.
- Encrypted Client Hello (ECH), where deployed, hides the SNI and much of the ClientHello — same handling as above.
- JA3 is brittle against modern extension-order randomization; JA4 is the primary fingerprint, JA3 kept only for compatibility with older threat-intel feeds.
