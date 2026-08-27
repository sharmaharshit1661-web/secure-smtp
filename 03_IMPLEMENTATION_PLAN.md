# Implementation Plan — Secure SMTP

**Read `01_PRD.md` and `02_TAD.md` first — this doc assumes both.**
**Instructions for the build agent:** work through phases in order. Do not start a phase's code until the previous phase's acceptance criteria are met — the AI layer (Phase 3) is only trustworthy if Phases 1–2 are correct. Check off each item as completed. If a decision point comes up that isn't covered by the PRD/TAD, make the most reasonable choice, note it in a `DECISIONS.md` file with a one-line rationale, and continue — don't stop to ask unless it's a genuine ambiguity that changes scope.

---

## Phase 0 — Project scaffolding

- [ ] Create the repository layout exactly as specified in TAD §3
- [ ] Set up `pyproject.toml` with dependencies from TAD §2
- [ ] Set up `pytest` with an empty `tests/unit/` and `tests/fixtures/pcaps/`
- [ ] Create `scripts/generate_test_pcaps.sh` scaffold (implementation comes in Phase 1)

**Acceptance:** `pip install -e .` succeeds; `pytest` runs (even with zero tests) without error.

---

## Phase 1 — Forensic core (PCAP → protocol → TLS → cert extraction)

This is the foundation everything else depends on. Do not proceed to Phase 2 until this phase's acceptance criteria pass.

- [ ] `ingest/pcap_reader.py`: load `.pcap`/`.pcapng`, filter to TCP streams on relevant ports **and** by banner-sniffing (FR-2 — don't hardcode ports only)
- [ ] `ingest/tcp_stream.py`: reassemble each TCP stream in order, handling retransmissions/out-of-order segments (FR-5)
- [ ] `ingest/protocol_id.py`: detect SMTP/IMAP/POP3 banners, detect STARTTLS/STLS command + affirmative reply, mark the exact byte offset where TLS begins (FR-3); detect advertised-but-incomplete STARTTLS (FR-4)
- [ ] `tls/handshake_parser.py`: parse ClientHello/ServerHello from that offset — version(s), cipher suite, extensions, key exchange type (FR-6)
- [ ] `tls/fingerprint.py`: compute JA3/JA3S and JA4/JA4S (FR-7)
- [ ] `tls/cert_parser.py`: extract full certificate chain; validate expiry, key algorithm/length, signature algorithm, chain completeness (FR-8, FR-9)
- [ ] Populate `db/models.py` entities from TAD §4 and persist extracted data
- [ ] Implement `scripts/generate_test_pcaps.sh`: Docker Compose mail servers across the good/bad TLS-config spectrum from TAD §9, captured with tcpdump into `tests/fixtures/pcaps/`, with a hand-written `labels.json` describing expected extracted facts per PCAP
- [ ] Unit tests in `tests/unit/` asserting extracted facts match `labels.json` exactly for every fixture PCAP

**Acceptance:** 100% match between extracted facts and `labels.json` across all fixture PCAPs. No silent failures — any session the parser can't fully handle (e.g. TLS 1.3 visibility limits, TAD §10) must set `visibility_limited: true` rather than emitting wrong data.

---

## Phase 2 — Rule engine

- [ ] `rules/ruleset.yaml`: encode the full rule set from TAD §5 (extend as needed, but every rule in TAD §5 must be present at minimum)
- [ ] `rules/engine.py`: load the YAML, evaluate each rule against `Session`/`TLSHandshake`/`Certificate`, emit `Finding` rows — use a restricted condition-evaluation approach, **not** raw `eval()` on untrusted input
- [ ] For every rule, add at least one fixture PCAP that should trigger it and one that should not (extend Phase 1's fixture set)
- [ ] Unit tests: every rule fires exactly on its intended fixtures and stays silent on the "good config" fixtures (false-positive check — PRD NFR-2)

**Acceptance:** Zero false positives on known-good fixture PCAPs; 100% detection on known-bad fixture PCAPs, across every rule in the ruleset.

---

## Phase 3 — AI/ML layer

Build in this exact order — each step should work end-to-end before starting the next:

- [ ] `ai/features.py`: build the feature vector (TAD §6.1) from Phase 1+2 output for every session
- [ ] `ai/risk_model.py` — **step A**: implement the rule-weighted base score (TAD §6.2 point 1) first. This has no ML dependency and must work standalone.
- [ ] `ai/anomaly_model.py`: Isolation Forest anomaly detector (TAD §6.3), with per-host baselining where ≥20 prior sessions exist for that host, global baseline otherwise
- [ ] `ai/risk_model.py` — **step B**: train the XGBoost/LightGBM calibration layer on the labeled fixture set (TAD §6.2 point 2); if the fixture set is too small to trust (document the threshold you used and why), keep the base score as the shipped default and log the trained model as experimental
- [ ] `ai/explain.py`: wire up SHAP (`shap.TreeExplainer`) so every risk score returned by the API includes feature attribution (FR-18)
- [ ] Add `recommendation` text to every `Finding` (already present in ruleset.yaml — wire it through to the API response) (FR-15)
- [ ] Host/fleet-level score rollup (FR-12)
- [ ] (Optional, only if time allows) LLM narrative summary enrichment per TAD §6.4 — must degrade gracefully with no API key set

**Acceptance:** Every session has a risk score, a tier, and a non-empty feature attribution. The anomaly detector flags the intentionally-injected downgrade/anomaly fixture PCAP from Phase 1. Disabling the ML calibration layer (env flag) still produces a fully functional, explainable score via the base path.

---

## Phase 4 — Reporting & dashboard

- [ ] `api/main.py`: implement the full FastAPI contract from TAD §7
- [ ] `reporting/json_export.py`, `pdf_export.py` (weasyprint + jinja2 templates), `html_export.py`
- [ ] Dashboard (Streamlit or React, per TAD §2 stack choice): fleet overview → host drill-down → session/finding detail, with risk score + SHAP explanation visible at the session level (FR-17)
- [ ] Wire file upload → background analysis job → dashboard polling/refresh flow end-to-end

**Acceptance:** Upload a fixture PCAP through the dashboard, see it processed, drill into a flagged session, see the explained risk score, and export all three report formats — with zero manual steps outside the UI.

---

## Phase 5 — Polish & demo readiness

- [ ] Prepare one composite "demo" PCAP mixing several of the good/bad fixture configs, so the end-to-end demo tells a clear story (per PRD §8 acceptance bar)
- [ ] Write a top-level `README.md`: setup instructions, architecture summary (link to `02_TAD.md`), how to run the demo
- [ ] Sanity pass on NFR-2 (false positives) and NFR-4 (performance) against the composite demo PCAP
- [ ] Record a backup demo walkthrough (screen recording) in case live tooling has issues during presentation

**Acceptance:** A fresh clone of the repo, following only `README.md`, can run the full pipeline against the demo PCAP and reach the dashboard with correct, explained findings.
