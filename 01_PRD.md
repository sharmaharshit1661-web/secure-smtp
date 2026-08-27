# Product Requirements Document (PRD)
## SecureMailScope — AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications

**Doc status:** Draft for build handoff
**Owner:** Harshit Sharma
**Companion docs:** `02_TAD.md` (technical architecture), `03_IMPLEMENTATION_PLAN.md` (phased build checklist)

---

## 1. Summary

SecureMailScope is a passive, AI-assisted network forensic tool that ingests PCAP files containing SMTP, IMAP, and POP3 traffic and automatically assesses the cryptographic security posture of the email infrastructure involved — without ever decrypting message content. It reconstructs sessions, parses TLS handshakes and certificates, evaluates them against a crypto weakness rulebook, layers AI-based risk scoring and anomaly detection on top, and outputs prioritized findings through a dashboard and exportable reports (JSON/PDF/HTML).

## 2. Problem statement

Email infrastructure (SMTP/IMAP/POP3 + TLS/STARTTLS) is widely deployed but frequently misconfigured — deprecated TLS versions, weak ciphers, expired or self-signed certificates, missing forward secrecy, and stripped STARTTLS upgrades all go undetected by standard packet-decoding tools, which show *what* traffic occurred but don't assess *how secure* it was. Security teams need a tool that turns raw packet captures into a prioritized, explainable security posture assessment.

## 3. Goals

- G1: Passively reconstruct SMTP/IMAP/POP3 sessions from a PCAP, including STARTTLS upgrade detection, with no live server access or credentials required.
- G2: Extract and validate every cryptographically relevant fact from the TLS handshake and certificate chain.
- G3: Deterministically detect known crypto weaknesses via an explainable, extensible rule engine.
- G4: Layer AI on top of the deterministic facts to produce a prioritized risk score per session/host and to flag anomalous TLS behavior that no single rule catches.
- G5: Generate mitigation recommendations and export findings as JSON, PDF, and HTML, plus an interactive dashboard.

## 4. Non-goals (explicitly out of scope)

- NG1: Decrypting or inspecting email *content* — this is a metadata/handshake posture tool only; no message body is ever read.
- NG2: Live/active scanning of mail servers — input is always a PCAP file, never a live connection.
- NG3: Blocking or intervening in traffic — this is a detection/reporting tool, not an inline security control.
- NG4: Full protocol-conformance fuzzing/pentesting — crypto posture only, not exploitation.

## 5. Target users / personas

| Persona | Need |
|---|---|
| SOC analyst | Quickly triage which mail servers in a captured environment are high-risk and why |
| Digital forensics / incident responder | Reconstruct exactly what crypto was negotiated during an incident window |
| Enterprise email administrator | Ongoing compliance check against a crypto baseline before/after config changes |

## 6. Functional requirements

Numbered and traceable to acceptance criteria in `03_IMPLEMENTATION_PLAN.md`.

| ID | Requirement |
|---|---|
| FR-1 | System shall accept a `.pcap`/`.pcapng` file as input |
| FR-2 | System shall identify SMTP, IMAP, and POP3 sessions regardless of port, by inspecting banners/commands, not just well-known ports |
| FR-3 | System shall detect STARTTLS/STLS negotiation and the exact byte offset where TLS begins |
| FR-4 | System shall flag sessions where STARTTLS was advertised but never completed (possible stripping/downgrade) |
| FR-5 | System shall reconstruct the TCP stream for each session in order, handling retransmissions/out-of-order packets |
| FR-6 | System shall parse the TLS ClientHello and ServerHello: negotiated version, cipher suite, key exchange type, extensions |
| FR-7 | System shall compute JA4/JA4S (and JA3/JA3S for backward compatibility) fingerprints per session |
| FR-8 | System shall extract the full X.509 certificate chain sent by the server |
| FR-9 | System shall validate certificate chain completeness, expiration, public key algorithm/length, and signature algorithm |
| FR-10 | System shall evaluate every session against a declarative, extensible rule set of known crypto weaknesses (see TAD §5) |
| FR-11 | System shall assess forward secrecy (ECDHE/DHE vs RSA key transport) per session |
| FR-12 | System shall compute a 0–100 AI-assisted risk score per session, and roll up to per-host and fleet-level scores |
| FR-13 | System shall run unsupervised anomaly detection to flag TLS behavior unusual for its environment/baseline, independent of rule hits |
| FR-14 | System shall produce a prioritized, ranked findings list (not just a flat list) |
| FR-15 | System shall generate a human-readable mitigation recommendation for every rule-engine finding |
| FR-16 | System shall export findings as JSON, PDF, and HTML |
| FR-17 | System shall provide an interactive dashboard: fleet overview → host drill-down → session/finding detail |
| FR-18 | System shall explain every risk score (feature attribution — e.g., SHAP) rather than emitting an opaque number |
| FR-19 | System shall clearly mark sessions it cannot fully assess (e.g., ECH-obscured, TLS 1.3 fields not visible passively) rather than silently mis-scoring them |

## 7. Non-functional requirements

- NFR-1 (Explainability): Every AI-driven score must be traceable to the underlying facts/features — no black-box-only output.
- NFR-2 (Correctness over recall): Zero tolerance for false positives on well-known-good configurations during validation; a missed edge case is preferable to crying wolf on a demo.
- NFR-3 (Passivity/safety): The tool must never send packets to or otherwise interact with the systems that produced the PCAP.
- NFR-4 (Performance): Should process a multi-thousand-session PCAP within a few minutes on a laptop-class machine for demo purposes (not a hard production SLA).
- NFR-5 (Extensibility): New crypto-weakness rules must be addable without code changes (declarative rule format).
- NFR-6 (Portability): Runnable locally via a single documented setup path (see TAD §8) — no cloud dependency required for the core pipeline.

## 8. Success criteria / acceptance bar

- Given a set of labeled test PCAPs (self-generated per TAD §7) spanning good and bad TLS configs, the rule engine achieves 100% correct detection with zero false positives on the labeled set.
- The risk scoring model ranks the known-worst-configured session at or near the top of the prioritized list.
- The anomaly detector flags at least the intentionally-injected downgrade/anomalous scenario in the test set.
- End-to-end: upload a PCAP → dashboard renders findings → export a PDF report, with no manual steps in between.

## 9. Key risks / open questions

- TLS 1.3's encrypted handshake extensions and (where deployed) Encrypted Client Hello reduce passively-visible metadata — mitigation is explicit "limited visibility" labeling (FR-19), not a functional gap to hide.
- Labeled training data for the supervised risk-scoring model is self-generated and modest in size for a hackathon timeline — the model must degrade gracefully to the rule-engine score when confidence is low (see TAD §6.2).
- Scope of "AI-assisted" should not overshadow explainability — reviewers/judges and real analysts trust an explained score far more than a bare number.
