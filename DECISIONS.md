# Implementation Decisions — SecureMailScope

Decisions made during implementation that weren't fully specified in the PRD/TAD.

| # | Decision | Rationale |
|---|---|---|
| 1 | **Streamlit** for dashboard (not React) | Fastest path to working demo; TAD §2 allows either; can upgrade to React later for polish. |
| 2 | **Inline HTML template** for reports (not file-based Jinja2) | Avoids template file path issues during packaging and deployment. Single-file report generation. |
| 3 | **Synthetic PCAPs** for initial dev (not Docker-based) | Docker PCAP generation requires infrastructure; synthetic scapy PCAPs give deterministic control for unit tests. |
| 4 | **JA3/JA3S pure Python**, JA4/JA4S best-effort | No mature pure-Python JA4 library exists; implemented per published spec. JA3 is well-documented. |
| 5 | **Safe condition DSL** instead of raw eval | Rule engine uses pattern matching and restricted evaluation — no `eval()` on untrusted YAML conditions. |
| 6 | **Rule-weighted base score** ships first | TAD §6.2 says "build and ship this first". ML calibration layer is opt-in, falls back gracefully. |
| 7 | **Added `no-tls` and `self-signed-cert` rules** | Beyond TAD §5 minimum but obvious security checks that users would expect. |
| 8 | **Worst-session weighting** for host rollup | Simple average would hide critical findings. Weighted toward worst sessions surfaces risk better. |
| 9 | **SQLite with SQLModel** | Zero setup as specified; schema is simple enough that ORM features are helpful without being heavy. |
| 10 | **LLM enrichment scaffolded but not active** | TAD §6.4 marks this optional; implemented graceful degradation (skip if no API key). |
