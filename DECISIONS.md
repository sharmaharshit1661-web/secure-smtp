# Implementation Decisions — Secure SMTP

Key architecture and implementation decisions made for the Secure SMTP platform:

| # | Decision | Rationale |
|---|---|---|
| 1 | **Streamlit + Plotly** for SOC console | Rapid, responsive, dark-mode glassmorphic dashboard with live data binding and drill-down interactions. |
| 2 | **MongoDB Document Model** (PyMongo) | Direct alignment with architecture diagram; allows natural document hierarchy for sessions with embedded TLS handshakes, certificate chains, rule findings, and SHAP vectors. |
| 3 | **Deterministic Synthetic PCAPs** | Scapy-generated PCAPs ensure 100% reproducible cryptographic test vectors covering STARTTLS stripping, weak ciphers, and expired certs. |
| 4 | **Native JA3 / JA3S & JA4 / JA4S Fingerprinting** | Computes MD5 and SHA-256 client/server cryptographic hashes directly from raw handshake records. |
| 5 | **Safe Condition DSL** for Rule Engine | Safe AST evaluation against declarative YAML rulebook without raw `eval()` vulnerabilities. |
| 6 | **Explainable AI (SHAP + Isolation Forest)** | Transparent percentage attributions for every risk score (0–100) and statistical anomaly detection against baseline fleet behaviors. |
| 7 | **Comprehensive Compliance Mapping** | Mapped rulebook to NIST SP 800-52r2, PCI-DSS v4.0, and RFC 8996 standards. |
| 8 | **Worst-Session Weighting for Host Rollup** | Surfaces genuine high-risk infrastructure threats without being diluted by high volumes of benign sessions. |
| 9 | **Multi-Format Executive Reports** | Automatic generation of boardroom-ready PDF, HTML, and JSON audit dossiers. |
