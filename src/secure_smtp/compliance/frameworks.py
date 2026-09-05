"""
Regulatory Compliance Evaluation Frameworks — Secure SMTP.

Maps cryptographic TLS telemetry, certificate validity, and protocol state to
recognized cybersecurity and regulatory standards:
- NIST SP 800-52 Rev. 2 (Guidelines for Federal TLS Implementations)
- PCI-DSS v4.0 Requirement 4.1 (Protecting Cardholder Data in Transit)
- RFC 8461 (MTA-STS) & RFC 7672 (DANE) Enforced Mail Encryption
- HIPAA Security Rule (45 CFR § 164.312(e)(1) Transmission Security)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Dict, List, Optional


@dataclass
class ComplianceCheck:
    """Individual regulatory requirement check."""
    rule_id: str
    standard: str
    requirement: str
    description: str
    status: str  # PASS, FAIL, NOT_APPLICABLE
    remediation: Optional[str] = None


@dataclass
class StandardSummary:
    """Summary of compliance against a specific regulatory framework."""
    standard_name: str
    passed: bool
    pass_count: int
    fail_count: int
    score_percentage: float
    checks: List[ComplianceCheck] = field(default_factory=list)


@dataclass
class ComplianceReport:
    """Consolidated multi-framework compliance report."""
    evaluated_at: str
    overall_status: str  # COMPLIANT, NON_COMPLIANT, WARNING
    overall_score: float
    standards: Dict[str, StandardSummary] = field(default_factory=dict)
    summary_findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ComplianceEvaluator:
    """Evaluates sessions and fleet findings against regulatory standards."""

    @staticmethod
    def evaluate_session(session_doc: Dict[str, Any]) -> ComplianceReport:
        """Evaluate a single session document against compliance frameworks."""
        handshake = session_doc.get("handshake") or {}
        certs = session_doc.get("certificates") or []
        findings = session_doc.get("findings") or []
        protocol = session_doc.get("protocol", "SMTP").upper()
        has_tls = session_doc.get("has_tls", False)

        rule_ids = {f.get("rule_id") for f in findings if isinstance(f, dict)}
        tls_version = handshake.get("tls_version_negotiated")
        forward_secrecy = handshake.get("forward_secrecy", False)

        # ── 1. NIST SP 800-52 Rev. 2 ──
        nist_checks: List[ComplianceCheck] = []

        # NIST-01: Approved TLS Version (1.2 or 1.3)
        if not has_tls:
            nist_checks.append(ComplianceCheck(
                rule_id="NIST-01",
                standard="NIST SP 800-52 Rev. 2",
                requirement="§3.1 Minimum Protocol Version",
                description="Servers must negotiate TLS 1.2 or TLS 1.3.",
                status="FAIL",
                remediation="Enable TLS on this mail service and require STARTTLS.",
            ))
        elif tls_version in ("TLS 1.2", "TLS 1.3"):
            nist_checks.append(ComplianceCheck(
                rule_id="NIST-01",
                standard="NIST SP 800-52 Rev. 2",
                requirement="§3.1 Minimum Protocol Version",
                description=f"Negotiated approved protocol version: {tls_version}.",
                status="PASS",
            ))
        else:
            nist_checks.append(ComplianceCheck(
                rule_id="NIST-01",
                standard="NIST SP 800-52 Rev. 2",
                requirement="§3.1 Minimum Protocol Version",
                description=f"Negotiated unapproved protocol version: {tls_version or 'Unknown'}.",
                status="FAIL",
                remediation="Disable SSLv3, TLS 1.0, and TLS 1.1 in mail server configuration.",
            ))

        # NIST-02: Ephemeral Key Exchange (Forward Secrecy)
        if has_tls and forward_secrecy:
            nist_checks.append(ComplianceCheck(
                rule_id="NIST-02",
                standard="NIST SP 800-52 Rev. 2",
                requirement="§3.3 Ephemeral Key Exchange",
                description="Forward secrecy is enforced with ephemeral (EC)DHE key exchange.",
                status="PASS",
            ))
        else:
            nist_checks.append(ComplianceCheck(
                rule_id="NIST-02",
                standard="NIST SP 800-52 Rev. 2",
                requirement="§3.3 Ephemeral Key Exchange",
                description="Session does not provide Perfect Forward Secrecy.",
                status="FAIL",
                remediation="Configure ECDHE or DHE cipher suites preferentially.",
            ))

        # NIST-03: Certificate Key Length & Signature
        cert_key_weak = "SEC-005" in rule_ids
        cert_sig_weak = "SEC-006" in rule_ids
        if cert_key_weak or cert_sig_weak:
            nist_checks.append(ComplianceCheck(
                rule_id="NIST-03",
                standard="NIST SP 800-52 Rev. 2",
                requirement="§4.1 Public Key Length & Hash Security",
                description="Certificate uses deprecated key size (<2048-bit) or weak signature (SHA-1/MD5).",
                status="FAIL",
                remediation="Reissue X.509 certificate with RSA >= 2048-bit or ECC >= 256-bit and SHA-256.",
            ))
        elif certs:
            nist_checks.append(ComplianceCheck(
                rule_id="NIST-03",
                standard="NIST SP 800-52 Rev. 2",
                requirement="§4.1 Public Key Length & Hash Security",
                description="Certificate meets minimum key length and cryptographic hash standards.",
                status="PASS",
            ))
        else:
            nist_checks.append(ComplianceCheck(
                rule_id="NIST-03",
                standard="NIST SP 800-52 Rev. 2",
                requirement="§4.1 Public Key Length & Hash Security",
                description="No certificate presented in this unencrypted connection.",
                status="FAIL",
                remediation="Provision a trusted X.509 certificate.",
            ))

        # ── 2. PCI-DSS v4.0 Requirement 4.1 ──
        pci_checks: List[ComplianceCheck] = []

        # PCI-01: Prohibit Early TLS
        early_tls = "SEC-001" in rule_ids or tls_version in ("TLS 1.0", "TLS 1.1", "SSLv3")
        if early_tls or not has_tls:
            pci_checks.append(ComplianceCheck(
                rule_id="PCI-01",
                standard="PCI-DSS v4.0",
                requirement="Req 4.1.2 Prohibit Early TLS",
                description="Early TLS versions (TLS 1.0/1.1) or plaintext transmission detected.",
                status="FAIL",
                remediation="Upgrade servers to TLS 1.2 or 1.3 per PCI-DSS requirement.",
            ))
        else:
            pci_checks.append(ComplianceCheck(
                rule_id="PCI-01",
                standard="PCI-DSS v4.0",
                requirement="Req 4.1.2 Prohibit Early TLS",
                description="Connection uses TLS 1.2+ as required by PCI-DSS.",
                status="PASS",
            ))

        # PCI-02: Strong Cryptography Ciphers
        weak_ciphers = "SEC-002" in rule_ids
        if weak_ciphers:
            pci_checks.append(ComplianceCheck(
                rule_id="PCI-02",
                standard="PCI-DSS v4.0",
                requirement="Req 4.1.1 Strong Cryptography",
                description="Weak or broken cipher suite negotiated (RC4, 3DES, or EXPORT).",
                status="FAIL",
                remediation="Disable weak ciphers; enforce AES-GCM or ChaCha20-Poly1305.",
            ))
        elif has_tls:
            pci_checks.append(ComplianceCheck(
                rule_id="PCI-02",
                standard="PCI-DSS v4.0",
                requirement="Req 4.1.1 Strong Cryptography",
                description="Strong cipher suite negotiated compliant with PCI-DSS.",
                status="PASS",
            ))
        else:
            pci_checks.append(ComplianceCheck(
                rule_id="PCI-02",
                standard="PCI-DSS v4.0",
                requirement="Req 4.1.1 Strong Cryptography",
                description="No cryptography applied to traffic.",
                status="FAIL",
                remediation="Require encrypted sessions for mail transport.",
            ))

        # ── 3. RFC 8461 (MTA-STS) & RFC 7672 (DANE) ──
        sts_checks: List[ComplianceCheck] = []

        stripped_or_plaintext = "SEC-008" in rule_ids or "SEC-009" in rule_ids or not has_tls
        if stripped_or_plaintext:
            sts_checks.append(ComplianceCheck(
                rule_id="STS-01",
                standard="MTA-STS / DANE",
                requirement="RFC 8461 Enforced Encryption",
                description="Mail transport downgraded to plaintext (STARTTLS stripped or omitted).",
                status="FAIL",
                remediation="Publish an MTA-STS policy in 'enforce' mode to block downgrade attacks.",
            ))
        else:
            sts_checks.append(ComplianceCheck(
                rule_id="STS-01",
                standard="MTA-STS / DANE",
                requirement="RFC 8461 Enforced Encryption",
                description="TLS transport successfully negotiated without opportunistic downgrade.",
                status="PASS",
            ))

        expired_or_self_signed = "SEC-004" in rule_ids or "SEC-007" in rule_ids
        if expired_or_self_signed:
            sts_checks.append(ComplianceCheck(
                rule_id="STS-02",
                standard="MTA-STS / DANE",
                requirement="RFC 8461 Valid Certificate",
                description="Certificate failed validation (self-signed or expired).",
                status="FAIL",
                remediation="Install a valid certificate issued by a public trusted Certificate Authority.",
            ))
        elif certs:
            sts_checks.append(ComplianceCheck(
                rule_id="STS-02",
                standard="MTA-STS / DANE",
                requirement="RFC 8461 Valid Certificate",
                description="Certificate is valid and unexpired.",
                status="PASS",
            ))
        else:
            sts_checks.append(ComplianceCheck(
                rule_id="STS-02",
                standard="MTA-STS / DANE",
                requirement="RFC 8461 Valid Certificate",
                description="No certificate present.",
                status="FAIL",
                remediation="Deploy a trusted TLS certificate.",
            ))

        # ── Summarize Frameworks ──
        frameworks = {
            "NIST SP 800-52 Rev. 2": nist_checks,
            "PCI-DSS v4.0 (Req 4.1)": pci_checks,
            "MTA-STS / DANE": sts_checks,
        }

        standards_summary: Dict[str, StandardSummary] = {}
        total_checks = 0
        total_passes = 0
        summary_findings: List[str] = []

        for name, checks in frameworks.items():
            passes = sum(1 for c in checks if c.status == "PASS")
            fails = sum(1 for c in checks if c.status == "FAIL")
            pct = round((passes / len(checks) * 100.0) if checks else 0.0, 1)

            for c in checks:
                if c.status == "FAIL":
                    summary_findings.append(f"[{name}] {c.requirement}: {c.description}")

            standards_summary[name] = StandardSummary(
                standard_name=name,
                passed=(fails == 0),
                pass_count=passes,
                fail_count=fails,
                score_percentage=pct,
                checks=checks,
            )
            total_checks += len(checks)
            total_passes += passes

        overall_score = round((total_passes / total_checks * 100.0) if total_checks else 0.0, 1)
        overall_status = "COMPLIANT" if overall_score == 100.0 else "WARNING" if overall_score >= 70.0 else "NON_COMPLIANT"

        return ComplianceReport(
            evaluated_at=datetime.now(UTC).isoformat(),
            overall_status=overall_status,
            overall_score=overall_score,
            standards=standards_summary,
            summary_findings=summary_findings,
        )


def evaluate_session_compliance(session_doc: Dict[str, Any]) -> Dict[str, Any]:
    """Helper returning JSON-serializable compliance evaluation dictionary."""
    report = ComplianceEvaluator.evaluate_session(session_doc)
    return report.to_dict()


def evaluate_fleet_compliance(sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate compliance statistics across all active sessions."""
    if not sessions:
        return {
            "evaluated_at": datetime.now(UTC).isoformat(),
            "overall_status": "NOT_ASSESSED",
            "overall_score": 0.0,
            "total_sessions_audited": 0,
            "framework_scores": {},
            "top_violations": [],
        }

    reports = [ComplianceEvaluator.evaluate_session(s) for s in sessions]
    total_score = sum(r.overall_score for r in reports) / len(reports)

    # Average score per standard
    standards_totals: Dict[str, List[float]] = {}
    violations: List[str] = []

    for r in reports:
        violations.extend(r.summary_findings)
        for std_name, std_data in r.standards.items():
            if std_name not in standards_totals:
                standards_totals[std_name] = []
            standards_totals[std_name].append(std_data.score_percentage)

    framework_scores = {
        name: round(sum(scores) / len(scores), 1)
        for name, scores in standards_totals.items()
    }

    # Count top violation frequencies
    from collections import Counter
    top_violations = [
        {"violation": item, "frequency": count}
        for item, count in Counter(violations).most_common(5)
    ]

    return {
        "evaluated_at": datetime.now(UTC).isoformat(),
        "overall_status": "COMPLIANT" if total_score >= 95.0 else "WARNING" if total_score >= 70.0 else "NON_COMPLIANT",
        "overall_score": round(total_score, 1),
        "total_sessions_audited": len(sessions),
        "framework_scores": framework_scores,
        "top_violations": top_violations,
    }
