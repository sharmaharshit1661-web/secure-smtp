"""
Unit tests for the regulatory compliance framework mapping engine
(NIST SP 800-52 Rev. 2, PCI-DSS v4.0 Req 4.1, MTA-STS / DANE).
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from secure_smtp.api.auth import DEFAULT_DEV_API_KEY
from secure_smtp.api.main import app
from secure_smtp.compliance.frameworks import (
    ComplianceEvaluator,
    evaluate_fleet_compliance,
    evaluate_session_compliance,
)


def test_clean_tls13_session_compliance():
    """Verify clean TLS 1.3 session passes all regulatory standards."""
    clean_session = {
        "id": 1,
        "protocol": "SMTP",
        "has_tls": True,
        "handshake": {
            "tls_version_negotiated": "TLS 1.3",
            "forward_secrecy": True,
            "cipher_suite_negotiated": "TLS_AES_256_GCM_SHA384",
        },
        "certificates": [{
            "subject": "CN=mail.example.com",
            "key_length_bits": 2048,
        }],
        "findings": [],
    }

    report = ComplianceEvaluator.evaluate_session(clean_session)
    assert report.overall_status == "COMPLIANT"
    assert report.overall_score == 100.0
    assert report.standards["NIST SP 800-52 Rev. 2"].passed is True
    assert report.standards["PCI-DSS v4.0 (Req 4.1)"].passed is True
    assert report.standards["MTA-STS / DANE"].passed is True
    assert len(report.summary_findings) == 0


def test_deprecated_tls10_rc4_compliance_failure():
    """Verify deprecated TLS 1.0 session with RC4 fails NIST and PCI-DSS."""
    weak_session = {
        "id": 2,
        "protocol": "SMTP",
        "has_tls": True,
        "handshake": {
            "tls_version_negotiated": "TLS 1.0",
            "forward_secrecy": False,
            "cipher_suite_negotiated": "TLS_RSA_WITH_RC4_128_SHA",
        },
        "certificates": [{
            "subject": "CN=legacy.example.com",
            "key_length_bits": 1024,
        }],
        "findings": [
            {"rule_id": "SEC-001", "severity": "CRITICAL", "title": "Deprecated TLS 1.0"},
            {"rule_id": "SEC-002", "severity": "CRITICAL", "title": "Insecure Cipher RC4"},
            {"rule_id": "SEC-003", "severity": "HIGH", "title": "No Forward Secrecy"},
            {"rule_id": "SEC-005", "severity": "HIGH", "title": "Weak RSA Key 1024-bit"},
        ],
    }

    report = ComplianceEvaluator.evaluate_session(weak_session)
    assert report.overall_status == "NON_COMPLIANT"
    assert report.standards["NIST SP 800-52 Rev. 2"].passed is False
    assert report.standards["PCI-DSS v4.0 (Req 4.1)"].passed is False
    assert len(report.summary_findings) > 0


def test_plaintext_stripped_session_compliance():
    """Verify plaintext STARTTLS-stripped session fails all standards."""
    stripped_session = {
        "id": 3,
        "protocol": "SMTP",
        "has_tls": False,
        "handshake": None,
        "certificates": [],
        "findings": [
            {"rule_id": "SEC-008", "severity": "CRITICAL", "title": "STARTTLS Stripped"},
        ],
    }

    report = ComplianceEvaluator.evaluate_session(stripped_session)
    assert report.overall_status == "NON_COMPLIANT"
    assert report.overall_score == 0.0
    assert report.standards["MTA-STS / DANE"].passed is False


def test_evaluate_fleet_compliance_aggregation():
    """Verify aggregation across mixed sessions."""
    sessions = [
        {
            "id": 1,
            "protocol": "SMTP",
            "has_tls": True,
            "handshake": {"tls_version_negotiated": "TLS 1.3", "forward_secrecy": True},
            "certificates": [{"key_length_bits": 2048}],
            "findings": [],
        },
        {
            "id": 2,
            "protocol": "SMTP",
            "has_tls": False,
            "handshake": None,
            "certificates": [],
            "findings": [{"rule_id": "SEC-009", "severity": "CRITICAL"}],
        },
    ]

    fleet = evaluate_fleet_compliance(sessions)
    assert fleet["total_sessions_audited"] == 2
    assert "NIST SP 800-52 Rev. 2" in fleet["framework_scores"]
    assert "PCI-DSS v4.0 (Req 4.1)" in fleet["framework_scores"]
    assert "top_violations" in fleet


def test_compliance_api_endpoint():
    """Verify GET /api/compliance/summary requires auth and returns report."""
    client = TestClient(app)

    # 401 without auth
    unauth_res = client.get("/api/compliance/summary")
    assert unauth_res.status_code == 401

    # 200 with auth
    auth_res = client.get(
        "/api/compliance/summary",
        headers={"X-API-Key": DEFAULT_DEV_API_KEY},
    )
    assert auth_res.status_code == 200
    data = auth_res.json()
    assert "overall_status" in data
    assert "framework_scores" in data
