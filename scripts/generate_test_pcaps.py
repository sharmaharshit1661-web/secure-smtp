#!/usr/bin/env python3
"""
Generate synthetic test PCAPs for Secure SMTP.

Creates deterministic test PCAPs using scapy that simulate various
email protocol sessions across good and bad TLS configurations.
Each PCAP represents a specific scenario for rule engine validation.

Decision #3 in DECISIONS.md chose synthetic scapy PCAPs over Docker-based
generation for deterministic control.
"""

from __future__ import annotations

import hashlib
import json
import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from scapy.all import IP, TCP, Raw, wrpcap

# ── Output directories ──

FIXTURES_DIR = Path(__file__).parent.parent / "tests" / "fixtures" / "pcaps"
FIXTURES_DIR.mkdir(parents=True, exist_ok=True)


# ── TLS record building helpers ──

def _build_tls_record(content_type: int, version: tuple[int, int], payload: bytes) -> bytes:
    """Build a TLS record: content_type(1) + version(2) + length(2) + payload."""
    return struct.pack("!BHH", content_type, (version[0] << 8) | version[1], len(payload)) + payload


def _build_client_hello(
    version: tuple[int, int] = (3, 3),
    cipher_suites: list[int] | None = None,
    sni: str = "mail.example.com",
    supported_versions: list[tuple[int, int]] | None = None,
) -> bytes:
    """Build a synthetic TLS ClientHello message."""
    if cipher_suites is None:
        cipher_suites = [0xC02F, 0xC030, 0xCCA8, 0x1301, 0x1302]

    # Random (32 bytes)
    random_bytes = hashlib.sha256(b"test_client_random_seed").digest()

    # Build ClientHello body
    body = b""
    body += struct.pack("!BB", version[0], version[1])
    body += random_bytes
    body += b"\x00"  # Session ID (empty)
    # Cipher suites
    body += struct.pack("!H", len(cipher_suites) * 2)
    for cs in cipher_suites:
        body += struct.pack("!H", cs)
    body += b"\x01\x00"  # Compression methods (null only)

    # Extensions
    extensions = b""

    # SNI extension (type 0)
    if sni:
        sni_bytes = sni.encode("ascii")
        sni_entry = struct.pack("!BH", 0, len(sni_bytes)) + sni_bytes
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
        extensions += struct.pack("!HH", 0, len(sni_list)) + sni_list

    # Supported versions extension (type 43) for TLS 1.3
    if supported_versions:
        sv_body = b""
        for sv in supported_versions:
            sv_body += struct.pack("!BB", sv[0], sv[1])
        sv_list = struct.pack("!B", len(sv_body)) + sv_body
        extensions += struct.pack("!HH", 43, len(sv_list)) + sv_list

    # Supported groups extension (type 10)
    groups = [0x0017, 0x0018, 0x0019]
    groups_body = struct.pack("!H", len(groups) * 2)
    for g in groups:
        groups_body += struct.pack("!H", g)
    extensions += struct.pack("!HH", 10, len(groups_body)) + groups_body

    # EC point formats (type 11)
    ecpf = b"\x01\x00"
    extensions += struct.pack("!HH", 11, len(ecpf)) + ecpf

    # Signature algorithms (type 13)
    sig_algos = [0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0603]
    sig_body = struct.pack("!H", len(sig_algos) * 2)
    for sa in sig_algos:
        sig_body += struct.pack("!H", sa)
    extensions += struct.pack("!HH", 13, len(sig_body)) + sig_body

    if extensions:
        body += struct.pack("!H", len(extensions)) + extensions

    # Handshake header (type 1 = ClientHello)
    handshake = struct.pack("!B", 1) + struct.pack("!I", len(body))[1:] + body

    record_version = (3, 1) if version == (3, 4) else version
    return _build_tls_record(0x16, record_version, handshake)


def _build_server_hello(
    version: tuple[int, int] = (3, 3),
    cipher_suite: int = 0xC02F,
    is_tls13: bool = False,
) -> bytes:
    """Build a synthetic TLS ServerHello message."""
    random_bytes = hashlib.sha256(b"test_server_random_seed").digest()

    body = b""
    sv = (3, 3) if is_tls13 else version
    body += struct.pack("!BB", sv[0], sv[1])
    body += random_bytes
    body += b"\x00"  # Session ID
    body += struct.pack("!H", cipher_suite)
    body += b"\x00"  # Compression method

    extensions = b""
    if is_tls13:
        sv_data = struct.pack("!BB", 3, 4)
        extensions += struct.pack("!HH", 43, len(sv_data)) + sv_data

    if extensions:
        body += struct.pack("!H", len(extensions)) + extensions

    handshake = struct.pack("!B", 2) + struct.pack("!I", len(body))[1:] + body

    record_version = (3, 3) if is_tls13 else version
    return _build_tls_record(0x16, record_version, handshake)


def _build_certificate_message(cert_der: bytes) -> bytes:
    """Build a TLS Certificate message containing one certificate."""
    cert_entry = struct.pack("!I", len(cert_der))[1:] + cert_der
    cert_list = struct.pack("!I", len(cert_entry))[1:] + cert_entry
    handshake = struct.pack("!B", 11) + struct.pack("!I", len(cert_list))[1:] + cert_list
    return _build_tls_record(0x16, (3, 3), handshake)


def _generate_self_signed_cert(
    cn: str = "mail.example.com",
    key_size: int = 2048,
    sig_hash=None,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    use_ec: bool = False,
) -> bytes:
    """Generate a self-signed X.509 certificate and return DER bytes."""
    if sig_hash is None:
        sig_hash = hashes.SHA256()

    if use_ec:
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    if not_before is None:
        not_before = datetime.now(UTC) - timedelta(days=365)
    if not_after is None:
        not_after = datetime.now(UTC) + timedelta(days=365)

    not_before_naive = not_before.replace(tzinfo=None) if not_before.tzinfo else not_before
    not_after_naive = not_after.replace(tzinfo=None) if not_after.tzinfo else not_after

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
    ])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before_naive)
        .not_valid_after(not_after_naive)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]),
            critical=False,
        )
    )

    cert = builder.sign(private_key, sig_hash)
    return cert.public_bytes(serialization.Encoding.DER)


def _generate_sha1_cert(cn: str = "mail.example.com", key_size: int = 2048) -> bytes:
    """Generate a cert that reports sha1WithRSAEncryption as its signature algorithm.

    Modern cryptography library rejects SHA-1 signing, so we generate a SHA-256
    cert and patch the signature algorithm OIDs in the DER output to read as
    sha1WithRSAEncryption (OID 1.2.840.113549.1.1.5). Our cert_parser only reads
    the OID name, so this is sufficient for rule engine testing.
    """
    # sha256WithRSAEncryption OID bytes: 2a 86 48 86 f7 0d 01 01 0b
    sha256_oid = bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b])
    # sha1WithRSAEncryption OID bytes:   2a 86 48 86 f7 0d 01 01 05
    sha1_oid   = bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05])

    der = _generate_self_signed_cert(cn=cn, key_size=key_size, sig_hash=hashes.SHA256())
    # Replace all occurrences of sha256 OID with sha1 OID
    patched = der.replace(sha256_oid, sha1_oid)
    return patched


# ── Packet building helpers ──

SRC_IP = "10.0.0.100"
BASE_TS = 1700000000.0


def _make_pkt(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b"", ts_offset=0.0):
    """Create a single TCP/IP packet."""
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    if payload:
        pkt = pkt / Raw(load=payload)
    pkt.time = BASE_TS + ts_offset
    return pkt


def _build_tcp_handshake(client_ip, server_ip, client_port, server_port, ts_base=0.0):
    """Build a TCP 3-way handshake."""
    syn = _make_pkt(client_ip, server_ip, client_port, server_port, 1000, 0, "S", ts_offset=ts_base)
    syn_ack = _make_pkt(server_ip, client_ip, server_port, client_port, 2000, 1001, "SA", ts_offset=ts_base + 0.01)
    ack = _make_pkt(client_ip, server_ip, client_port, server_port, 1001, 2001, "A", ts_offset=ts_base + 0.02)
    return [syn, syn_ack, ack], 1001, 2001


# ── Scenario generators ──

def generate_smtp_tls12_good():
    """Scenario 1: Good SMTP with TLS 1.2 + ECDHE + valid cert (STARTTLS)."""
    server_ip = "192.168.1.10"
    client_port, server_port = 54321, 25
    pkts, c_seq, s_seq = _build_tcp_handshake(SRC_IP, server_ip, client_port, server_port)

    banner = b"220 mail.secure.example.com ESMTP Postfix\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", banner, 0.03))
    s_seq += len(banner)

    ehlo = b"EHLO client.example.com\r\n"
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", ehlo, 0.04))
    c_seq += len(ehlo)

    ehlo_resp = b"250-mail.secure.example.com\r\n250-SIZE 52428800\r\n250-STARTTLS\r\n250 OK\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", ehlo_resp, 0.05))
    s_seq += len(ehlo_resp)

    starttls_cmd = b"STARTTLS\r\n"
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", starttls_cmd, 0.06))
    c_seq += len(starttls_cmd)

    ready = b"220 2.0.0 Ready to start TLS\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", ready, 0.07))
    s_seq += len(ready)

    client_hello = _build_client_hello(version=(3, 3), cipher_suites=[0xC02F, 0xC030, 0xCCA8, 0xC02B, 0xC02C], sni="mail.secure.example.com")
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", client_hello, 0.08))
    c_seq += len(client_hello)

    server_hello = _build_server_hello(version=(3, 3), cipher_suite=0xC02F)
    cert_der = _generate_self_signed_cert(cn="mail.secure.example.com", key_size=4096, not_after=datetime.now(UTC) + timedelta(days=365))
    cert_msg = _build_certificate_message(cert_der)
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", server_hello + cert_msg, 0.09))

    return pkts, server_ip


def generate_smtp_tls13_good():
    """Scenario 2: Good SMTP with TLS 1.3 + strong ciphers (implicit TLS on 465)."""
    server_ip = "192.168.1.11"
    client_port, server_port = 54322, 465
    pkts, c_seq, s_seq = _build_tcp_handshake(SRC_IP, server_ip, client_port, server_port)

    client_hello = _build_client_hello(version=(3, 3), cipher_suites=[0x1301, 0x1302, 0x1303], sni="mail.modern.example.com", supported_versions=[(3, 4), (3, 3)])
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", client_hello, 0.03))
    c_seq += len(client_hello)

    server_hello = _build_server_hello(version=(3, 3), cipher_suite=0x1301, is_tls13=True)
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", server_hello, 0.04))

    return pkts, server_ip


def generate_smtp_tls10_rc4():
    """Scenario 3: Bad SMTP with TLS 1.0 + RC4 cipher."""
    server_ip = "192.168.1.20"
    client_port, server_port = 54323, 25
    pkts, c_seq, s_seq = _build_tcp_handshake(SRC_IP, server_ip, client_port, server_port)

    banner = b"220 oldmail.legacy.example.com ESMTP\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", banner, 0.03))
    s_seq += len(banner)

    ehlo = b"EHLO client.example.com\r\n"
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", ehlo, 0.04))
    c_seq += len(ehlo)

    ehlo_resp = b"250-oldmail.legacy.example.com\r\n250-STARTTLS\r\n250 OK\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", ehlo_resp, 0.05))
    s_seq += len(ehlo_resp)

    starttls_cmd = b"STARTTLS\r\n"
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", starttls_cmd, 0.06))
    c_seq += len(starttls_cmd)

    ready = b"220 Ready to start TLS\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", ready, 0.07))
    s_seq += len(ready)

    client_hello = _build_client_hello(version=(3, 1), cipher_suites=[0x0005, 0x0004, 0x000A], sni="oldmail.legacy.example.com")
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", client_hello, 0.08))
    c_seq += len(client_hello)

    server_hello = _build_server_hello(version=(3, 1), cipher_suite=0x0005)
    cert_der = _generate_self_signed_cert(cn="oldmail.legacy.example.com", key_size=2048)
    cert_msg = _build_certificate_message(cert_der)
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", server_hello + cert_msg, 0.09))

    return pkts, server_ip


def generate_smtp_expired_cert():
    """Scenario 4: SMTP with expired certificate."""
    server_ip = "192.168.1.21"
    client_port, server_port = 54324, 25
    pkts, c_seq, s_seq = _build_tcp_handshake(SRC_IP, server_ip, client_port, server_port)

    banner = b"220 expired.example.com ESMTP\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", banner, 0.03))
    s_seq += len(banner)
    ehlo = b"EHLO client.example.com\r\n"
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", ehlo, 0.04))
    c_seq += len(ehlo)
    ehlo_resp = b"250-expired.example.com\r\n250-STARTTLS\r\n250 OK\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", ehlo_resp, 0.05))
    s_seq += len(ehlo_resp)
    starttls_cmd = b"STARTTLS\r\n"
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", starttls_cmd, 0.06))
    c_seq += len(starttls_cmd)
    ready = b"220 Ready to start TLS\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", ready, 0.07))
    s_seq += len(ready)

    client_hello = _build_client_hello(version=(3, 3), cipher_suites=[0xC02F])
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", client_hello, 0.08))
    c_seq += len(client_hello)

    server_hello = _build_server_hello(version=(3, 3), cipher_suite=0xC02F)
    cert_der = _generate_self_signed_cert(cn="expired.example.com", key_size=2048, not_before=datetime.now(UTC) - timedelta(days=730), not_after=datetime.now(UTC) - timedelta(days=30))
    cert_msg = _build_certificate_message(cert_der)
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", server_hello + cert_msg, 0.09))

    return pkts, server_ip


def generate_smtp_self_signed():
    """Scenario 5: SMTP with self-signed cert + weak key (1024-bit RSA)."""
    server_ip = "192.168.1.22"
    client_port, server_port = 54325, 25
    pkts, c_seq, s_seq = _build_tcp_handshake(SRC_IP, server_ip, client_port, server_port)

    banner = b"220 selfsigned.example.com ESMTP\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", banner, 0.03))
    s_seq += len(banner)
    ehlo = b"EHLO client.example.com\r\n"
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", ehlo, 0.04))
    c_seq += len(ehlo)
    ehlo_resp = b"250-selfsigned.example.com\r\n250-STARTTLS\r\n250 OK\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", ehlo_resp, 0.05))
    s_seq += len(ehlo_resp)
    starttls_cmd = b"STARTTLS\r\n"
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", starttls_cmd, 0.06))
    c_seq += len(starttls_cmd)
    ready = b"220 Ready to start TLS\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", ready, 0.07))
    s_seq += len(ready)

    client_hello = _build_client_hello(version=(3, 3), cipher_suites=[0x002F])
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", client_hello, 0.08))
    c_seq += len(client_hello)

    server_hello = _build_server_hello(version=(3, 3), cipher_suite=0x002F)
    cert_der = _generate_self_signed_cert(cn="selfsigned.example.com", key_size=1024)
    cert_msg = _build_certificate_message(cert_der)
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", server_hello + cert_msg, 0.09))

    return pkts, server_ip


def generate_smtp_starttls_stripped():
    """Scenario 6: STARTTLS advertised but stripped."""
    server_ip = "192.168.1.30"
    client_port, server_port = 54326, 25
    pkts, c_seq, s_seq = _build_tcp_handshake(SRC_IP, server_ip, client_port, server_port)

    banner = b"220 stripped.example.com ESMTP\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", banner, 0.03))
    s_seq += len(banner)
    ehlo = b"EHLO client.example.com\r\n"
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", ehlo, 0.04))
    c_seq += len(ehlo)
    ehlo_resp = b"250-stripped.example.com\r\n250-STARTTLS\r\n250 OK\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", ehlo_resp, 0.05))
    s_seq += len(ehlo_resp)

    mail_from = b"MAIL FROM:<sender@example.com>\r\n"
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", mail_from, 0.06))
    c_seq += len(mail_from)
    ok_resp = b"250 OK\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", ok_resp, 0.07))

    return pkts, server_ip


def generate_smtp_plaintext():
    """Scenario 7: Completely plaintext SMTP."""
    server_ip = "192.168.1.31"
    client_port, server_port = 54327, 25
    pkts, c_seq, s_seq = _build_tcp_handshake(SRC_IP, server_ip, client_port, server_port)

    banner = b"220 plain.example.com ESMTP\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", banner, 0.03))
    s_seq += len(banner)
    ehlo = b"EHLO client.example.com\r\n"
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", ehlo, 0.04))
    c_seq += len(ehlo)
    ehlo_resp = b"250-plain.example.com\r\n250-SIZE 52428800\r\n250 OK\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", ehlo_resp, 0.05))
    s_seq += len(ehlo_resp)
    mail_from = b"MAIL FROM:<sender@example.com>\r\n"
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", mail_from, 0.06))
    c_seq += len(mail_from)
    ok_resp = b"250 OK\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", ok_resp, 0.07))

    return pkts, server_ip


def generate_imap_tls12_good():
    """Scenario 8: Good IMAP with TLS 1.2 (implicit TLS on 993)."""
    server_ip = "192.168.1.12"
    client_port, server_port = 54328, 993
    pkts, c_seq, s_seq = _build_tcp_handshake(SRC_IP, server_ip, client_port, server_port)

    client_hello = _build_client_hello(version=(3, 3), cipher_suites=[0xC02F, 0xC030, 0xCCA8], sni="imap.secure.example.com")
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", client_hello, 0.03))
    c_seq += len(client_hello)

    server_hello = _build_server_hello(version=(3, 3), cipher_suite=0xC02F)
    cert_der = _generate_self_signed_cert(cn="imap.secure.example.com", key_size=2048)
    cert_msg = _build_certificate_message(cert_der)
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", server_hello + cert_msg, 0.04))

    return pkts, server_ip


def generate_pop3_sha1_cert():
    """Scenario 9: POP3 with SHA-1 signed certificate."""
    server_ip = "192.168.1.23"
    client_port, server_port = 54329, 110
    pkts, c_seq, s_seq = _build_tcp_handshake(SRC_IP, server_ip, client_port, server_port)

    banner = b"+OK POP3 server ready\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", banner, 0.03))
    s_seq += len(banner)
    capa = b"CAPA\r\n"
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", capa, 0.04))
    c_seq += len(capa)
    capa_resp = b"+OK Capability list follows\r\nSTLS\r\nUSER\r\n.\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", capa_resp, 0.05))
    s_seq += len(capa_resp)
    stls = b"STLS\r\n"
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", stls, 0.06))
    c_seq += len(stls)
    stls_ok = b"+OK Begin TLS negotiation\r\n"
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", stls_ok, 0.07))
    s_seq += len(stls_ok)

    client_hello = _build_client_hello(version=(3, 3), cipher_suites=[0xC02F])
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", client_hello, 0.08))
    c_seq += len(client_hello)

    server_hello = _build_server_hello(version=(3, 3), cipher_suite=0xC02F)
    cert_der = _generate_sha1_cert(cn="pop3.legacy.example.com", key_size=2048)
    cert_msg = _build_certificate_message(cert_der)
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", server_hello + cert_msg, 0.09))

    return pkts, server_ip


def generate_smtp_no_forward_secrecy():
    """Scenario 10: SMTP with RSA key exchange (no forward secrecy)."""
    server_ip = "192.168.1.24"
    client_port, server_port = 54330, 465
    pkts, c_seq, s_seq = _build_tcp_handshake(SRC_IP, server_ip, client_port, server_port)

    client_hello = _build_client_hello(version=(3, 3), cipher_suites=[0x009C, 0x009D, 0x002F, 0x0035], sni="rsa-only.example.com")
    pkts.append(_make_pkt(SRC_IP, server_ip, client_port, server_port, c_seq, s_seq, "PA", client_hello, 0.03))
    c_seq += len(client_hello)

    server_hello = _build_server_hello(version=(3, 3), cipher_suite=0x009C)
    cert_der = _generate_self_signed_cert(cn="rsa-only.example.com", key_size=2048)
    cert_msg = _build_certificate_message(cert_der)
    pkts.append(_make_pkt(server_ip, SRC_IP, server_port, client_port, s_seq, c_seq, "PA", server_hello + cert_msg, 0.04))

    return pkts, server_ip


# ── Main ──

SCENARIOS = {
    "smtp_tls12_good": {"generator": generate_smtp_tls12_good, "label": {"protocol": "smtp", "tls_mode": "starttls", "tls_version": "TLS1.2", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "forward_secrecy": True, "key_exchange": "ecdhe", "cert_key_algo": "RSA", "cert_key_bits": 4096, "cert_expired": False, "cert_self_signed": True, "cert_sig_algo": "sha256", "starttls_advertised": True, "starttls_completed": True, "expected_rules_fired": ["self-signed-cert"], "expected_rules_silent": ["deprecated-tls-version", "weak-cipher", "no-forward-secrecy", "cert-expired", "weak-cert-key-rsa", "weak-cert-signature", "no-tls", "starttls-stripped"]}},
    "smtp_tls13_good": {"generator": generate_smtp_tls13_good, "label": {"protocol": "smtp", "tls_mode": "implicit", "tls_version": "TLS1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256", "forward_secrecy": True, "key_exchange": "ecdhe", "visibility_limited": True, "expected_rules_fired": [], "expected_rules_silent": ["deprecated-tls-version", "weak-cipher", "no-forward-secrecy", "no-tls", "starttls-stripped"]}},
    "smtp_tls10_rc4": {"generator": generate_smtp_tls10_rc4, "label": {"protocol": "smtp", "tls_mode": "starttls", "tls_version": "TLS1.0", "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA", "forward_secrecy": False, "key_exchange": "rsa", "cert_key_algo": "RSA", "cert_key_bits": 2048, "cert_expired": False, "cert_self_signed": True, "cert_sig_algo": "sha256", "starttls_advertised": True, "starttls_completed": True, "expected_rules_fired": ["deprecated-tls-version", "weak-cipher", "no-forward-secrecy", "self-signed-cert"], "expected_rules_silent": ["cert-expired", "weak-cert-key-rsa", "weak-cert-signature", "no-tls", "starttls-stripped"]}},
    "smtp_expired_cert": {"generator": generate_smtp_expired_cert, "label": {"protocol": "smtp", "tls_mode": "starttls", "tls_version": "TLS1.2", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "forward_secrecy": True, "key_exchange": "ecdhe", "cert_key_algo": "RSA", "cert_key_bits": 2048, "cert_expired": True, "cert_self_signed": True, "cert_sig_algo": "sha256", "starttls_advertised": True, "starttls_completed": True, "expected_rules_fired": ["cert-expired", "self-signed-cert"], "expected_rules_silent": ["deprecated-tls-version", "weak-cipher", "no-forward-secrecy", "weak-cert-key-rsa", "weak-cert-signature", "no-tls", "starttls-stripped"]}},
    "smtp_self_signed_weak_key": {"generator": generate_smtp_self_signed, "label": {"protocol": "smtp", "tls_mode": "starttls", "tls_version": "TLS1.2", "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA", "forward_secrecy": False, "key_exchange": "rsa", "cert_key_algo": "RSA", "cert_key_bits": 1024, "cert_expired": False, "cert_self_signed": True, "cert_sig_algo": "sha256", "starttls_advertised": True, "starttls_completed": True, "expected_rules_fired": ["no-forward-secrecy", "weak-cert-key-rsa", "self-signed-cert"], "expected_rules_silent": ["deprecated-tls-version", "weak-cipher", "cert-expired", "weak-cert-signature", "no-tls", "starttls-stripped"]}},
    "smtp_starttls_stripped": {"generator": generate_smtp_starttls_stripped, "label": {"protocol": "smtp", "tls_mode": "none", "starttls_advertised": True, "starttls_completed": False, "expected_rules_fired": ["no-tls"], "expected_rules_silent": ["deprecated-tls-version", "weak-cipher", "no-forward-secrecy", "cert-expired", "weak-cert-key-rsa", "weak-cert-signature"]}},
    "smtp_plaintext": {"generator": generate_smtp_plaintext, "label": {"protocol": "smtp", "tls_mode": "none", "starttls_advertised": False, "starttls_completed": False, "expected_rules_fired": ["no-tls"], "expected_rules_silent": ["deprecated-tls-version", "weak-cipher", "no-forward-secrecy", "cert-expired", "weak-cert-key-rsa", "weak-cert-signature", "starttls-stripped"]}},
    "imap_tls12_good": {"generator": generate_imap_tls12_good, "label": {"protocol": "imap", "tls_mode": "implicit", "tls_version": "TLS1.2", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "forward_secrecy": True, "key_exchange": "ecdhe", "cert_key_algo": "RSA", "cert_key_bits": 2048, "cert_expired": False, "cert_self_signed": True, "cert_sig_algo": "sha256", "expected_rules_fired": ["self-signed-cert"], "expected_rules_silent": ["deprecated-tls-version", "weak-cipher", "no-forward-secrecy", "cert-expired", "weak-cert-key-rsa", "weak-cert-signature", "no-tls", "starttls-stripped"]}},
    "pop3_sha1_cert": {"generator": generate_pop3_sha1_cert, "label": {"protocol": "pop3", "tls_mode": "starttls", "tls_version": "TLS1.2", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "forward_secrecy": True, "key_exchange": "ecdhe", "cert_key_algo": "RSA", "cert_key_bits": 2048, "cert_expired": False, "cert_self_signed": True, "cert_sig_algo": "sha1", "starttls_advertised": True, "starttls_completed": True, "expected_rules_fired": ["weak-cert-signature", "self-signed-cert"], "expected_rules_silent": ["deprecated-tls-version", "weak-cipher", "no-forward-secrecy", "cert-expired", "weak-cert-key-rsa", "no-tls", "starttls-stripped"]}},
    "smtp_no_forward_secrecy": {"generator": generate_smtp_no_forward_secrecy, "label": {"protocol": "smtp", "tls_mode": "implicit", "tls_version": "TLS1.2", "cipher_suite": "TLS_RSA_WITH_AES_128_GCM_SHA256", "forward_secrecy": False, "key_exchange": "rsa", "cert_key_algo": "RSA", "cert_key_bits": 2048, "cert_expired": False, "cert_self_signed": True, "cert_sig_algo": "sha256", "expected_rules_fired": ["no-forward-secrecy", "self-signed-cert"], "expected_rules_silent": ["deprecated-tls-version", "weak-cipher", "cert-expired", "weak-cert-key-rsa", "weak-cert-signature", "no-tls", "starttls-stripped"]}},
}


def main():
    """Generate all test PCAPs and labels.json."""
    labels = {}

    for name, scenario in SCENARIOS.items():
        pcap_path = FIXTURES_DIR / f"{name}.pcap"
        pkts, server_ip = scenario["generator"]()
        wrpcap(str(pcap_path), pkts)
        print(f"  ✓ Generated {pcap_path.name} ({len(pkts)} packets)")

        label = dict(scenario["label"])
        label["server_ip"] = server_ip
        label["pcap_file"] = f"{name}.pcap"
        labels[name] = label

    labels_path = FIXTURES_DIR / "labels.json"
    with open(labels_path, "w") as f:
        json.dump(labels, f, indent=2, default=str)
    print(f"\n  ✓ Written {labels_path}")

    # Composite demo PCAP
    print("\nGenerating composite demo PCAP...")
    all_pkts = []
    time_offset = 0.0
    for name, scenario in SCENARIOS.items():
        pkts, _ = scenario["generator"]()
        for pkt in pkts:
            pkt.time = BASE_TS + time_offset + (pkt.time - BASE_TS)
        all_pkts.extend(pkts)
        time_offset += 1.0

    demo_path = FIXTURES_DIR / "demo_composite.pcap"
    wrpcap(str(demo_path), all_pkts)
    print(f"  ✓ Generated {demo_path.name} ({len(all_pkts)} packets)")
    print(f"\nDone! Generated {len(SCENARIOS)} scenario PCAPs + 1 composite demo + labels.json")


if __name__ == "__main__":
    main()
