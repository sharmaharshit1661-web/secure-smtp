"""
Secure SMTP — High-Assurance Cryptographic Security Posture Intelligence Console.

Passive Network Forensics & AI Risk Attribution for SMTP / IMAP / POP3 Protocols.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import plotly.graph_objects as go
import requests
import streamlit as st

# Ensure src/ is on sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# ── Page Configuration ──

st.set_page_config(
    page_title="SECURE SMTP — Cryptographic Security Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

API_BASE = os.environ.get("SECUREMAILSCOPE_API", "http://localhost:8000")
FIXTURES_PCAPS_DIR = ROOT_DIR / "tests" / "fixtures" / "pcaps"

# ── Custom CSS Design System ──

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

    :root {
        --bg-void: #05080E;
        --bg-canvas: #090D16;
        --bg-sidebar: #0A0F1D;
        --bg-surface: #0F1626;
        --bg-surface-hover: #151F36;
        --bg-surface-raised: #1A2642;
        --border-subtle: rgba(255, 255, 255, 0.08);
        --border-glow: rgba(0, 240, 255, 0.35);
        --text-primary: #F8FAFC;
        --text-secondary: #94A3B8;
        --text-muted: #64748B;
        --cyan-neon: #00F0FF;
        --emerald-neon: #10B981;
        --amber-neon: #F59E0B;
        --orange-neon: #F97316;
        --crimson-neon: #FF3B30;
    }

    /* Hide Deploy Button, Toolbar, Footer — but KEEP sidebar toggle visible */
    #MainMenu { display: none !important; visibility: hidden !important; }
    .stDeployButton { display: none !important; visibility: hidden !important; }
    div[data-testid="stToolbar"] { display: none !important; visibility: hidden !important; }
    div[data-testid="stDecoration"] { display: none !important; visibility: hidden !important; }
    div[data-testid="stStatusWidget"] { display: none !important; visibility: hidden !important; }
    div[data-testid="stActionElements"] { display: none !important; visibility: hidden !important; }
    footer { display: none !important; visibility: hidden !important; }

    /* Keep header visible but transparent so sidebar toggle works */
    header[data-testid="stHeader"] {
        background: transparent !important;
        backdrop-filter: none !important;
    }

    /* Global Application Styles */
    .stApp {
        background: radial-gradient(circle at 50% 0%, #111A2E 0%, var(--bg-canvas) 70%);
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
        color: var(--text-primary);
    }

    .block-container {
        padding-top: 1.25rem !important;
        padding-bottom: 2rem !important;
        max-width: 1440px !important;
    }

    /* Custom Scrollbars */
    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    ::-webkit-scrollbar-track {
        background: var(--bg-void);
    }
    ::-webkit-scrollbar-thumb {
        background: rgba(255, 255, 255, 0.15);
        border-radius: 3px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: rgba(0, 240, 255, 0.4);
    }

    /* ══════════════════════════════════════════════════════════════ */
    /* BESPOKE SIDEBAR DESIGN SYSTEM                                 */
    /* ══════════════════════════════════════════════════════════════ */
    
    div[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0A0F1D 0%, #070A14 100%) !important;
        border-right: 1px solid var(--border-subtle);
        box-shadow: 4px 0 24px rgba(0, 0, 0, 0.4);
    }

    div[data-testid="stSidebar"] > div:first-child {
        padding-top: 1.1rem;
        padding-bottom: 1.25rem;
    }

    /* Brand Block */
    .sms-sidebar-brand {
        display: flex;
        align-items: center;
        gap: 0.85rem;
        padding: 0.2rem 0.2rem 1rem 0.2rem;
        border-bottom: 1px solid var(--border-subtle);
        margin-bottom: 1rem;
    }

    .sms-sidebar-logo {
        width: 38px;
        height: 38px;
        background: linear-gradient(135deg, #00F0FF 0%, #3B82F6 100%);
        border-radius: 9px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.25rem;
        box-shadow: 0 0 16px rgba(0, 240, 255, 0.4), inset 0 1px 1px rgba(255, 255, 255, 0.4);
    }

    .sms-sidebar-name {
        font-weight: 800;
        font-size: 1.08rem;
        letter-spacing: -0.02em;
        color: #FFFFFF;
        line-height: 1.1;
    }

    .sms-sidebar-sub {
        font-size: 0.65rem;
        color: #00F0FF;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 700;
        letter-spacing: 0.06em;
        margin-top: 2px;
    }

    /* Section Category Headers */
    .sms-sidebar-section-label {
        font-size: 0.65rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        color: #64748B;
        margin-bottom: 0.5rem;
        padding-left: 0.25rem;
        display: flex;
        align-items: center;
        gap: 0.35rem;
    }

    /* COMPACT, SLEEK SIDEBAR NAVIGATION BUTTONS */
    div[data-testid="stSidebar"] div.stButton {
        margin-bottom: 0.18rem !important;
    }

    div[data-testid="stSidebar"] div.stButton > button {
        text-align: left !important;
        justify-content: flex-start !important;
        padding: 0.42rem 0.75rem !important;
        min-height: 36px !important;
        height: 36px !important;
        font-size: 0.82rem !important;
        font-weight: 600 !important;
        border-radius: 7px !important;
        transition: all 0.18s cubic-bezier(0.16, 1, 0.3, 1) !important;
        display: flex !important;
        align-items: center !important;
        width: 100% !important;
    }

    /* Inactive Nav Items */
    div[data-testid="stSidebar"] div.stButton > button[kind="secondary"],
    div[data-testid="stSidebar"] div.stButton > button[data-testid="baseButton-secondary"] {
        background: rgba(255, 255, 255, 0.025) !important;
        border: 1px solid rgba(255, 255, 255, 0.05) !important;
        color: #94A3B8 !important;
    }

    div[data-testid="stSidebar"] div.stButton > button[kind="secondary"]:hover,
    div[data-testid="stSidebar"] div.stButton > button[data-testid="baseButton-secondary"]:hover {
        background: rgba(0, 240, 255, 0.08) !important;
        border-color: rgba(0, 240, 255, 0.3) !important;
        color: #FFFFFF !important;
        transform: translateX(3px) !important;
        box-shadow: 0 0 12px rgba(0, 240, 255, 0.15) !important;
    }

    /* Active Nav Item - Sleek Cyber Cyan */
    div[data-testid="stSidebar"] div.stButton > button[kind="primary"],
    div[data-testid="stSidebar"] div.stButton > button[data-testid="baseButton-primary"] {
        background: linear-gradient(90deg, rgba(0, 240, 255, 0.18) 0%, rgba(0, 240, 255, 0.03) 100%) !important;
        border: 1px solid rgba(0, 240, 255, 0.45) !important;
        border-left: 3px solid #00F0FF !important;
        color: #00F0FF !important;
        font-weight: 700 !important;
        box-shadow: 0 0 14px rgba(0, 240, 255, 0.18), inset 0 0 8px rgba(0, 240, 255, 0.05) !important;
    }

    /* Telemetry Posture Widget */
    .sms-telemetry-widget {
        background: rgba(15, 22, 38, 0.95);
        border: 1px solid var(--border-subtle);
        border-radius: 10px;
        padding: 0.75rem;
        margin: 1rem 0;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
    }

    .sms-telemetry-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 0.68rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: var(--text-secondary);
        margin-bottom: 0.6rem;
        padding-bottom: 0.4rem;
        border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }

    .sms-status-beacon {
        display: inline-flex;
        align-items: center;
        gap: 0.35rem;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.65rem;
        color: #34D399;
        font-weight: 700;
    }

    .sms-status-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background-color: #10B981;
        box-shadow: 0 0 8px #10B981;
        animation: pulse-glow 2s infinite ease-in-out;
    }

    @keyframes pulse-glow {
        0% { transform: scale(0.9); opacity: 0.7; }
        50% { transform: scale(1.3); opacity: 1; box-shadow: 0 0 14px #10B981; }
        100% { transform: scale(0.9); opacity: 0.7; }
    }

    .sms-stats-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 0.45rem;
    }

    .sms-stat-box {
        background: rgba(6, 9, 15, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-radius: 6px;
        padding: 0.45rem 0.55rem;
    }

    .sms-stat-lbl {
        font-size: 0.58rem;
        color: var(--text-muted);
        text-transform: uppercase;
        font-weight: 700;
        letter-spacing: 0.05em;
    }

    .sms-stat-num {
        font-size: 1.15rem;
        font-weight: 800;
        font-family: 'JetBrains Mono', monospace;
        color: #FFFFFF;
        line-height: 1.1;
        margin-top: 2px;
    }

    /* Security Assurance Seal */
    .sms-security-seal {
        background: linear-gradient(135deg, rgba(0, 240, 255, 0.06) 0%, rgba(16, 185, 129, 0.03) 100%);
        border: 1px solid rgba(0, 240, 255, 0.18);
        border-radius: 9px;
        padding: 0.75rem;
        margin-top: 0.65rem;
    }

    .sms-seal-head {
        font-size: 0.72rem;
        font-weight: 700;
        color: #00F0FF;
        display: flex;
        align-items: center;
        gap: 0.35rem;
        margin-bottom: 0.25rem;
    }

    .sms-seal-desc {
        font-size: 0.68rem;
        color: var(--text-secondary);
        line-height: 1.35;
    }

    /* ══════════════════════════════════════════════════════════════ */
    /* MAIN DASHBOARD CONTENT STYLES                                 */
    /* ══════════════════════════════════════════════════════════════ */

    .sms-header-box {
        background: linear-gradient(135deg, rgba(15, 22, 38, 0.9) 0%, rgba(10, 15, 28, 0.95) 100%);
        border: 1px solid var(--border-subtle);
        border-radius: 14px;
        padding: 1.1rem 1.6rem;
        margin-bottom: 1rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
        backdrop-filter: blur(16px);
        box-shadow: 0 10px 30px -5px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.1);
    }

    .sms-header-left {
        display: flex;
        align-items: center;
        gap: 1.1rem;
    }

    .sms-header-title {
        font-size: 1.4rem;
        font-weight: 800;
        letter-spacing: -0.02em;
        margin: 0;
        color: #FFFFFF;
        display: flex;
        align-items: center;
        gap: 0.6rem;
    }

    .sms-header-sub {
        font-size: 0.8rem;
        color: var(--text-secondary);
        margin: 0;
        margin-top: 2px;
    }

    .sms-telemetry-pill {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.45rem 0.9rem;
        background: rgba(16, 185, 129, 0.1);
        border: 1px solid rgba(16, 185, 129, 0.3);
        border-radius: 24px;
        font-size: 0.75rem;
        font-family: 'JetBrains Mono', monospace;
        color: #34D399;
        font-weight: 600;
        box-shadow: 0 0 12px rgba(16, 185, 129, 0.15);
    }

    .sms-kpi-card {
        background: var(--bg-surface);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        padding: 1.15rem 1.25rem;
        transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
        position: relative;
        overflow: hidden;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.25);
    }

    .sms-kpi-card:hover {
        border-color: var(--border-glow);
        background: var(--bg-surface-hover);
        transform: translateY(-3px);
        box-shadow: 0 12px 30px rgba(0, 240, 255, 0.15);
    }

    .sms-kpi-label {
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--text-secondary);
        margin-bottom: 0.35rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }

    .sms-kpi-val {
        font-size: 2.1rem;
        font-weight: 800;
        font-family: 'JetBrains Mono', monospace;
        line-height: 1.1;
        color: var(--text-primary);
        letter-spacing: -0.02em;
    }

    .sms-kpi-sub {
        font-size: 0.75rem;
        color: var(--text-muted);
        margin-top: 0.4rem;
    }

    .val-critical { color: var(--crimson-neon) !important; text-shadow: 0 0 12px rgba(255, 59, 48, 0.3); }
    .val-high { color: var(--orange-neon) !important; }
    .val-medium { color: var(--amber-neon) !important; }
    .val-low { color: var(--cyan-neon) !important; }
    .val-clean { color: var(--emerald-neon) !important; text-shadow: 0 0 12px rgba(16, 185, 129, 0.3); }

    .sms-glass-container {
        background: var(--bg-surface);
        border: 1px solid var(--border-subtle);
        border-radius: 14px;
        padding: 1.35rem;
        margin-bottom: 1.25rem;
        box-shadow: 0 6px 20px rgba(0, 0, 0, 0.25);
    }

    .sms-section-header {
        font-size: 1.05rem;
        font-weight: 700;
        letter-spacing: -0.01em;
        color: var(--text-primary);
        margin-bottom: 1rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .sms-finding-card {
        background: rgba(15, 22, 38, 0.85);
        border: 1px solid var(--border-subtle);
        border-radius: 10px;
        padding: 1rem 1.25rem;
        margin-bottom: 0.85rem;
        transition: all 0.2s ease;
    }

    .sms-finding-card.critical { border-color: rgba(255, 59, 48, 0.4); background: rgba(255, 59, 48, 0.04); }
    .sms-finding-card.high { border-color: rgba(249, 115, 22, 0.4); background: rgba(249, 115, 22, 0.04); }
    .sms-finding-card.medium { border-color: rgba(245, 158, 11, 0.4); background: rgba(245, 158, 11, 0.04); }
    .sms-finding-card.low { border-color: rgba(0, 240, 255, 0.4); background: rgba(0, 240, 255, 0.04); }

    .sms-tag-badge {
        display: inline-block;
        padding: 3px 8px;
        border-radius: 5px;
        font-size: 0.7rem;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }

    .sms-tag-badge.critical { background: rgba(255, 59, 48, 0.15); color: #FF6B6B; border: 1px solid rgba(255, 59, 48, 0.3); }
    .sms-tag-badge.high { background: rgba(249, 115, 22, 0.15); color: #FDBA74; border: 1px solid rgba(249, 115, 22, 0.3); }
    .sms-tag-badge.medium { background: rgba(245, 158, 11, 0.15); color: #FDE047; border: 1px solid rgba(245, 158, 11, 0.3); }
    .sms-tag-badge.low { background: rgba(0, 240, 255, 0.15); color: #67E8F9; border: 1px solid rgba(0, 240, 255, 0.3); }
    .sms-tag-badge.clean { background: rgba(16, 185, 129, 0.15); color: #6EE7B7; border: 1px solid rgba(16, 185, 129, 0.3); }

    .sms-remediation-box {
        background: rgba(6, 9, 15, 0.85);
        border: 1px solid rgba(255, 255, 255, 0.07);
        border-radius: 8px;
        padding: 0.75rem 1rem;
        margin-top: 0.65rem;
        font-size: 0.82rem;
        color: #93C5FD;
        display: flex;
        align-items: flex-start;
        gap: 0.6rem;
    }

    .sms-wire-strip {
        background: linear-gradient(90deg, #0F1626 0%, #151F36 50%, #0F1626 100%);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        padding: 1.15rem 1.5rem;
        margin-bottom: 1.35rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
    }

    .sms-endpoint-box {
        text-align: center;
    }

    .sms-endpoint-title {
        font-size: 0.7rem;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.08em;
        font-weight: 600;
    }

    .sms-endpoint-addr {
        font-family: 'JetBrains Mono', monospace;
        font-size: 1.15rem;
        font-weight: 700;
        color: #FFFFFF;
        margin-top: 2px;
    }

    .sms-wire-mid {
        flex: 1;
        margin: 0 2rem;
        text-align: center;
    }

    .sms-wire-glow {
        height: 2px;
        background: linear-gradient(90deg, transparent, #00F0FF, transparent);
        margin: 0.35rem 0;
        box-shadow: 0 0 8px rgba(0, 240, 255, 0.6);
    }

    .sms-scenario-card {
        background: var(--bg-surface);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        padding: 1.1rem;
        margin-bottom: 0.85rem;
        transition: all 0.2s ease;
    }

    .sms-scenario-card:hover {
        border-color: var(--border-glow);
        background: var(--bg-surface-hover);
        transform: translateY(-2px);
    }

    .stTabs [data-baseweb="tab-list"] {
        gap: 0.5rem;
        background: rgba(6, 9, 15, 0.6);
        padding: 0.35rem;
        border-radius: 10px;
        border: 1px solid var(--border-subtle);
    }

    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        padding: 0.5rem 1.15rem;
        color: var(--text-secondary);
        font-weight: 600;
        font-size: 0.85rem;
    }

    .stTabs [aria-selected="true"] {
        background: var(--bg-surface-raised) !important;
        color: var(--cyan-neon) !important;
        box-shadow: 0 0 15px rgba(0, 240, 255, 0.15);
    }
</style>
""", unsafe_allow_html=True)


# ── Live Real-Time Data Fetching Layer (FastAPI REST + MongoDB Direct Fallback) ──

@st.cache_data(ttl=1)
def get_fleet_hosts() -> list[dict[str, Any]]:
    """Fetch live host inventory directly from FastAPI backend or MongoDB fallback."""
    try:
        resp = requests.get(f"{API_BASE}/api/hosts", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if data:
                return sorted(data, key=lambda x: -x.get("aggregate_risk_score", 0.0))
    except Exception:
        pass

    try:
        from securemailscope.db.mongodb import get_hosts_col
        hosts_col = get_hosts_col()
        hosts = list(hosts_col.find({}, {"_id": 0}))
        res = [
            {
                "host_id": h["id"],
                "ip": h["ip_or_hostname"],
                "session_count": h.get("session_count", 0),
                "aggregate_risk_score": float(h.get("aggregate_risk_score", 0.0)),
            }
            for h in hosts
        ]
        return sorted(res, key=lambda x: -x["aggregate_risk_score"])
    except Exception:
        return []


@st.cache_data(ttl=1)
def get_host_detail(host_id: int) -> dict[str, Any] | None:
    """Fetch real-time host detail and all associated session streams."""
    try:
        resp = requests.get(f"{API_BASE}/api/hosts/{host_id}", timeout=3)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass

    try:
        from securemailscope.db.mongodb import get_hosts_col, get_sessions_col
        hosts_col = get_hosts_col()
        sessions_col = get_sessions_col()

        host = hosts_col.find_one({"id": host_id}, {"_id": 0})
        if not host:
            return None

        sessions = list(sessions_col.find({"host_id": host_id}, {"_id": 0}))
        session_list = []
        for s in sessions:
            risk = s.get("risk_score") or {}
            session_list.append({
                "session_id": s["id"],
                "src_ip": s["src_ip"],
                "src_port": s["src_port"],
                "dst_ip": s["dst_ip"],
                "dst_port": s["dst_port"],
                "protocol": s.get("protocol", "smtp"),
                "tls_mode": s.get("tls_mode", "none"),
                "risk_score": risk.get("score_0_100", 0.0),
                "risk_tier": risk.get("tier", "low"),
            })

        return {
            "host_id": host["id"],
            "ip": host["ip_or_hostname"],
            "aggregate_risk_score": host.get("aggregate_risk_score", 0.0),
            "sessions": session_list,
        }
    except Exception:
        return None


@st.cache_data(ttl=1)
def get_session_detail(session_id: int) -> dict[str, Any] | None:
    """Fetch deep real-time session telemetry record from backend or MongoDB."""
    try:
        resp = requests.get(f"{API_BASE}/api/sessions/{session_id}", timeout=3)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass

    try:
        from securemailscope.db.mongodb import get_sessions_col
        sessions_col = get_sessions_col()
        session = sessions_col.find_one({"id": session_id}, {"_id": 0})
        if not session:
            return None

        handshake = session.get("handshake")
        certificates = session.get("certificates", [])
        findings = session.get("findings", [])
        risk_score = session.get("risk_score")
        anomaly_score = session.get("anomaly_score")

        return {
            "id": session["id"],
            "session_id": session["id"],
            "pcap_source": session.get("pcap_source", ""),
            "src_ip": session["src_ip"],
            "src_port": session["src_port"],
            "dst_ip": session["dst_ip"],
            "dst_port": session["dst_port"],
            "protocol": session.get("protocol", "smtp"),
            "tls_mode": session.get("tls_mode", "none"),
            "starttls_advertised": session.get("starttls_advertised", False),
            "starttls_completed": session.get("starttls_completed", False),
            "handshake": handshake,
            "certificates": [
                {
                    "chain_position": c.get("chain_position", 0),
                    "subject": c.get("subject", ""),
                    "issuer": c.get("issuer", ""),
                    "not_before": c.get("not_before"),
                    "not_after": c.get("not_after"),
                    "public_key_algorithm": c.get("public_key_algorithm", ""),
                    "key_length_bits": c.get("key_length_bits", 0),
                    "signature_algorithm": c.get("signature_algorithm", ""),
                    "self_signed": c.get("self_signed", False),
                    "chain_valid": c.get("chain_valid", True),
                }
                for c in certificates
            ],
            "findings": [
                {
                    "rule_id": f.get("rule_id", ""),
                    "severity": f.get("severity", "info"),
                    "message": f.get("message", ""),
                    "recommendation": f.get("recommendation_text") or f.get("recommendation", ""),
                }
                for f in findings
            ],
            "risk_score": {
                "score": risk_score.get("score_0_100", 0.0),
                "tier": risk_score.get("tier", "low"),
                "explanation": risk_score.get("feature_attribution", {}),
            } if risk_score else None,
            "anomaly_score": {
                "score": anomaly_score.get("anomaly_score", 0.0),
                "is_anomalous": anomaly_score.get("is_anomalous", False),
                "baseline": anomaly_score.get("baseline_reference", "global"),
            } if anomaly_score else None,
        }
    except Exception:
        return None


def run_pcap_ingest(pcap_bytes: bytes, filename: str) -> tuple[bool, str]:
    """Execute real-time PCAP ingestion through FastAPI or direct MongoDB pipeline."""
    try:
        files = {"file": (filename, pcap_bytes, "application/octet-stream")}
        resp = requests.post(f"{API_BASE}/api/analyze", files=files, timeout=30)
        if resp.status_code == 200:
            return True, resp.json().get("job_id", "")
    except Exception:
        pass

    try:
        import uuid
        from securemailscope.api.main import _run_analysis
        from securemailscope.db.models import AnalysisJob
        from securemailscope.db.mongodb import get_jobs_col, get_next_sequence

        job_id = str(uuid.uuid4())
        upload_dir = Path("/tmp/securemailscope_uploads")
        upload_dir.mkdir(parents=True, exist_ok=True)
        file_path = upload_dir / f"{job_id}_{filename}"
        file_path.write_bytes(pcap_bytes)

        jobs_col = get_jobs_col()
        job = AnalysisJob(
            id=get_next_sequence("job_id"),
            job_id=job_id,
            pcap_filename=filename,
            status="pending",
        )
        jobs_col.insert_one(job.model_dump())

        _run_analysis(job_id, str(file_path))
        return True, job_id
    except Exception as e:
        return False, str(e)


# ── Color & Gauge Generators ──

def get_tier_color(tier: str) -> str:
    mapping = {
        "critical": "#FF3B30",
        "high": "#F97316",
        "medium": "#F59E0B",
        "low": "#00F0FF",
        "clean": "#10B981",
        "info": "#64748B",
    }
    return mapping.get(str(tier).lower(), "#64748B")


def make_gauge_chart(score: float, tier: str) -> go.Figure:
    color = get_tier_color(tier)
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={"x": [0, 1], "y": [0, 1]},
        number={
            "font": {"color": "#FFFFFF", "family": "JetBrains Mono", "size": 38},
            "suffix": "/100",
        },
        gauge={
            "axis": {
                "range": [0, 100],
                "tickwidth": 1,
                "tickcolor": "#334155",
                "tickfont": {"color": "#64748B", "family": "JetBrains Mono", "size": 10},
                "nticks": 5,
            },
            "bar": {"color": color, "thickness": 0.28},
            "bgcolor": "#0F1626",
            "borderwidth": 1,
            "bordercolor": "rgba(255, 255, 255, 0.1)",
            "steps": [
                {"range": [0, 25], "color": "rgba(16, 185, 129, 0.1)"},
                {"range": [25, 50], "color": "rgba(245, 158, 11, 0.1)"},
                {"range": [50, 75], "color": "rgba(249, 115, 22, 0.1)"},
                {"range": [75, 100], "color": "rgba(255, 59, 48, 0.15)"},
            ],
            "threshold": {
                "line": {"color": color, "width": 3},
                "thickness": 0.8,
                "value": score,
            },
        },
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=170,
        margin=dict(l=15, r=15, t=20, b=10),
    )
    return fig


# ── Global Navigation Session State ──

if "nav_page" not in st.session_state:
    st.session_state["nav_page"] = "fleet"

if "selected_host_id" not in st.session_state:
    st.session_state["selected_host_id"] = None

hosts_list = get_fleet_hosts()
total_hosts = len(hosts_list)
total_sessions = sum(h.get("session_count", 0) for h in hosts_list)
critical_hosts_count = sum(1 for h in hosts_list if h.get("aggregate_risk_score", 0) >= 75)

# ── Sidebar Navigation ──

with st.sidebar:
    st.markdown("""
    <div class="sms-sidebar-brand">
        <div class="sms-sidebar-logo">🛡️</div>
        <div>
            <div class="sms-sidebar-name">Secure SMTP</div>
            <div class="sms-sidebar-sub">CRYPTOGRAPHIC OPS</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="sms-sidebar-section-label">
        <span style="color:#00F0FF;">●</span> Console Navigation
    </div>
    """, unsafe_allow_html=True)

    nav_options = [
        ("fleet", "🌐  Fleet Overview"),
        ("explorer", "🔬  Session Explorer"),
        ("ingest", "⚡  Live Ingest & Replay"),
        ("rules", "📋  Rules & Compliance"),
    ]

    for key, label in nav_options:
        is_active = st.session_state["nav_page"] == key
        btn_type = "primary" if is_active else "secondary"
        if st.button(label, key=f"sidebar_nav_{key}", type=btn_type):
            st.session_state["nav_page"] = key
            st.rerun()

    # Telemetry Widget Box
    st.markdown(f"""
    <div class="sms-telemetry-widget">
        <div class="sms-telemetry-header">
            <span>LIVE AUDIT TELEMETRY</span>
            <div class="sms-status-beacon">
                <span class="sms-status-dot"></span>
                <span>ACTIVE</span>
            </div>
        </div>
        <div class="sms-stats-grid">
            <div class="sms-stat-box">
                <div class="sms-stat-lbl">AUDITED HOSTS</div>
                <div class="sms-stat-num">{total_hosts}</div>
            </div>
            <div class="sms-stat-box">
                <div class="sms-stat-lbl">TOTAL SESSIONS</div>
                <div class="sms-stat-num">{total_sessions}</div>
            </div>
            <div class="sms-stat-box" style="grid-column: span 2; display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <div class="sms-stat-lbl">CRITICAL ALERTS</div>
                    <div class="sms-stat-num" style="color: {'#FF3B30' if critical_hosts_count > 0 else '#10B981'}; font-size: 1.1rem;">
                        {critical_hosts_count} HOSTS
                    </div>
                </div>
                <div style="font-size: 0.72rem; font-weight: 700; color: {'#FF3B30' if critical_hosts_count > 0 else '#10B981'}; background: {'rgba(255, 59, 48, 0.12)' if critical_hosts_count > 0 else 'rgba(16, 185, 129, 0.12)'}; padding: 3px 8px; border-radius: 4px; border: 1px solid {'rgba(255, 59, 48, 0.3)' if critical_hosts_count > 0 else 'rgba(16, 185, 129, 0.3)'};">
                    {'ATTENTION' if critical_hosts_count > 0 else 'PRISTINE'}
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Security Assurance Seal
    st.markdown("""
    <div class="sms-security-seal">
        <div class="sms-seal-head">
            <span>🔒</span> PASSIVE FORENSIC ENGINE
        </div>
        <div class="sms-seal-desc">
            Passive PCAP inspection with zero network transmission or message payload decryption.
        </div>
    </div>
    """, unsafe_allow_html=True)


# ── Top Banner ──

st.markdown(f"""
<div class="sms-header-box">
    <div class="sms-header-left">
        <div style="width: 42px; height: 42px; background: linear-gradient(135deg, #00F0FF 0%, #3B82F6 100%); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.35rem; box-shadow: 0 0 18px rgba(0, 240, 255, 0.4);">🛡️</div>
        <div>
            <div class="sms-header-title">
                Secure SMTP
                <span style="font-size: 0.7rem; font-weight: 700; color: #00F0FF; background: rgba(0, 240, 255, 0.12); padding: 3px 8px; border-radius: 4px; border: 1px solid rgba(0, 240, 255, 0.3);">ENTERPRISE AUDIT</span>
            </div>
            <div class="sms-header-sub">
                Passive Cryptographic Posture Intelligence & Explainable AI Risk Attribution for SMTP / IMAP / POP3
            </div>
        </div>
    </div>
    <div>
        <div class="sms-telemetry-pill">
            <span class="sms-status-dot"></span>
            <span>ENGINE READY ({total_hosts} HOSTS / {total_sessions} SESSIONS)</span>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Top Quick Navigation Bar ──

top_nav_c1, top_nav_c2, top_nav_c3, top_nav_c4 = st.columns(4)

with top_nav_c1:
    is_f = st.session_state["nav_page"] == "fleet"
    if st.button("🌐  Fleet Overview", key="top_nav_fleet", type="primary" if is_f else "secondary", width='stretch'):
        st.session_state["nav_page"] = "fleet"
        st.rerun()

with top_nav_c2:
    is_e = st.session_state["nav_page"] == "explorer"
    if st.button("🔬  Session Explorer", key="top_nav_explorer", type="primary" if is_e else "secondary", width='stretch'):
        st.session_state["nav_page"] = "explorer"
        st.rerun()

with top_nav_c3:
    is_i = st.session_state["nav_page"] == "ingest"
    if st.button("⚡  Live Ingest & Replay", key="top_nav_ingest", type="primary" if is_i else "secondary", width='stretch'):
        st.session_state["nav_page"] = "ingest"
        st.rerun()

with top_nav_c4:
    is_r = st.session_state["nav_page"] == "rules"
    if st.button("📋  Rules & Compliance", key="top_nav_rules", type="primary" if is_r else "secondary", width='stretch'):
        st.session_state["nav_page"] = "rules"
        st.rerun()

st.markdown("<br>", unsafe_allow_html=True)


# ==============================================================================
# VIEW 1: FLEET OVERVIEW
# ==============================================================================

if st.session_state["nav_page"] == "fleet":
    if not hosts_list:
        st.info("No host data available in database. Head to 'Live Ingest & Replay' to run your first PCAP analysis.")
    else:
        avg_risk = sum(h["aggregate_risk_score"] for h in hosts_list) / total_hosts if total_hosts > 0 else 0
        high_hosts = sum(1 for h in hosts_list if 50 <= h["aggregate_risk_score"] < 75)
        clean_hosts = sum(1 for h in hosts_list if h["aggregate_risk_score"] < 25)

        # ── KPI Posture Metric Banner ──
        kpi_1, kpi_2, kpi_3, kpi_4, kpi_5 = st.columns(5)

        with kpi_1:
            st.markdown(f"""
            <div class="sms-kpi-card">
                <div class="sms-kpi-label"><span>Audited Hosts</span> <span>🌐</span></div>
                <div class="sms-kpi-val">{total_hosts}</div>
                <div class="sms-kpi-sub">Across All Subnets</div>
            </div>
            """, unsafe_allow_html=True)

        with kpi_2:
            st.markdown(f"""
            <div class="sms-kpi-card">
                <div class="sms-kpi-label"><span>Evaluated Sessions</span> <span>🔐</span></div>
                <div class="sms-kpi-val">{total_sessions}</div>
                <div class="sms-kpi-sub">SMTP / IMAP / POP3</div>
            </div>
            """, unsafe_allow_html=True)

        with kpi_3:
            st.markdown(f"""
            <div class="sms-kpi-card">
                <div class="sms-kpi-label"><span>Fleet Risk Index</span> <span>📊</span></div>
                <div class="sms-kpi-val {'val-critical' if avg_risk >= 50 else 'val-medium' if avg_risk >= 25 else 'val-clean'}">{avg_risk:.1f}</div>
                <div class="sms-kpi-sub">Weighted Posture Mean</div>
            </div>
            """, unsafe_allow_html=True)

        with kpi_4:
            st.markdown(f"""
            <div class="sms-kpi-card">
                <div class="sms-kpi-label"><span>Critical Threat</span> <span>⚠️</span></div>
                <div class="sms-kpi-val val-critical">{critical_hosts_count}</div>
                <div class="sms-kpi-sub">Score ≥ 75 (Action Needed)</div>
            </div>
            """, unsafe_allow_html=True)

        with kpi_5:
            st.markdown(f"""
            <div class="sms-kpi-card">
                <div class="sms-kpi-label"><span>Pristine / Good</span> <span>✅</span></div>
                <div class="sms-kpi-val val-clean">{clean_hosts}</div>
                <div class="sms-kpi-sub">Modern TLS 1.3 / AEAD</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # ── Interactive Visualizations ──
        c_bar, c_pie = st.columns([3, 2])

        with c_bar:
            st.markdown('<div class="sms-section-header">📊 Host Cryptographic Risk Distribution</div>', unsafe_allow_html=True)

            host_ips = [h["ip"] for h in hosts_list]
            host_scores = [h["aggregate_risk_score"] for h in hosts_list]
            bar_colors = [
                "#FF3B30" if s >= 75
                else "#F97316" if s >= 50
                else "#F59E0B" if s >= 25
                else "#10B981"
                for s in host_scores
            ]

            fig_bar = go.Figure(data=[
                go.Bar(
                    x=host_ips,
                    y=host_scores,
                    marker=dict(
                        color=bar_colors,
                        line=dict(color="rgba(255, 255, 255, 0.2)", width=1),
                    ),
                    text=[f"{s:.0f}" for s in host_scores],
                    textposition="outside",
                    textfont=dict(color="#FFFFFF", family="JetBrains Mono", size=11),
                )
            ])

            fig_bar.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(15, 22, 38, 0.5)",
                xaxis=dict(
                    color="#94A3B8",
                    tickfont=dict(family="JetBrains Mono", size=10),
                    gridcolor="rgba(255, 255, 255, 0.05)",
                ),
                yaxis=dict(
                    color="#94A3B8",
                    range=[0, 115],
                    tickfont=dict(family="JetBrains Mono", size=10),
                    gridcolor="rgba(255, 255, 255, 0.08)",
                    title="Risk Score (0–100)",
                ),
                font=dict(color="#E2E8F0"),
                height=300,
                margin=dict(l=40, r=20, t=20, b=40),
            )
            st.plotly_chart(fig_bar, width='stretch')

        with c_pie:
            st.markdown('<div class="sms-section-header">🛡️ Posture Risk Tier Breakdown</div>', unsafe_allow_html=True)

            tier_counts = {
                "Critical (≥75)": critical_hosts_count,
                "High (50–74)": high_hosts,
                "Medium (25–49)": sum(1 for h in hosts_list if 25 <= h["aggregate_risk_score"] < 50),
                "Clean (<25)": clean_hosts,
            }

            fig_donut = go.Figure(data=[
                go.Pie(
                    labels=list(tier_counts.keys()),
                    values=list(tier_counts.values()),
                    hole=0.62,
                    marker=dict(colors=["#FF3B30", "#F97316", "#F59E0B", "#10B981"]),
                    textinfo="value",
                    textfont=dict(family="JetBrains Mono", size=13, color="#FFFFFF"),
                    hoverinfo="label+value+percent",
                )
            ])

            fig_donut.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                showlegend=True,
                legend=dict(font=dict(color="#94A3B8", size=11), orientation="v", x=1.02, y=0.5),
                height=300,
                margin=dict(l=20, r=80, t=20, b=20),
            )
            st.plotly_chart(fig_donut, width='stretch')

        st.markdown("---")

        # ── Host Posture Inventory Table / Cards ──
        st.markdown('<div class="sms-section-header">🔍 Host Posture Inventory & Drill-Down</div>', unsafe_allow_html=True)

        filter_1, filter_2 = st.columns([3, 1])
        with filter_1:
            query = st.text_input("Search Host IP or Subnet", placeholder="e.g. 10.0.0.1 or 192.168", label_visibility="collapsed")
        with filter_2:
            t_filter = st.selectbox(
                "Filter Tier",
                ["All Risk Tiers", "Critical Only (≥75)", "High Only (50–74)", "Medium (25–49)", "Clean (<25)"],
                label_visibility="collapsed",
            )

        filtered = hosts_list
        if query:
            filtered = [h for h in filtered if query.lower() in h["ip"].lower()]

        if "Critical" in t_filter:
            filtered = [h for h in filtered if h["aggregate_risk_score"] >= 75]
        elif "High" in t_filter:
            filtered = [h for h in filtered if 50 <= h["aggregate_risk_score"] < 75]
        elif "Medium" in t_filter:
            filtered = [h for h in filtered if 25 <= h["aggregate_risk_score"] < 50]
        elif "Clean" in t_filter:
            filtered = [h for h in filtered if h["aggregate_risk_score"] < 25]

        for h in filtered:
            score = h["aggregate_risk_score"]
            tier_str = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "clean"
            color_badge = get_tier_color(tier_str)

            col_h1, col_h2 = st.columns([4, 1.2])

            with col_h1:
                st.markdown(f"""
                <div class="sms-glass-container" style="margin-bottom: 0.4rem; padding: 0.85rem 1.25rem; display: flex; justify-content: space-between; align-items: center;">
                    <div style="display: flex; align-items: center; gap: 1.2rem;">
                        <div style="width: 8px; height: 38px; border-radius: 4px; background: {color_badge}; box-shadow: 0 0 10px {color_badge};"></div>
                        <div>
                            <div style="font-size: 1.1rem; font-weight: 800; font-family: 'JetBrains Mono'; color: #FFFFFF;">
                                {h['ip']}
                            </div>
                            <div style="font-size: 0.75rem; color: #94A3B8; margin-top: 1px;">
                                {h['session_count']} Analyzed Sessions • Real Cryptographic Ground Truth
                            </div>
                        </div>
                    </div>
                    <div style="text-align: right;">
                        <div style="font-size: 1.35rem; font-weight: 800; font-family: 'JetBrains Mono'; color: {color_badge};">
                            {score:.0f}<span style="font-size: 0.8rem; color: #64748B;">/100</span>
                        </div>
                        <div class="sms-tag-badge {tier_str}" style="margin-top: 2px;">{tier_str.upper()} RISK</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            with col_h2:
                st.markdown("<div style='margin-top: 6px;'></div>", unsafe_allow_html=True)
                if st.button(f"🔬 Inspect {h['ip']}", key=f"btn_inspect_{h['host_id']}", width='stretch'):
                    st.session_state["selected_host_id"] = h["host_id"]
                    st.session_state["nav_page"] = "explorer"
                    st.rerun()


# ==============================================================================
# VIEW 2: SESSION EXPLORER
# ==============================================================================

elif st.session_state["nav_page"] == "explorer":
    if not hosts_list:
        st.info("No sessions available. Ingest a PCAP file to explore cryptographic sessions.")
    else:
        st.markdown('<div class="sms-section-header">🔬 Deep Forensic Session Telemetry & Posture Dossier</div>', unsafe_allow_html=True)

        sel_h, sel_s = st.columns([1, 2])

        # Default host index if selected from Fleet
        default_h_idx = 0
        if st.session_state.get("selected_host_id"):
            for idx, h in enumerate(hosts_list):
                if h["host_id"] == st.session_state["selected_host_id"]:
                    default_h_idx = idx
                    break

        with sel_h:
            selected_h = st.selectbox(
                "Select Target Host",
                hosts_list,
                index=default_h_idx,
                format_func=lambda h: f"{h['ip']} — Score {h['aggregate_risk_score']:.0f} ({h['session_count']} sessions)",
            )

        if selected_h:
            h_data = get_host_detail(selected_h["host_id"])

            if not h_data or not h_data.get("sessions"):
                st.warning("No session streams found for this host.")
            else:
                s_list = h_data["sessions"]

                with sel_s:
                    selected_s = st.selectbox(
                        "Select Forensic Session Stream",
                        s_list,
                        format_func=lambda s: (
                            f"Session #{s['session_id']} | {s['src_ip']}:{s['src_port']} ➔ {s['dst_ip']}:{s['dst_port']} "
                            f"[{s['protocol'].upper()}] | Risk: {s.get('risk_score', 0):.0f}"
                        ),
                    )

                if selected_s:
                    sess = get_session_detail(selected_s["session_id"])

                    if sess:
                        st.markdown("<br>", unsafe_allow_html=True)

                        # Connection Diagram Wire
                        is_starttls = sess["tls_mode"].lower() == "starttls"
                        is_stripped = is_starttls and (not sess.get("starttls_completed"))
                        proto = sess["protocol"].upper()

                        tls_badge = (
                            '<span class="sms-tag-badge critical">⚠️ STARTTLS STRIPPED</span>' if is_stripped
                            else f'<span class="sms-tag-badge clean">🔒 {sess["tls_mode"].upper()} TLS</span>' if sess["tls_mode"] != "none"
                            else '<span class="sms-tag-badge critical">⚠️ UNENCRYPTED PLAINTEXT</span>'
                        )

                        st.markdown(f"""
                        <div class="sms-wire-strip">
                            <div class="sms-endpoint-box">
                                <div class="sms-endpoint-title">Source Client</div>
                                <div class="sms-endpoint-addr">{sess['src_ip']}:{sess['src_port']}</div>
                            </div>
                            <div class="sms-wire-mid">
                                <div style="font-size: 0.75rem; font-family: 'JetBrains Mono'; color: #00F0FF; font-weight: 600;">
                                    PROTOCOL: {proto} {tls_badge}
                                </div>
                                <div class="sms-wire-glow"></div>
                                <div style="font-size: 0.7rem; color: #64748B;">
                                    PCAP Source: {sess.get('pcap_source', 'Live Session')}
                                </div>
                            </div>
                            <div class="sms-endpoint-box">
                                <div class="sms-endpoint-title">Destination Server</div>
                                <div class="sms-endpoint-addr">{sess['dst_ip']}:{sess['dst_port']}</div>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)

                        # Top Cards: Gauge + Handshake Summary + Anomaly
                        sc_1, sc_2, sc_3 = st.columns([1.2, 1.8, 1])

                        with sc_1:
                            rs = sess.get("risk_score")
                            score_val = rs["score"] if rs else 0.0
                            tier_str = rs["tier"] if rs else "clean"
                            fig_g = make_gauge_chart(score_val, tier_str)
                            st.plotly_chart(fig_g, width='stretch')

                        with sc_2:
                            st.markdown("""
                            <div class="sms-glass-container" style="height: 100%; display: flex; flex-direction: column; justify-content: center;">
                                <div class="sms-section-header" style="margin-bottom: 0.5rem;">
                                    <span>🔐 Handshake Intelligence Summary</span>
                                </div>
                            """, unsafe_allow_html=True)

                            hs = sess.get("handshake")
                            if hs:
                                st.markdown(f"""
                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.6rem; font-size: 0.84rem;">
                                    <div><strong>Negotiated Version:</strong> <span style="font-family:'JetBrains Mono'; color:#00F0FF;">{hs.get('tls_version_negotiated', 'N/A')}</span></div>
                                    <div><strong>Key Exchange:</strong> <span style="font-family:'JetBrains Mono'; color:#F59E0B;">{str(hs.get('key_exchange_type', 'N/A')).upper()}</span></div>
                                    <div><strong>Forward Secrecy:</strong> {'<span style="color:#10B981; font-weight:700;">✅ PRESENT (PFS)</span>' if hs.get('forward_secrecy') else '<span style="color:#FF3B30; font-weight:700;">❌ NONE (STATIC RSA)</span>'}</div>
                                    <div><strong>Cipher Suite:</strong> <span style="font-family:'JetBrains Mono'; font-size: 0.74rem; color:#FFFFFF;">{hs.get('cipher_suite_negotiated', 'N/A')}</span></div>
                                </div>
                                </div>
                                """, unsafe_allow_html=True)
                            else:
                                st.markdown("""
                                <div style="color: #FF3B30; font-size: 0.88rem; font-weight: 600;">
                                    ⚠️ Plaintext session — no cryptographic handshake was negotiated.
                                </div>
                                </div>
                                """, unsafe_allow_html=True)

                        with sc_3:
                            anom = sess.get("anomaly_score")
                            st.markdown('<div class="sms-glass-container" style="height: 100%;">', unsafe_allow_html=True)
                            st.markdown('<div class="sms-section-header">🧠 Anomaly Detection</div>', unsafe_allow_html=True)
                            if anom:
                                is_anom = anom.get("is_anomalous", False)
                                anom_score = anom.get("score", 0.0)
                                if is_anom:
                                    st.markdown(f"""
                                    <div class="sms-tag-badge critical" style="font-size: 0.85rem; padding: 4px 8px; margin-bottom: 0.4rem;">
                                        ⚠️ UNUSUAL ANOMALY
                                    </div>
                                    <div style="font-size: 0.78rem; color: #94A3B8;">Isolation Forest: <span style="font-family:'JetBrains Mono'; color:#FF6B6B; font-weight:700;">{anom_score:.3f}</span></div>
                                    """, unsafe_allow_html=True)
                                else:
                                    st.markdown(f"""
                                    <div class="sms-tag-badge clean" style="font-size: 0.85rem; padding: 4px 8px; margin-bottom: 0.4rem;">
                                        ✅ NORMAL BEHAVIOR
                                    </div>
                                    <div style="font-size: 0.78rem; color: #94A3B8;">Conformity: <span style="font-family:'JetBrains Mono'; color:#6EE7B7; font-weight:700;">{anom_score:.3f}</span></div>
                                    """, unsafe_allow_html=True)
                                st.caption(f"Baseline: {anom.get('baseline', 'Global Fleet')}")
                            else:
                                st.caption("No anomaly model output.")
                            st.markdown('</div>', unsafe_allow_html=True)

                        st.markdown("<br>", unsafe_allow_html=True)

                        # Tabs for Detailed Dossier
                        t1, t2, t3, t4 = st.tabs([
                            "🔐 TLS Handshake & JA3/JA4",
                            "📜 Certificate Chain Inspector",
                            "⚠️ Posture Findings & Remediation",
                            "📊 AI Risk Attribution (SHAP)",
                        ])

                        with t1:
                            if hs:
                                col_t1, col_t2 = st.columns(2)
                                with col_t1:
                                    st.markdown("##### Handshake Parameters")
                                    st.markdown(f"**Negotiated TLS Version:** `{hs.get('tls_version_negotiated')}`")
                                    st.markdown(f"**Negotiated Cipher Suite:** `{hs.get('cipher_suite_negotiated')}`")
                                    st.markdown(f"**Key Exchange Algorithm:** `{hs.get('key_exchange_type')}`")
                                    st.markdown(f"**Forward Secrecy Support:** {'✅ Present' if hs.get('forward_secrecy') else '❌ None'}")
                                    if hs.get('visibility_limited'):
                                        st.info("ℹ️ **TLS 1.3 Limited Visibility**: Encrypted extensions post-ServerHello are shielded passively by design.")

                                with col_t2:
                                    st.markdown("##### Cryptographic Fingerprints")
                                    if hs.get("ja3"):
                                        st.markdown(f"**JA3 (Client):** `{hs['ja3']}`")
                                    if hs.get("ja3s"):
                                        st.markdown(f"**JA3S (Server):** `{hs['ja3s']}`")
                                    if hs.get("ja4"):
                                        st.markdown(f"**JA4 (Modern):** `{hs['ja4']}`")
                            else:
                                st.info("No TLS Handshake data exists for plaintext traffic.")

                        with t2:
                            certs = sess.get("certificates", [])
                            if not certs:
                                st.info("No X.509 certificates were exchanged (Plaintext / TLS 1.3 Encrypted Handshake).")
                            else:
                                for c in certs:
                                    pos = c.get("chain_position", 0)
                                    is_self = c.get("self_signed", False)
                                    is_v = c.get("chain_valid", True)
                                    subj = c.get("subject", "Unknown")

                                    with st.expander(f"📜 Certificate Node [{pos}] — {subj[:55]}...", expanded=(pos == 0)):
                                        c_a, c_b = st.columns(2)
                                        with c_a:
                                            st.markdown(f"**Subject:** `{c.get('subject')}`")
                                            st.markdown(f"**Issuer:** `{c.get('issuer')}`")
                                            st.markdown(f"**Valid Not Before:** `{c.get('not_before')}`")
                                            st.markdown(f"**Valid Not After:** `{c.get('not_after')}`")
                                        with c_b:
                                            st.markdown(f"**Public Key Algorithm:** `{c.get('public_key_algorithm')} ({c.get('key_length_bits')} bits)`")
                                            st.markdown(f"**Signature Algorithm:** `{c.get('signature_algorithm')}`")
                                            st.markdown(f"**Self-Signed Flag:** {'⚠️ TRUE' if is_self else '✅ No'}")
                                            st.markdown(f"**Chain Validation:** {'✅ VALID' if is_v else '❌ INVALID'}")

                        with t3:
                            findings = sess.get("findings", [])
                            if not findings:
                                st.success("🎉 Pristine Posture: Zero cryptographic weaknesses detected.")
                            else:
                                for f in findings:
                                    sev = f.get("severity", "info").lower()
                                    st.markdown(f"""
                                    <div class="sms-finding-card {sev}">
                                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem;">
                                            <div>
                                                <span class="sms-tag-badge {sev}">{sev.upper()}</span>
                                                <strong style="margin-left: 0.5rem; font-family: 'JetBrains Mono'; font-size: 0.92rem; color: #FFFFFF;">{f.get('rule_id')}</strong>
                                            </div>
                                        </div>
                                        <div style="font-size: 0.88rem; color: #E2E8F0; margin-top: 0.35rem;">
                                            {f.get('message')}
                                        </div>
                                        <div class="sms-remediation-box">
                                            <span>💡</span>
                                            <div><strong>Engineering Remediation:</strong> {f.get('recommendation')}</div>
                                        </div>
                                    </div>
                                    """, unsafe_allow_html=True)

                        with t4:
                            rs = sess.get("risk_score")
                            if rs and rs.get("explanation"):
                                expl = rs["explanation"]
                                if isinstance(expl, str):
                                    try:
                                        expl = json.loads(expl)
                                    except Exception:
                                        expl = {}

                                if isinstance(expl, dict):
                                    st.markdown(f"**Scoring Engine:** `{expl.get('method', 'Rule Weighted + XGBoost Calibration')}`")

                                    contribs = expl.get("contributions", [])
                                    if contribs:
                                        st.markdown("##### Vulnerability Feature Contributions")
                                        c_names = [c["rule_id"] for c in contribs]
                                        c_pcts = [c.get("percentage", 0) for c in contribs]
                                        c_colors = [get_tier_color(c.get("severity", "info")) for c in contribs]

                                        fig_c = go.Figure(go.Bar(
                                            x=c_names,
                                            y=c_pcts,
                                            marker_color=c_colors,
                                            text=[f"{p:.0f}%" for p in c_pcts],
                                            textposition="outside",
                                            textfont=dict(family="JetBrains Mono", size=11, color="#FFFFFF"),
                                        ))
                                        fig_c.update_layout(
                                            paper_bgcolor="rgba(0,0,0,0)",
                                            plot_bgcolor="rgba(15, 22, 38, 0.4)",
                                            xaxis=dict(color="#94A3B8", tickfont=dict(family="JetBrains Mono", size=10)),
                                            yaxis=dict(color="#94A3B8", title="Impact Contribution %", gridcolor="rgba(255, 255, 255, 0.08)"),
                                            height=250,
                                            margin=dict(l=40, r=20, t=20, b=40),
                                        )
                                        st.plotly_chart(fig_c, width='stretch')

                                    shap_vals = expl.get("shap_values", {})
                                    if shap_vals:
                                        st.markdown("##### SHAP Feature Attribution Waterfall")
                                        sorted_shap = sorted(shap_vals.items(), key=lambda x: abs(x[1]), reverse=True)[:8]

                                        fig_s = go.Figure(go.Bar(
                                            y=[s[0] for s in sorted_shap],
                                            x=[s[1] for s in sorted_shap],
                                            orientation="h",
                                            marker_color=["#FF3B30" if v > 0 else "#10B981" for _, v in sorted_shap],
                                        ))
                                        fig_s.update_layout(
                                            paper_bgcolor="rgba(0,0,0,0)",
                                            plot_bgcolor="rgba(15, 22, 38, 0.4)",
                                            xaxis=dict(color="#94A3B8", title="SHAP Impact (Increases / Decreases Risk)", gridcolor="rgba(255, 255, 255, 0.08)"),
                                            yaxis=dict(color="#94A3B8", tickfont=dict(family="JetBrains Mono", size=10)),
                                            height=280,
                                            margin=dict(l=140, r=20, t=20, b=40),
                                        )
                                        st.plotly_chart(fig_s, width='stretch')
                            else:
                                st.info("No AI explanation vector available.")


# ==============================================================================
# VIEW 3: LIVE INGEST & REPLAY
# ==============================================================================

elif st.session_state["nav_page"] == "ingest":
    st.markdown('<div class="sms-section-header">⚡ Passive PCAP Ingest & Attack Scenario Replay</div>', unsafe_allow_html=True)

    c_up, c_sc = st.columns([1.1, 1.2])

    with c_up:
        st.markdown("#### 📁 Upload Custom Packet Capture")
        st.markdown("Ingest network traces (.pcap, .pcapng) with SMTP, IMAP, or POP3 handshakes.")

        up_file = st.file_uploader(
            "Upload PCAP",
            type=["pcap", "pcapng"],
            help="Passive ingestion: zero packet transmission or live connections.",
            label_visibility="collapsed",
        )

        if up_file is not None:
            st.markdown(f"📁 **{up_file.name}** ({up_file.size / 1024:.1f} KB)")

            if st.button("🚀 Analyze Packet Capture", type="primary", width='stretch'):
                with st.spinner("Reassembling TCP streams & parsing handshakes..."):
                    ok, res_id = run_pcap_ingest(up_file.getvalue(), up_file.name)
                    if ok:
                        st.session_state["latest_job_id"] = res_id
                        st.success("✅ Analysis Complete! Cryptographic telemetry ingested.")
                        st.balloons()
                        st.cache_data.clear()
                    else:
                        st.error(f"❌ Ingestion failed: {res_id}")

        st.markdown("---")
        st.markdown("#### 📄 Executive Audit Reports")
        st.caption("Download boardroom-ready compliance audits and forensic reports.")

        job_id = st.session_state.get("latest_job_id", "demo_report")

        rep_1, rep_2, rep_3 = st.columns(3)
        with rep_1:
            st.link_button("📑 PDF Report", f"{API_BASE}/api/reports/{job_id}.pdf", width='stretch')
        with rep_2:
            st.link_button("🌐 HTML Report", f"{API_BASE}/api/reports/{job_id}.html", width='stretch')
        with rep_3:
            st.link_button("📊 JSON Schema", f"{API_BASE}/api/reports/{job_id}.json", width='stretch')

    with c_sc:
        st.markdown("#### 🎯 One-Click Attack Scenarios")
        st.markdown("Instantly evaluate pre-packaged real-world forensic capture scenarios:")

        scenarios = [
            ("🔴 STARTTLS Stripping Attack", "smtp_starttls_stripped.pcap", "Active downgrade attack: STARTTLS advertised in EHLO but stripped from response."),
            ("🟠 Legacy TLS 1.0 + RC4 Cipher", "smtp_tls10_rc4.pcap", "Deprecated TLS protocol negotiation with weak stream cipher suite."),
            ("🟡 Expired Certificate Chain", "smtp_expired_cert.pcap", "Valid handshake with an expired X.509 server certificate."),
            ("🟢 Pristine TLS 1.3 Modern Baseline", "smtp_tls13_good.pcap", "Hardened SMTP configuration with TLS 1.3 and AES-GCM ciphers."),
            ("🟣 Complete Enterprise Multi-Host PCAP", "demo_composite.pcap", "Composite environment with multiple subnets and varied posture configurations."),
        ]

        for title, pcap_fname, desc in scenarios:
            pcap_path = FIXTURES_PCAPS_DIR / pcap_fname
            st.markdown(f"""
            <div class="sms-scenario-card">
                <div style="font-weight: 700; font-size: 0.92rem; color: #FFFFFF;">{title}</div>
                <div style="font-size: 0.78rem; color: #94A3B8; margin: 0.25rem 0 0.5rem 0;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

            if pcap_path.exists():
                if st.button(f"⚡ Ingest {pcap_fname}", key=f"btn_{pcap_fname}", width='stretch'):
                    with st.spinner(f"Ingesting {pcap_fname}..."):
                        pcap_bytes = pcap_path.read_bytes()
                        ok, res_id = run_pcap_ingest(pcap_bytes, pcap_fname)
                        if ok:
                            st.session_state["latest_job_id"] = res_id
                            st.success(f"✅ {title} analyzed successfully!")
                            st.cache_data.clear()
                            st.rerun()


# ==============================================================================
# VIEW 4: RULES & COMPLIANCE
# ==============================================================================

elif st.session_state["nav_page"] == "rules":
    st.markdown('<div class="sms-section-header">📋 Declarative Crypto Weakness Rulebook & Standards</div>', unsafe_allow_html=True)
    st.markdown("All cryptographic findings are evaluated against a declarative YAML rulebook mapped to **NIST SP 800-52r2**, **PCI-DSS v4.0**, and **RFC 8996**.")

    rules_file = ROOT_DIR / "src" / "securemailscope" / "rules" / "ruleset.yaml"
    if rules_file.exists():
        import yaml
        try:
            rules_data = yaml.safe_load(rules_file.read_text()) or []
            r_c1, r_c2 = st.columns([1, 2])

            with r_c1:
                sev_filter = st.selectbox("Filter by Severity", ["All Severities", "critical", "high", "medium", "low"])

            filtered_rules = rules_data
            if sev_filter != "All Severities":
                filtered_rules = [r for r in filtered_rules if r.get("severity") == sev_filter]

            for r in filtered_rules:
                sev = r.get("severity", "info").lower()
                st.markdown(f"""
                <div class="sms-finding-card {sev}">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem;">
                        <div>
                            <span class="sms-tag-badge {sev}">{sev.upper()}</span>
                            <strong style="margin-left: 0.5rem; font-family: 'JetBrains Mono'; font-size: 0.95rem; color: #FFFFFF;">{r.get('id')}</strong>
                        </div>
                        <div style="font-size: 0.75rem; font-family: 'JetBrains Mono'; color: #64748B;">Target: {r.get('applies_to')}</div>
                    </div>
                    <div style="font-size: 0.85rem; color: #E2E8F0; margin-top: 0.35rem;">
                        <strong>Trigger Condition:</strong> <code style="color: #00F0FF;">{r.get('condition')}</code>
                    </div>
                    <div style="font-size: 0.82rem; color: #94A3B8; margin-top: 0.25rem;">
                        {r.get('message')}
                    </div>
                    <div class="sms-remediation-box">
                        <span>🛡️</span>
                        <div><strong>Policy Remediation:</strong> {r.get('recommendation')}</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
        except Exception as e:
            st.error(f"Error loading ruleset: {e}")
