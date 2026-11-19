#!/usr/bin/env python3
"""
4_dashboard.py
==============
Live auto-refreshing Streamlit SOC (Security Operations Center) Dashboard for
Veritas University Context-Aware Brute-Force Defense System.

Features:
  - KPI Metric Cards (Total Attempts, Failed Attempts, Hard-Banned IPs, Throttled Accounts)
  - Active Mitigation JSON & Health Status Panels
  - Interactive Visualizations (Traffic Origin, Threat Class Breakdown, Actions Taken)
  - Live Reverse-Chronological Log Table with Badges
  - One-Click Reset Button communicating with Flask /reset endpoint
"""

import os
import sys
import subprocess
import tempfile
os.environ.setdefault("MPLCONFIGDIR", os.path.join(tempfile.gettempdir(), "matplotlib"))

import json
import time
import datetime
import requests
import pandas as pd
import streamlit as st

# Page Configuration
st.set_page_config(
    page_title="Veritas SOC | Context-Aware Defense",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Dark Theme CSS
st.markdown("""
<style>
    .reportview-container {
        background: #0b0f19;
    }
    .main-header {
        font-size: 26px;
        font-weight: 700;
        color: #f3f4f6;
        margin-bottom: 2px;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .sub-header {
        font-size: 13px;
        color: #9ca3af;
        margin-bottom: 20px;
    }
    .kpi-card {
        background: #111827;
        border: 1px solid #1f2937;
        border-radius: 10px;
        padding: 16px 20px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.4);
    }
    .kpi-title {
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        color: #9ca3af;
        letter-spacing: 0.5px;
    }
    .kpi-value {
        font-size: 28px;
        font-weight: 700;
        margin-top: 6px;
    }
    .status-pill {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 11px;
        font-weight: 600;
    }
    .pill-green { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
    .pill-red { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
    .pill-amber { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }
    .pill-blue { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }
</style>
""", unsafe_allow_html=True)

CSV_LOG_PATH = "server_auth.csv"
STATE_PATH = "mitigation_state.json"
PORTAL_URL = "http://127.0.0.1:5000"

def load_data():
    """Load logs from server_auth.csv safely."""
    if not os.path.exists(CSV_LOG_PATH) or os.path.getsize(CSV_LOG_PATH) == 0:
        return pd.DataFrame(columns=["timestamp", "ip", "username", "status", "is_campus_ip", "ai_prediction", "action_taken"])
    try:
        df = pd.read_csv(CSV_LOG_PATH)
        return df
    except Exception:
        return pd.DataFrame(columns=["timestamp", "ip", "username", "status", "is_campus_ip", "ai_prediction", "action_taken"])

def load_state():
    """Load mitigation state safely."""
    if not os.path.exists(STATE_PATH):
        return {"hard_banned_ips": [], "throttled_accounts": {}, "last_updated": ""}
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"hard_banned_ips": [], "throttled_accounts": {}, "last_updated": ""}

def trigger_reset():
    """Call the Flask reset endpoint or directly reset files."""
    try:
        resp = requests.post(f"{PORTAL_URL}/reset", timeout=2.0)
        if resp.status_code == 200:
            return True, "Successfully reset via Portal API."
    except Exception:
        pass

    # Direct fallback reset
    try:
        with open(STATE_PATH, "w", encoding="utf-8") as f:
            json.dump({
                "hard_banned_ips": [],
                "throttled_accounts": {},
                "last_updated": datetime.datetime.now().isoformat()
            }, f, indent=2)
        with open(CSV_LOG_PATH, "w", encoding="utf-8") as f:
            f.write("timestamp,ip,username,status,is_campus_ip,ai_prediction,action_taken\n")
        return True, "Successfully reset via local storage fallback."
    except Exception as e:
        return False, f"Reset failed: {e}"

# --- Sidebar Controls ---
st.sidebar.markdown("### ⚙️ SOC Controls")
auto_refresh = st.sidebar.checkbox("Auto-Refresh (3s)", value=True)
refresh_rate = st.sidebar.slider("Refresh Interval (seconds)", min_value=1, max_value=10, value=3)

if st.sidebar.button("🔄 Refresh Data Now", use_container_width=True):
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown("""
**Threat Classification Reference:**
- **Class 0**: Normal Logins & Hostel NAT Exam Rush (*Campus Safe*)
- **Class 1**: Campus Password Spraying (*Account Throttled - 429*)
- **Class 2**: External Brute-Force Attack (*Hard IP Ban - 403*)
""")

# --- Main Layout ---
st.markdown("""
<div class="main-header">
    🛡️ Veritas University | AI-Based Security Operations Center (SOC)
</div>
""", unsafe_allow_html=True)
st.caption("Real-time 60-second sliding-window behavioral intelligence & context-aware mitigation monitoring")

# --- Live Presentation Simulator Control Bar ---
st.markdown("##### 🎮 Live Presentation Simulator Controls")
ctrl_col1, ctrl_col2, ctrl_col3, ctrl_col4 = st.columns(4)

base_dir = os.path.dirname(os.path.abspath(__file__))
sim_script = os.path.join(base_dir, "5_attack_simulator.py")

with ctrl_col1:
    if st.button("1️⃣ Hostel Exam Rush (NAT Safe)", use_container_width=True):
        subprocess.Popen([sys.executable, sim_script, "--scenario", "1"], cwd=base_dir)
        st.toast("🚀 Scenario 1: Hostel Exam Rush launched! Watch incoming campus telemetry.", icon="🏫")

with ctrl_col2:
    if st.button("2️⃣ Lab Password Spraying", use_container_width=True):
        subprocess.Popen([sys.executable, sim_script, "--scenario", "2"], cwd=base_dir)
        st.toast("⚠️ Scenario 2: Lab Password Spraying launched! Monitoring account throttles.", icon="🔒")

with ctrl_col3:
    if st.button("3️⃣ External Brute-Force", use_container_width=True):
        subprocess.Popen([sys.executable, sim_script, "--scenario", "3"], cwd=base_dir)
        st.toast("🚨 Scenario 3: External Brute-Force launched! Watch for hard IP bans.", icon="🛡️")

with ctrl_col4:
    if st.button("🔄 Reset System & Logs", use_container_width=True, type="primary"):
        subprocess.Popen([sys.executable, sim_script, "--scenario", "reset"], cwd=base_dir)
        trigger_reset()
        st.toast("🧹 Reset triggered! Clearing active bans, throttles, and logs.", icon="🔄")
        time.sleep(0.5)
        st.rerun()

st.markdown("<br>", unsafe_allow_html=True)

df_logs = load_data()
mitigation = load_state()

total_attempts = len(df_logs)
failed_attempts = len(df_logs[df_logs["status"] == "FAILURE"]) if total_attempts > 0 else 0
fail_rate = (failed_attempts / total_attempts * 100) if total_attempts > 0 else 0.0

hard_banned_ips = mitigation.get("hard_banned_ips", [])
throttled_accounts = mitigation.get("throttled_accounts", {})

# --- KPI Cards Row ---
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Total Logins Monitored</div>
        <div class="kpi-value" style="color: #60a5fa;">{total_attempts:,}</div>
        <div style="font-size: 11px; color: #9ca3af; margin-top: 4px;">Live authentication telemetry</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Failed Attempts</div>
        <div class="kpi-value" style="color: {'#ef4444' if fail_rate > 30 else '#f59e0b'};">{failed_attempts:,} <span style="font-size: 15px; font-weight: normal;">({fail_rate:.1f}%)</span></div>
        <div style="font-size: 11px; color: #9ca3af; margin-top: 4px;">Rejected / invalid credentials</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Hard-Banned External IPs</div>
        <div class="kpi-value" style="color: #ef4444;">{len(hard_banned_ips)}</div>
        <div style="font-size: 11px; color: #9ca3af; margin-top: 4px;">Enforced with HTTP 403 Forbidden</div>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Throttled Campus Accounts</div>
        <div class="kpi-value" style="color: #f59e0b;">{len(throttled_accounts)}</div>
        <div style="font-size: 11px; color: #9ca3af; margin-top: 4px;">Enforced with HTTP 429 (IP unbanned)</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# --- Active Mitigation Panels Row ---
left_panel, right_panel = st.columns([1, 1])

with left_panel:
    st.markdown("#### 🚫 Active Mitigation State (`mitigation_state.json`)")
    with st.container(border=True):
        st.json({
            "hard_banned_ips": hard_banned_ips,
            "throttled_accounts": throttled_accounts,
            "last_updated": mitigation.get("last_updated", "N/A")
        })

with right_panel:
    st.markdown("#### 🌐 Campus NAT & Gateway Health Status")
    with st.container(border=True):
        if len(hard_banned_ips) == 0 and len(throttled_accounts) == 0:
            st.success("✅ **Normal Campus State**: No active perimeter threats detected. Campus Wi-Fi & NAT subnets fully clear.")
        else:
            if len(hard_banned_ips) > 0:
                st.error(f"⚠️ **Perimeter Defenses Engaged**: {len(hard_banned_ips)} External IP(s) isolated from network.")
            if len(throttled_accounts) > 0:
                st.warning(f"🔒 **Targeted Spray Defense**: {len(throttled_accounts)} Student account(s) throttled. Shared Campus NAT IP remained 100% ACCESSIBLE to other students!")
        
        st.info("💡 **Zero-False-Positive Guarantee**: Shared hostel NAT traffic (Class 0) retains full throughput even during massive exam rush concurrency.")

# --- Analytics and Charts ---
st.markdown("---")
st.markdown("#### 📊 Threat Analytics & Behavioral Distributions")

chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    if total_attempts > 0 and "is_campus_ip" in df_logs.columns:
        origin_counts = df_logs["is_campus_ip"].value_counts().rename(index={1: "Campus Subnet (10.10.x / 172.16.x)", 0: "External Internet"})
        st.write("**Traffic Origin Distribution**")
        st.bar_chart(origin_counts, color="#3b82f6")
    else:
        st.write("Awaiting authentication traffic for origin chart...")

with chart_col2:
    if total_attempts > 0 and "action_taken" in df_logs.columns:
        action_counts = df_logs["action_taken"].value_counts()
        st.write("**Context-Aware Actions Enforced**")
        st.bar_chart(action_counts, color="#10b981")
    else:
        st.write("Awaiting authentication traffic for actions chart...")

# --- Live Log Table ---
st.markdown("---")
st.markdown(f"#### 📜 Live Security Event Feed (Latest {min(total_attempts, 50)} Events)")

if total_attempts > 0:
    display_df = df_logs.tail(50).iloc[::-1].copy()

    def color_action(val):
        val = str(val)
        if val == "HARD_BAN_IP" or val == "BLOCKED_IP":
            return "color: #ef4444; font-weight: bold;"
        elif val == "THROTTLE_ACCOUNT" or val == "BLOCKED_ACCOUNT":
            return "color: #f59e0b; font-weight: bold;"
        elif val == "ALLOW":
            return "color: #34d399;"
        return ""

    def color_status(val):
        val = str(val)
        if val == "SUCCESS":
            return "color: #34d399; font-weight: bold;"
        elif val == "FAILURE":
            return "color: #ef4444;"
        return ""

    styled_df = display_df.style.map(color_action, subset=["action_taken"]).map(color_status, subset=["status"])
    st.dataframe(styled_df, use_container_width=True, height=350)
else:
    st.info("No login attempts recorded yet. Run `5_attack_simulator.py` or attempt logins on the portal to generate live traffic.")

# Feature Importance Chart Section
if os.path.exists("models/uni_feature_importance.png"):
    with st.expander("🔍 View AI Model Feature Importance & Architecture Details"):
        st.image("models/uni_feature_importance.png", caption="120-Tree Random Forest Sliding-Window Feature Importance", use_container_width=True)

# Auto-refresh loop
if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()
