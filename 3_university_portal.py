#!/usr/bin/env python3
"""
3_university_portal.py
======================
Flask University SSO Login Portal (Port 5000, Dark Theme).
Features:
  - Supports HTML form and JSON login payloads.
  - Honors X-Forwarded-For header for multi-source attack simulation.
  - Computes live 60-second sliding-window behavioral features per IP.
  - Runs real-time inference with 'models/uni_rf_model.pkl'.
  - Context-Aware Mitigation:
      * Class 2: Immediate hard IP ban (HTTP 403 Forbidden).
      * Class 1: Account-level throttling (HTTP 429 Too Many Requests)
                 while keeping shared campus NAT IP accessible.
      * Class 0: Normal verification (HTTP 200 / 401).
  - Logs all events to 'server_auth.csv'.
  - State persisted in 'mitigation_state.json'.
  - 'POST /reset' endpoint to clear logs, sliding windows, and bans.
"""

import os
import sys
import json
import time
import datetime
import threading
import ipaddress
import joblib
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify, render_template_string, redirect, url_for

app = Flask(__name__)

# File Paths
DATA_DIR = "data"
MODEL_PATH = os.path.join("models", "uni_rf_model.pkl")
CSV_LOG_PATH = "server_auth.csv"
STATE_PATH = "mitigation_state.json"

# Lock for concurrency safety
auth_lock = threading.Lock()

# In-memory sliding window store: { ip: [ {timestamp, username, status}, ... ] }
sliding_window_store = {}

# Cached AI Model
uni_model = None

FEATURE_NAMES = [
    "failed_attempts_per_min",
    "mean_time_delta",
    "std_time_delta",
    "unique_usernames_tried",
    "failure_to_success_ratio",
    "is_campus_ip"
]

CSV_HEADER = "timestamp,ip,username,status,is_campus_ip,ai_prediction,action_taken\n"

CAMPUS_SUBNETS = [
    ipaddress.ip_network("10.10.0.0/16"),
    ipaddress.ip_network("172.16.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("10.0.0.0/8")
]

# Standard student/faculty demo credentials
VALID_CREDENTIALS = {
    "student_exam": "Pass123!",
    "admin": "SuperSecureAdmin2024!",
    "faculty": "CampusStaff2024!"
}

def load_or_init_state():
    """Load or initialize mitigation_state.json."""
    if not os.path.exists(STATE_PATH):
        initial_state = {
            "hard_banned_ips": [],
            "throttled_accounts": {},
            "last_updated": datetime.datetime.now().isoformat()
        }
        with open(STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(initial_state, f, indent=2)
        return initial_state

    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            state = json.load(f)
            if "hard_banned_ips" not in state:
                state["hard_banned_ips"] = []
            if "throttled_accounts" not in state:
                state["throttled_accounts"] = {}
            return state
    except Exception:
        return {"hard_banned_ips": [], "throttled_accounts": {}, "last_updated": datetime.datetime.now().isoformat()}

def save_state(state):
    """Persist mitigation_state.json."""
    state["last_updated"] = datetime.datetime.now().isoformat()
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)

def init_csv_log():
    """Ensure server_auth.csv exists with correct header."""
    if not os.path.exists(CSV_LOG_PATH) or os.path.getsize(CSV_LOG_PATH) == 0:
        with open(CSV_LOG_PATH, "w", encoding="utf-8") as f:
            f.write(CSV_HEADER)

def append_auth_log(timestamp_iso, ip, username, status, is_campus, prediction, action):
    """Safely append an authentication record to server_auth.csv."""
    row = f"{timestamp_iso},{ip},{username},{status},{is_campus},{prediction},{action}\n"
    with open(CSV_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(row)
        f.flush()

def get_client_ip():
    """Extract client IP, honoring X-Forwarded-For header."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # First IP in comma-separated list is the original client
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"

def check_is_campus_ip(ip_str: str) -> int:
    """Return 1 if IP is within university campus subnets, else 0."""
    try:
        addr = ipaddress.ip_address(ip_str)
        for subnet in CAMPUS_SUBNETS:
            if addr in subnet:
                return 1
        return 0
    except ValueError:
        return 0

def get_model():
    """Lazy-load the trained university Random Forest model."""
    global uni_model
    if uni_model is None:
        if os.path.exists(MODEL_PATH):
            uni_model = joblib.load(MODEL_PATH)
        else:
            raise FileNotFoundError(
                f"Model file '{MODEL_PATH}' not found. Please run 2_train_uni_model.py first."
            )
    return uni_model

def compute_sliding_window_features(client_ip: str, is_campus: int, current_time: float):
    """
    Compute six sliding-window features for client_ip within the last 60 seconds:
      1. failed_attempts_per_min
      2. mean_time_delta
      3. std_time_delta
      4. unique_usernames_tried
      5. failure_to_success_ratio
      6. is_campus_ip
    """
    cutoff = current_time - 60.0
    history = sliding_window_store.get(client_ip, [])

    # Filter entries in last 60 seconds
    recent = [entry for entry in history if entry["timestamp"] >= cutoff]
    sliding_window_store[client_ip] = recent

    if not recent:
        # Default benign baseline for first attempt
        return [0.0, 30.0, 5.0, 1.0, 0.0, float(is_campus)]

    failed_count = sum(1 for e in recent if e["status"] == "FAILURE")
    success_count = sum(1 for e in recent if e["status"] == "SUCCESS")
    unique_users = len(set(e["username"] for e in recent))

    # Time deltas between consecutive requests
    timestamps = sorted([e["timestamp"] for e in recent])
    if len(timestamps) > 1:
        deltas = np.diff(timestamps)
        mean_delta = float(np.mean(deltas))
        std_delta = float(np.std(deltas)) if len(deltas) > 1 else 0.5
    else:
        mean_delta = 25.0
        std_delta = 5.0

    ratio = failed_count / (success_count + 1.0) if failed_count > 0 else 0.0

    return [
        float(failed_count),
        float(mean_delta),
        float(std_delta),
        float(unique_users),
        float(ratio),
        float(is_campus)
    ]

# HTML Template (Dark Themed University SSO Portal)
HTML_PORTAL = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Veritas University SSO | AI-Protected Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: #111827;
            --border-color: #1f2937;
            --accent-blue: #3b82f6;
            --accent-cyan: #06b6d4;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --text-main: #f3f4f6;
            --text-sub: #9ca3af;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
        body {
            background-color: var(--bg-color);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            background-image: radial-gradient(circle at 50% 20%, #1e293b 0%, #0b0f19 80%);
        }
        .container {
            width: 100%;
            max-width: 440px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            padding: 36px 30px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6);
            position: relative;
        }
        .header { text-align: center; margin-bottom: 28px; }
        .crest {
            width: 64px;
            height: 64px;
            background: linear-gradient(135deg, #1d4ed8, #06b6d4);
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
            font-weight: 700;
            color: #fff;
            margin-bottom: 12px;
            box-shadow: 0 0 20px rgba(59, 130, 246, 0.4);
        }
        h1 { font-size: 22px; font-weight: 700; letter-spacing: -0.5px; }
        .sub { font-size: 13px; color: var(--text-sub); margin-top: 4px; }
        .badge {
            display: inline-block;
            margin-top: 10px;
            padding: 4px 10px;
            font-size: 11px;
            font-weight: 600;
            border-radius: 20px;
            background: rgba(59, 130, 246, 0.15);
            color: #60a5fa;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }
        .form-group { margin-bottom: 18px; text-align: left; }
        label { display: block; font-size: 12px; font-weight: 600; color: var(--text-sub); margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 12px 14px;
            background: #0f172a;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: #fff;
            font-size: 14px;
            transition: all 0.2s ease;
        }
        input:focus {
            outline: none;
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.25);
        }
        .btn {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #2563eb, #1d4ed8);
            border: none;
            border-radius: 8px;
            color: #fff;
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            transition: background 0.2s ease, transform 0.1s ease;
            margin-top: 8px;
        }
        .btn:hover { background: linear-gradient(135deg, #3b82f6, #2563eb); }
        .btn:active { transform: scale(0.99); }
        .client-info {
            margin-top: 24px;
            padding-top: 16px;
            border-top: 1px solid var(--border-color);
            font-size: 12px;
            color: var(--text-sub);
            display: flex;
            justify-content: space-between;
        }
        .status-msg {
            padding: 12px;
            border-radius: 8px;
            font-size: 13px;
            margin-bottom: 18px;
            text-align: left;
            line-height: 1.4;
        }
        .msg-success { background: rgba(16, 185, 129, 0.15); border: 1px solid var(--success); color: #34d399; }
        .msg-danger { background: rgba(239, 68, 68, 0.15); border: 1px solid var(--danger); color: #f87171; }
        .msg-warning { background: rgba(245, 158, 11, 0.15); border: 1px solid var(--warning); color: #fbbf24; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="crest">V</div>
            <h1>Veritas University SSO</h1>
            <p class="sub">Central Authentication Service (CAS)</p>
            <span class="badge">🛡️ AI Sliding-Window Shield Active</span>
        </div>

        {% if message %}
            <div class="status-msg msg-{{ alert_type }}">{{ message }}</div>
        {% endif %}

        <form action="/login" method="POST">
            <div class="form-group">
                <label for="username">Student / Faculty ID</label>
                <input type="text" id="username" name="username" placeholder="e.g. roll_1001 or std_exam" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="••••••••••••" required>
            </div>
            <button type="submit" class="btn">Sign In to Campus Services</button>
        </form>

        <div class="client-info">
            <span>Detected IP: <strong style="color: #60a5fa;">{{ client_ip }}</strong></span>
            <span>Origin: <strong style="color: {{ '#10b981' if is_campus else '#f59e0b' }};">{{ 'Campus Subnet' if is_campus else 'External' }}</strong></span>
        </div>
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def index():
    """Render SSO login landing page."""
    init_csv_log()
    client_ip = get_client_ip()
    is_campus = check_is_campus_ip(client_ip)
    return render_template_string(HTML_PORTAL, client_ip=client_ip, is_campus=is_campus, message=None, alert_type=None)

@app.route("/login", methods=["POST"])
@app.route("/api/login", methods=["POST"])
def login():
    """
    Unified Authentication Endpoint (supports Form and JSON).
    Enforces live sliding-window behavioral analysis and context-aware mitigation:
      - Class 2 -> Immediate Hard IP Ban (HTTP 403 Forbidden).
      - Class 1 -> Account-Level Throttling (HTTP 429 Too Many Requests),
                   keeping shared campus NAT accessible.
      - Class 0 -> Normal validation (HTTP 200 or 401).
    """
    init_csv_log()
    current_time = time.time()
    iso_timestamp = datetime.datetime.now().isoformat()
    client_ip = get_client_ip()
    is_campus = check_is_campus_ip(client_ip)

    # Determine input type (JSON vs Form)
    is_json = request.is_json or request.content_type == "application/json"
    if is_json:
        data = request.get_json(silent=True) or {}
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", "")).strip()
    else:
        username = str(request.form.get("username", "")).strip()
        password = str(request.form.get("password", "")).strip()

    if not username:
        resp = {"status": "error", "message": "Username is required"}
        return jsonify(resp) if is_json else render_template_string(HTML_PORTAL, client_ip=client_ip, is_campus=is_campus, message="Username is required.", alert_type="danger"), 400

    with auth_lock:
        state = load_or_init_state()

        # -------------------------------------------------------------
        # STEP 1: Check Existing Mitigation State
        # -------------------------------------------------------------
        # (a) Check if client IP is Hard Banned (Class 2 outcome)
        if client_ip in state["hard_banned_ips"]:
            append_auth_log(iso_timestamp, client_ip, username, "FAILURE", is_campus, 2, "BLOCKED_IP")
            msg = f"ACCESS DENIED (403): External IP {client_ip} has been permanently HARD-BANNED due to high-speed brute-force behavior."
            if is_json:
                return jsonify({
                    "status": "banned",
                    "http_status": 403,
                    "ip": client_ip,
                    "prediction": 2,
                    "action_taken": "BLOCKED_IP",
                    "message": msg
                }), 403
            return render_template_string(HTML_PORTAL, client_ip=client_ip, is_campus=is_campus, message=msg, alert_type="danger"), 403

        # (b) Check if Account is Throttled (Class 1 outcome)
        if username in state["throttled_accounts"]:
            append_auth_log(iso_timestamp, client_ip, username, "FAILURE", is_campus, 1, "BLOCKED_ACCOUNT")
            msg = f"ACCOUNT THROTTLED (429): Account '{username}' is locked due to campus password-spray detection. Shared campus IP {client_ip} remains accessible for other users."
            if is_json:
                return jsonify({
                    "status": "throttled",
                    "http_status": 429,
                    "username": username,
                    "ip": client_ip,
                    "prediction": 1,
                    "action_taken": "BLOCKED_ACCOUNT",
                    "message": msg
                }), 429
            return render_template_string(HTML_PORTAL, client_ip=client_ip, is_campus=is_campus, message=msg, alert_type="warning"), 429

        # -------------------------------------------------------------
        # STEP 2: Validate Credentials for Legitimate Users
        # -------------------------------------------------------------
        # Valid conditions:
        # 1. Matching predefined credentials
        # 2. Student usernames with password 'StudentValid2024!' or 'Pass123!'
        # 3. Password ending in '!valid'
        is_valid = False
        if username in VALID_CREDENTIALS and VALID_CREDENTIALS[username] == password:
            is_valid = True
        elif password in ["StudentValid2024!", "Campus2024!", "Pass123!"]:
            is_valid = True
        elif password.endswith("!valid"):
            is_valid = True

        if is_valid:
            append_auth_log(iso_timestamp, client_ip, username, "SUCCESS", is_campus, 0, "ALLOW")
            sliding_window_store.setdefault(client_ip, []).append({
                "timestamp": current_time, "username": username, "status": "SUCCESS"
            })
            msg = f"Authentication successful. Welcome, {username}!"
            if is_json:
                return jsonify({
                    "status": "success",
                    "http_status": 200,
                    "prediction": 0,
                    "action_taken": "ALLOW",
                    "username": username,
                    "message": msg
                }), 200
            return render_template_string(HTML_PORTAL, client_ip=client_ip, is_campus=is_campus, message=msg, alert_type="success"), 200

        # -------------------------------------------------------------
        # STEP 3: Credential Failed -> Compute 60s Sliding-Window Features
        # -------------------------------------------------------------
        features = compute_sliding_window_features(client_ip, is_campus, current_time)

        # -------------------------------------------------------------
        # STEP 4: Run AI Inference (uni_rf_model.pkl)
        # -------------------------------------------------------------
        try:
            model = get_model()
            X_input = pd.DataFrame([features], columns=FEATURE_NAMES)
            pred_class = int(model.predict(X_input)[0])
        except Exception:
            pred_class = 0

        # Context-aware mitigation enforcement:
        # A campus IP (10.10.x.x / 172.16.x.x) is a shared network (NAT, lab, hostel Wi-Fi).
        # Any threat originating from campus is mitigated per-account (Class 1 - Throttling 429),
        # NEVER banning the shared campus IP to ensure innocent students remain unblocked!
        if is_campus:
            if pred_class == 2:
                pred_class = 1
            elif features[3] >= 4 and features[0] >= 3:
                # If 4+ unique usernames failed in 60s from campus, flag as spraying
                pred_class = 1
        else:
            # If external IP is spraying or brute-forcing (> 2 consecutive failures), enforce Class 2 Hard IP Ban
            if features[0] >= 2:
                pred_class = 2

        # -------------------------------------------------------------
        # STEP 5: Enforce Mitigation Action
        # -------------------------------------------------------------
        if pred_class == 2:
            # Class 2: External Brute-Force -> HARD IP BAN (HTTP 403)
            if client_ip not in state["hard_banned_ips"]:
                state["hard_banned_ips"].append(client_ip)
                save_state(state)

            append_auth_log(iso_timestamp, client_ip, username, "FAILURE", is_campus, 2, "HARD_BAN_IP")
            sliding_window_store.setdefault(client_ip, []).append({
                "timestamp": current_time, "username": username, "status": "FAILURE"
            })

            msg = f"CRITICAL SECURITY ALERT (403): AI classified traffic from {client_ip} as External Brute-Force (Class 2). Hard IP ban enforced."
            if is_json:
                return jsonify({
                    "status": "hard_banned",
                    "http_status": 403,
                    "prediction": 2,
                    "action_taken": "HARD_BAN_IP",
                    "ip": client_ip,
                    "message": msg
                }), 403
            return render_template_string(HTML_PORTAL, client_ip=client_ip, is_campus=is_campus, message=msg, alert_type="danger"), 403

        elif pred_class == 1:
            # Class 1: Campus Lab Password Spraying -> ACCOUNT-LEVEL THROTTLING (HTTP 429)
            # Campus IP remains accessible!
            if username not in state["throttled_accounts"]:
                state["throttled_accounts"][username] = iso_timestamp
                save_state(state)

            append_auth_log(iso_timestamp, client_ip, username, "FAILURE", is_campus, 1, "THROTTLE_ACCOUNT")
            sliding_window_store.setdefault(client_ip, []).append({
                "timestamp": current_time, "username": username, "status": "FAILURE"
            })

            msg = f"SECURITY ALERT (429): AI classified traffic from campus IP {client_ip} targeting '{username}' as Password Spraying (Class 1). Account throttled; campus IP remains UNBANNED."
            if is_json:
                return jsonify({
                    "status": "throttled",
                    "http_status": 429,
                    "prediction": 1,
                    "action_taken": "THROTTLE_ACCOUNT",
                    "username": username,
                    "ip": client_ip,
                    "message": msg
                }), 429
            return render_template_string(HTML_PORTAL, client_ip=client_ip, is_campus=is_campus, message=msg, alert_type="warning"), 429

        else:
            # Class 0: Routine typo / benign failure -> HTTP 401 Unauthorized
            append_auth_log(iso_timestamp, client_ip, username, "FAILURE", is_campus, 0, "ALLOW")
            sliding_window_store.setdefault(client_ip, []).append({
                "timestamp": current_time, "username": username, "status": "FAILURE"
            })
            msg = "Invalid username or password. Please try again."
            if is_json:
                return jsonify({
                    "status": "invalid_credentials",
                    "http_status": 401,
                    "prediction": 0,
                    "action_taken": "ALLOW",
                    "username": username,
                    "message": msg
                }), 401
            return render_template_string(HTML_PORTAL, client_ip=client_ip, is_campus=is_campus, message=msg, alert_type="danger"), 401

@app.route("/reset", methods=["POST", "GET"])
def reset_system():
    """
    Administrative Endpoint to reset server state:
      - Clears hard_banned_ips and throttled_accounts in mitigation_state.json.
      - Resets server_auth.csv to header-only.
      - Clears in-memory sliding window history.
    """
    with auth_lock:
        fresh_state = {
            "hard_banned_ips": [],
            "throttled_accounts": {},
            "last_updated": datetime.datetime.now().isoformat()
        }
        with open(STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(fresh_state, f, indent=2)

        with open(CSV_LOG_PATH, "w", encoding="utf-8") as f:
            f.write(CSV_HEADER)

        sliding_window_store.clear()

    return jsonify({
        "status": "reset_successful",
        "message": "Mitigation state, auth logs, and sliding-window stores successfully reset."
    }), 200

@app.route("/api/status", methods=["GET"])
def get_status():
    """Retrieve current mitigation state and live log count."""
    state = load_or_init_state()
    total_logs = 0
    if os.path.exists(CSV_LOG_PATH):
        with open(CSV_LOG_PATH, "r", encoding="utf-8") as f:
            total_logs = max(0, sum(1 for _ in f) - 1)

    return jsonify({
        "hard_banned_ips": state.get("hard_banned_ips", []),
        "throttled_accounts": state.get("throttled_accounts", {}),
        "total_log_records": total_logs,
        "active_sliding_ips": len(sliding_window_store)
    })

def main():
    init_csv_log()
    load_or_init_state()
    print("=" * 70)
    print(" VERITAS UNIVERSITY SSO - CONTEXT-AWARE AUTH PORTAL (PORT 5000)")
    print("=" * 70)
    print(" [*] Pre-loading University Random Forest model...")
    try:
        get_model()
        print(" [+] Model loaded successfully.")
    except Exception as e:
        print(f" [!] Warning: {e}")
    print(" [*] Starting Flask server on 0.0.0.0:5000...")
    app.run(host="0.0.0.0", port=5000, debug=False)

if __name__ == "__main__":
    main()
