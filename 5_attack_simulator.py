#!/usr/bin/env python3
"""
5_attack_simulator.py
=====================
Interactive CLI Attack Simulator for Veritas University Auth System.

Simulates three distinct real-world traffic scenarios:
  1. Shared Hostel NAT Exam Rush (10.10.45.12)
     -> High concurrency, diverse student usernames, high success rate.
     -> Proves ZERO FALSE POSITIVES (No IP bans, no throttling).
  2. Campus Lab Password Spraying (10.10.88.5)
     -> Paced attacks across sequential student roll numbers.
     -> Triggers Account-Level Throttling (HTTP 429), leaving shared campus IP accessible.
  3. External High-Speed Brute-Force Attack (185.220.101.44)
     -> Rapid automated dictionary attacks against single target.
     -> Triggers Immediate Hard IP Ban (HTTP 403 Forbidden).
"""

import sys
import time
import argparse
import requests
import importlib

# Terminal Colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

DEFAULT_BASE_URL = "http://127.0.0.1:5000"
_direct_client = None

def get_direct_client():
    """Lazily initialize direct WSGI test client if HTTP connection is unavailable."""
    global _direct_client
    if _direct_client is None:
        try:
            portal_module = importlib.import_module("3_university_portal")
            _direct_client = portal_module.app.test_client()
        except Exception as e:
            print(Colors.RED + f"[-] Error loading portal application: {e}" + Colors.RESET)
    return _direct_client

def print_header(title: str):
    print("\n" + Colors.BOLD + Colors.CYAN + "=" * 80 + Colors.RESET)
    print(Colors.BOLD + Colors.CYAN + f"  {title.upper()}" + Colors.RESET)
    print(Colors.BOLD + Colors.CYAN + "=" * 80 + Colors.RESET)

def send_login_request(base_url: str, ip: str, username: str, password: str):
    """
    Send an authentication attempt honoring X-Forwarded-For.
    Attempts HTTP socket first; if unavailable or restricted by sandbox permissions,
    transparently falls back to Flask WSGI client.
    """
    global _direct_client
    url = f"{base_url}/api/login"
    payload = {"username": username, "password": password}
    headers = {"X-Forwarded-For": ip, "Content-Type": "application/json"}

    t0 = time.time()

    # If direct client was already engaged, use it directly
    if _direct_client is not None:
        res = _direct_client.post("/api/login", json=payload, headers=headers)
        elapsed = (time.time() - t0) * 1000
        data = res.get_json(silent=True) or {}
        return res.status_code, data, elapsed

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=3.0)
        elapsed = (time.time() - t0) * 1000
        try:
            data = resp.json()
        except Exception:
            data = {"message": resp.text[:100]}
        return resp.status_code, data, elapsed
    except (requests.exceptions.ConnectionError, OSError):
        # Fall back to in-process WSGI client
        client = get_direct_client()
        if client is not None:
            res = client.post("/api/login", json=payload, headers=headers)
            elapsed = (time.time() - t0) * 1000
            data = res.get_json(silent=True) or {}
            return res.status_code, data, elapsed
        else:
            print(Colors.RED + f"[-] Could not connect to {base_url} and could not initialize WSGI client." + Colors.RESET)
            sys.exit(1)

def check_server_health(base_url: str):
    """Check if the university portal is online via HTTP or direct WSGI."""
    try:
        r = requests.get(base_url, timeout=2.0)
        if r.status_code == 200:
            return True, "HTTP Socket Active"
    except Exception:
        pass

    client = get_direct_client()
    if client is not None:
        return True, "Direct WSGI Client Active (Sandboxed/In-Process)"
    return False, "Offline"

def reset_server(base_url: str):
    """Trigger system reset on the portal."""
    global _direct_client
    if _direct_client is not None:
        res = _direct_client.post("/reset")
        if res.status_code == 200:
            print(Colors.GREEN + "[+] System reset successful (cleared logs, sliding windows, and bans)." + Colors.RESET)
            return True

    try:
        r = requests.post(f"{base_url}/reset", timeout=3.0)
        if r.status_code == 200:
            print(Colors.GREEN + "[+] System reset successful (cleared logs, sliding windows, and bans)." + Colors.RESET)
            return True
    except Exception:
        client = get_direct_client()
        if client is not None:
            res = client.post("/reset")
            if res.status_code == 200:
                print(Colors.GREEN + "[+] System reset successful via WSGI client." + Colors.RESET)
                return True
    return False

# ---------------------------------------------------------------------------
# SCENARIO 1: Shared Hostel NAT Exam Rush
# ---------------------------------------------------------------------------
def run_scenario_1(base_url: str):
    print_header("Scenario 1: Shared Hostel NAT Exam Rush (10.10.45.12)")
    print(Colors.BOLD + "Context:" + Colors.RESET + " 40 students behind a single campus hostel NAT gateway")
    print("logging in concurrently for an online exam. High concurrent successes.")
    print(Colors.YELLOW + "Objective: Verify ZERO FALSE POSITIVES (IP 10.10.45.12 is NEVER banned)." + Colors.RESET + "\n")

    hostel_ip = "10.10.45.12"
    total_students = 35
    success_count = 0
    fail_count = 0
    banned_count = 0
    throttled_count = 0

    for i in range(1, total_students + 1):
        username = f"std_hostel_2024_{i:03d}"
        # 90%+ know their password; a few make a typo
        if i in [7, 21, 33]:
            password = "TypoPassword123"  # Typo
        else:
            password = "StudentValid2024!"  # Correct

        status, data, latency = send_login_request(base_url, hostel_ip, username, password)
        action = data.get("action_taken", "UNKNOWN")

        if status == 200:
            success_count += 1
            status_badge = Colors.GREEN + f"[200 OK] {action}" + Colors.RESET
        elif status == 401:
            fail_count += 1
            status_badge = Colors.YELLOW + f"[401 UNAUTH] {action} (Typo)" + Colors.RESET
        elif status == 403:
            banned_count += 1
            status_badge = Colors.RED + f"[403 BANNED] {action}" + Colors.RESET
        elif status == 429:
            throttled_count += 1
            status_badge = Colors.YELLOW + f"[429 THROTTLED] {action}" + Colors.RESET
        else:
            status_badge = f"[{status}]"

        print(f" Student {i:02d}/{total_students} | IP: {hostel_ip} | User: {username:<22} -> {status_badge} ({latency:.1f}ms)")
        time.sleep(0.04)

    print("\n" + Colors.BOLD + "--- Scenario 1 Results ---" + Colors.RESET)
    print(f"Total Requests: {total_students} | Successes: {success_count} | Typos (401): {fail_count}")
    print(f"IP Bans (403): {banned_count} | Throttles (429): {throttled_count}")

    if banned_count == 0 and throttled_count == 0:
        print(Colors.BOLD + Colors.GREEN + "[VERIFIED] SUCCESS: Zero false positives! Shared hostel NAT IP was protected and remained unbanned." + Colors.RESET)
        return True
    else:
        print(Colors.BOLD + Colors.RED + "[FAILED] False positives occurred! Campus IP or students were banned." + Colors.RESET)
        return False

# ---------------------------------------------------------------------------
# SCENARIO 2: Campus Lab Password Spraying
# ---------------------------------------------------------------------------
def run_scenario_2(base_url: str):
    print_header("Scenario 2: Campus Lab Password Spraying (10.10.88.5)")
    print(Colors.BOLD + "Context:" + Colors.RESET + " Attacker on a university computer lab PC spraying a single")
    print("password ('Winter2024!') across sequential student roll numbers.")
    print(Colors.YELLOW + "Objective: Trigger Account Throttling (HTTP 429) while keeping campus IP unbanned." + Colors.RESET + "\n")

    lab_ip = "10.10.88.5"
    sprayed_password = "Winter2024!"
    throttled_accounts = []

    print("[*] Launching sequential roll number spray from campus PC...")
    for i in range(1, 26):
        roll_user = f"roll_2024_{1000 + i}"
        status, data, latency = send_login_request(base_url, lab_ip, roll_user, sprayed_password)
        action = data.get("action_taken", "UNKNOWN")

        if status == 429:
            throttled_accounts.append(roll_user)
            badge = Colors.YELLOW + f"[429 THROTTLED] {action}" + Colors.RESET
        elif status == 401:
            badge = Colors.DIM + f"[401 REJECTED] {action}" + Colors.RESET
        elif status == 403:
            badge = Colors.RED + f"[403 HARD BAN] {action}" + Colors.RESET
        else:
            badge = f"[{status}]"

        print(f" Attempt {i:02d}/25 | Target: {roll_user:<16} | Status: {badge} ({latency:.1f}ms)")
        time.sleep(0.06)

    print("\n[*] CRITICAL TEST: Verifying innocent student on the SAME campus lab IP (10.10.88.5)...")
    innocent_user = "innocent_student_lab"
    status_innocent, data_innocent, lat_innocent = send_login_request(
        base_url, lab_ip, innocent_user, "StudentValid2024!"
    )

    print(f" Innocent Student Login | User: {innocent_user} | IP: {lab_ip}")
    print(f" Status: {status_innocent} | Action: {data_innocent.get('action_taken')} | Message: {data_innocent.get('message')}")

    print("\n" + Colors.BOLD + "--- Scenario 2 Results ---" + Colors.RESET)
    print(f"Accounts Throttled: {len(throttled_accounts)}")
    if status_innocent == 200 and len(throttled_accounts) > 0:
        print(Colors.BOLD + Colors.GREEN + "[VERIFIED] SUCCESS: Password spray was throttled per-account (429), and the shared campus IP was NOT banned! Innocent lab student authenticated successfully." + Colors.RESET)
        return True
    elif status_innocent == 403:
        print(Colors.BOLD + Colors.RED + "[FAILED] Flaw: Campus lab IP was banned, cutting off innocent students!" + Colors.RESET)
        return False
    else:
        print(Colors.YELLOW + f"[NOTE] Innocent login returned status {status_innocent}." + Colors.RESET)
        return len(throttled_accounts) > 0

# ---------------------------------------------------------------------------
# SCENARIO 3: External High-Speed Brute-Force Attack
# ---------------------------------------------------------------------------
def run_scenario_3(base_url: str):
    print_header("Scenario 3: External High-Speed Brute-Force Attack (185.220.101.44)")
    print(Colors.BOLD + "Context:" + Colors.RESET + " External malicious botnet IP launching a rapid dictionary attack")
    print("against administrative account 'admin'.")
    print(Colors.YELLOW + "Objective: Trigger immediate Hard IP Ban (HTTP 403 Forbidden)." + Colors.RESET + "\n")

    attacker_ip = "185.220.101.44"
    target_user = "admin"
    wordlist = [
        "123456", "password", "admin123", "root", "toor", "letmein", "welcome",
        "qwerty", "admin2024", "veritas2024", "superadmin", "football", "dragon",
        "master", "monkey", "shadow", "sunshine", "iloveyou", "trustno1", "princess",
        "secure", "server", "campus", "academic", "registrar"
    ]

    ban_triggered = False
    ban_attempt = None

    for i, pwd in enumerate(wordlist, start=1):
        status, data, latency = send_login_request(base_url, attacker_ip, target_user, pwd)
        action = data.get("action_taken", "UNKNOWN")

        if status == 403:
            if not ban_triggered:
                ban_triggered = True
                ban_attempt = i
            badge = Colors.BOLD + Colors.RED + f"[403 HARD BAN] {action}" + Colors.RESET
        elif status == 401:
            badge = Colors.DIM + f"[401 REJECTED] {action}" + Colors.RESET
        elif status == 429:
            badge = Colors.YELLOW + f"[429 THROTTLED] {action}" + Colors.RESET
        else:
            badge = f"[{status}]"

        print(f" Attack {i:02d}/{len(wordlist)} | Password: '{pwd:<14}' -> {badge} ({latency:.1f}ms)")
        time.sleep(0.04)

    print("\n[*] Post-Ban Edge Verification: Testing subsequent request from banned IP...")
    post_status, post_data, _ = send_login_request(base_url, attacker_ip, "any_user", "any_password")
    print(f" Subsequent Request Status: {post_status} ({post_data.get('action_taken')})")

    print("\n" + Colors.BOLD + "--- Scenario 3 Results ---" + Colors.RESET)
    if ban_triggered and post_status == 403:
        print(Colors.BOLD + Colors.GREEN + f"[VERIFIED] SUCCESS: External attacker IP {attacker_ip} was hard-banned (HTTP 403) at attempt #{ban_attempt}! Edge defense successfully blocked subsequent requests." + Colors.RESET)
        return True
    else:
        print(Colors.BOLD + Colors.RED + f"[FAILED] Attacker IP {attacker_ip} was not hard banned." + Colors.RESET)
        return False

def run_all(base_url: str):
    """Run all three scenarios sequentially with automatic resets."""
    print(Colors.BOLD + "\n🚀 RUNNING FULL END-TO-END VERIFICATION SUITE" + Colors.RESET)
    reset_server(base_url)
    time.sleep(0.5)

    print("\n>>> EXECUTING TEST 1 OF 3: HOSTEL EXAM RUSH <<<")
    r1 = run_scenario_1(base_url)
    time.sleep(0.5)

    print("\n>>> EXECUTING TEST 2 OF 3: CAMPUS LAB PASSWORD SPRAY <<<")
    r2 = run_scenario_2(base_url)
    time.sleep(0.5)

    print("\n>>> EXECUTING TEST 3 OF 3: EXTERNAL BRUTE FORCE <<<")
    r3 = run_scenario_3(base_url)

    print("\n" + Colors.BOLD + Colors.GREEN + "================================================================================" + Colors.RESET)
    print(Colors.BOLD + Colors.GREEN + "  ALL SCENARIOS COMPLETED! CHECK LIVE TELEMETRY ON STREAMLIT SOC DASHBOARD." + Colors.RESET)
    print(Colors.BOLD + Colors.GREEN + "================================================================================" + Colors.RESET)
    return r1 and r2 and r3

def interactive_menu(base_url: str):
    """Interactive CLI menu."""
    while True:
        print("\n" + Colors.BOLD + "================== VERITAS UNIVERSITY ATTACK SIMULATOR ==================" + Colors.RESET)
        print(f" Target Server: {Colors.CYAN}{base_url}{Colors.RESET}")
        print(" 1) Scenario 1: Shared Hostel NAT Exam Rush (10.10.45.12 - Zero False Positives)")
        print(" 2) Scenario 2: Campus Lab Password Spraying (10.10.88.5 - Account 429 Throttling)")
        print(" 3) Scenario 3: External Brute-Force Attack (185.220.101.44 - Hard 403 Ban)")
        print(" 4) Run All Scenarios in Sequence (Full End-to-End Suite)")
        print(" 5) Reset Portal State & Logs (/reset)")
        print(" 6) Exit Simulator")
        print("=" * 73)
        choice = input(Colors.BOLD + " Select an option [1-6]: " + Colors.RESET).strip()

        if choice == "1":
            run_scenario_1(base_url)
        elif choice == "2":
            run_scenario_2(base_url)
        elif choice == "3":
            run_scenario_3(base_url)
        elif choice == "4":
            run_all(base_url)
        elif choice == "5":
            reset_server(base_url)
        elif choice == "6" or choice.lower() in ["exit", "q", "quit"]:
            print("Exiting simulator.")
            break
        else:
            print(Colors.YELLOW + "Invalid choice. Please enter 1-6." + Colors.RESET)

def main():
    parser = argparse.ArgumentParser(description="University Brute-Force & Context-Aware Mitigation Simulator")
    parser.add_argument("--url", default=DEFAULT_BASE_URL, help=f"Base URL of portal (default: {DEFAULT_BASE_URL})")
    parser.add_argument("--scenario", choices=["1", "2", "3", "all", "reset"], help="Scenario to run immediately")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")

    online, mode_desc = check_server_health(base_url)
    print(f"[*] University Portal Connection: {Colors.GREEN if online else Colors.RED}{mode_desc}{Colors.RESET}")

    if args.scenario:
        if args.scenario == "1":
            run_scenario_1(base_url)
        elif args.scenario == "2":
            run_scenario_2(base_url)
        elif args.scenario == "3":
            run_scenario_3(base_url)
        elif args.scenario == "all":
            success = run_all(base_url)
            sys.exit(0 if success else 1)
        elif args.scenario == "reset":
            reset_server(base_url)
    else:
        interactive_menu(base_url)

if __name__ == "__main__":
    main()
