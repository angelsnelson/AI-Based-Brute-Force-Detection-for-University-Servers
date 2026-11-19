#!/usr/bin/env python3
"""
start_servers.py
================
Unified launcher to start both the Veritas University SSO Portal (port 5000)
and the Streamlit SOC Dashboard (port 8501) simultaneously.
"""

import os
import sys
import time
import subprocess
import signal

PYTHON_EXE = sys.executable

def main():
    print("=" * 75)
    print(" STARTING LIVE SERVICES: UNIVERSITY SSO PORTAL & STREAMLIT SOC")
    print("=" * 75)

    base_dir = os.path.dirname(os.path.abspath(__file__))

    # 1. Start Flask Portal (Port 5000)
    portal_cmd = [PYTHON_EXE, "-u", os.path.join(base_dir, "3_university_portal.py")]
    print("[*] Launching University SSO Portal (Flask @ http://localhost:5000)...")
    portal_proc = subprocess.Popen(
        portal_cmd,
        cwd=base_dir,
        stdout=sys.stdout,
        stderr=sys.stderr
    )

    # Allow Flask a brief moment to initialize
    time.sleep(1.5)

    # 2. Start Streamlit SOC Dashboard (Port 8501)
    dash_cmd = [
        PYTHON_EXE, "-m", "streamlit", "run",
        os.path.join(base_dir, "4_dashboard.py"),
        "--server.port", "8501",
        "--server.headless", "true",
        "--browser.serverAddress", "localhost",
        "--server.enableCORS", "false",
        "--server.enableXsrfProtection", "false"
    ]
    print("[*] Launching Streamlit SOC Dashboard (@ http://localhost:8501)...")
    dash_proc = subprocess.Popen(
        dash_cmd,
        cwd=base_dir,
        stdout=sys.stdout,
        stderr=sys.stderr
    )

    print("\n" + "=" * 75)
    print(" [LIVE] University SSO Portal:  http://localhost:5000")
    print(" [LIVE] Streamlit SOC Dashboard: http://localhost:8501")
    print(" Press Ctrl+C to terminate both servers.")
    print("=" * 75 + "\n")

    def shutdown(signum, frame):
        print("\n[*] Shutting down servers...")
        try:
            portal_proc.terminate()
            dash_proc.terminate()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        while True:
            # Check if either process terminated unexpectedly
            p_code = portal_proc.poll()
            d_code = dash_proc.poll()

            if p_code is not None:
                print(f"[-] Portal process terminated with code {p_code}")
                dash_proc.terminate()
                break
            if d_code is not None:
                print(f"[-] Dashboard process terminated with code {d_code}")
                portal_proc.terminate()
                break

            time.sleep(1.0)
    except KeyboardInterrupt:
        shutdown(None, None)

if __name__ == "__main__":
    main()
