# AI-Based Brute-Force Detection & Context-Aware Mitigation for University Servers

An end-to-end cybersecurity microproject designed for academic environments. It features sliding-window behavioral telemetry, machine learning threat classification, and context-aware mitigation that protects shared university NAT gateways and campus Wi-Fi from false-positive bans while aggressively neutralizing automated brute-force attacks.

---

## 🏛️ Project Architecture

```
ai/
├── requirements.txt              # Core package dependencies
├── 1_benchmark_cicids.py         # CSE-CIC-IDS2018 benchmark & classifier comparison
├── 2_train_uni_model.py          # 12,000-row university dataset generator & 120-tree RF trainer
├── 3_university_portal.py        # Flask SSO Login Portal (Port 5000, Dark Theme)
├── 4_dashboard.py                # Streamlit live auto-refreshing SOC telemetry dashboard
├── 5_attack_simulator.py         # Multi-scenario interactive attack & rush simulator
├── server_auth.csv               # Live sliding-window event log (timestamp, ip, status, etc.)
├── mitigation_state.json         # Active edge mitigations (banned IPs, throttled accounts)
├── data/
│   ├── 02-14-2018.csv            # CSE-CIC-IDS2018 brute-force network flow dataset
│   └── university_auth_dataset.csv # 12,000-row synthetic sliding-window telemetry
└── models/
    ├── cicids_rf_model.pkl       # Trained benchmark Random Forest classifier
    ├── cicids_confusion_matrix.png # Benchmark confusion matrix heatmap
    ├── uni_rf_model.pkl          # 120-tree University RF classifier
    └── uni_feature_importance.png# Sliding-window feature importance chart
```

---

## 🔬 Core Defense Logic & Context-Aware Mitigation

Traditional rate limiters fail in university environments because hundreds or thousands of students in hostels, dorms, and computer labs share a single campus NAT gateway IP (e.g., `10.10.45.12`). Banning the IP shuts down all innocent students.

This system monitors **six 60-second sliding-window behavioral features**:
1. `failed_attempts_per_min`: Frequency of authentication rejections in the window.
2. `mean_time_delta`: Average elapsed seconds between consecutive attempts from this IP.
3. `std_time_delta`: Timing jitter (low jitter = machine scripts, high jitter = human variance).
4. `unique_usernames_tried`: Count of distinct student/faculty usernames targeted.
5. `failure_to_success_ratio`: Ratio of failed attempts to successful attempts in the window.
6. `is_campus_ip`: Binary flag (1 for `10.10.x.x` and `172.16.x.x` subnets, 0 for external internet).

### Threat Taxonomy & Dynamic Mitigation Table

| Class | Threat Profile | Key Sliding-Window Signature | Enforced Mitigation Action | HTTP Code | Impact on Campus Users |
|---|---|---|---|---|---|
| **Class 0** | **Normal Logins & Hostel NAT Exam Rush** | High concurrency, many unique users, **high concurrent successes** (`failure_to_success_ratio < 0.2`) | **ALLOW** | 200 / 401 | **Zero False Positives**: Campus IP is never banned. |
| **Class 1** | **Campus Lab Password Spraying** | Campus subnet (`is_campus_ip=1`), sequential roll numbers (`unique_usernames > 5`), high failure ratio | **THROTTLE_ACCOUNT** | 429 Too Many Requests | **Context-Aware Isolation**: Only targeted accounts are locked; campus NAT IP remains 100% accessible to innocent lab users. |
| **Class 2** | **External High-Speed Brute-Force** | External origin (`is_campus_ip=0`), machine speed (`mean_delta < 0.8s`), rapid automated dictionary attempts | **HARD_BAN_IP** | 403 Forbidden | **Immediate Perimeter Block**: Attacker IP permanently banned in `mitigation_state.json`. |

---

## 🚀 Step-by-Step Execution Guide

### 1. Install Dependencies
```bash
python -m pip install -r requirements.txt
```

### 2. Benchmark Against CSE-CIC-IDS2018 Brute-Force Dataset
Preprocesses `data/02-14-2018.csv`, compares Logistic Regression, Decision Tree, and Random Forest on an 80/20 stratified split, and exports the model and confusion matrix:
```bash
python 1_benchmark_cicids.py
```
*Outputs: `models/cicids_rf_model.pkl`, `models/cicids_confusion_matrix.png`*

### 3. Generate University Dataset & Train Behavioral RF Model
Synthesizes 12,000 rows across Class 0, Class 1, and Class 2, trains a 120-tree Random Forest, and exports feature rankings:
```bash
python 2_train_uni_model.py
```
*Outputs: `data/university_auth_dataset.csv`, `models/uni_rf_model.pkl`, `models/uni_feature_importance.png`*

### 4. Start Flask University SSO Portal (Port 5000)
Runs the dark-themed University CAS SSO Portal supporting HTML form and JSON logins:
```bash
python 3_university_portal.py
```
*Available at: `http://localhost:5000` (Reset API: `POST http://localhost:5000/reset`)*

### 5. Launch Live SOC Streamlit Dashboard
Launches the real-time SOC command dashboard with live KPI cards, traffic origin breakdowns, active mitigation JSON state, and live audit log table:
```bash
streamlit run 4_dashboard.py
```
*Available at: `http://localhost:8501`*

### 6. Run the Attack & Rush Simulator
Run interactive CLI scenarios to verify real-time mitigation:
```bash
# Run all three scenarios sequentially
python 5_attack_simulator.py --scenario all

# Or run individual scenarios:
python 5_attack_simulator.py --scenario 1   # Shared Hostel Exam Rush (Zero False Positives)
python 5_attack_simulator.py --scenario 2   # Campus Lab Password Spraying (HTTP 429)
python 5_attack_simulator.py --scenario 3   # External Brute-Force Attack (HTTP 403)
python 5_attack_simulator.py --scenario reset # Reset bans and logs
```
