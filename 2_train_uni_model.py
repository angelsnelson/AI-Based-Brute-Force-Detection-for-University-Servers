#!/usr/bin/env python3
"""
2_train_uni_model.py
====================
Generates a 12,000-row realistic synthetic university authentication dataset
capturing six 60-second sliding-window behavioral features across three classes:
  - Class 0: Normal student logins & high-traffic shared hostel NAT exam rushes (concurrent successes)
  - Class 1: Campus lab password spraying (sequential student roll numbers, high failure ratio, campus IP)
  - Class 2: External high-speed brute-force attacks (rapid automated dictionary attack, external IP)

Trains a 120-tree Random Forest classifier, exports 'models/uni_rf_model.pkl',
and saves a feature importance visualization to 'models/uni_feature_importance.png'.
"""

import os
import tempfile
os.environ.setdefault("MPLCONFIGDIR", os.path.join(tempfile.gettempdir(), "matplotlib"))

import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

DATA_DIR = "data"
MODEL_DIR = "models"
DATA_PATH = os.path.join(DATA_DIR, "university_auth_dataset.csv")
MODEL_PATH = os.path.join(MODEL_DIR, "uni_rf_model.pkl")
IMPORTANCE_IMG_PATH = os.path.join(MODEL_DIR, "uni_feature_importance.png")

FEATURE_NAMES = [
    "failed_attempts_per_min",
    "mean_time_delta",
    "std_time_delta",
    "unique_usernames_tried",
    "failure_to_success_ratio",
    "is_campus_ip"
]

def generate_university_dataset(n_total: int = 12000, random_state: int = 42) -> pd.DataFrame:
    """
    Synthesize realistic 60-second sliding-window behavioral logs.
    Distribution:
      - Class 0: 8,000 samples (5,500 normal routine logins + 2,500 hostel NAT exam rushes)
      - Class 1: 2,000 samples (campus lab password spraying)
      - Class 2: 2,000 samples (external high-speed brute-force)
    """
    np.random.seed(random_state)
    records = []

    # 1. Class 0 - Part A: Normal Routine Student/Faculty Logins (5,500 samples)
    n_c0_normal = 5500
    for _ in range(n_c0_normal):
        failed_attempts = float(np.random.choice([0, 1, 2, 3], p=[0.75, 0.18, 0.05, 0.02]))
        mean_delta = float(np.random.uniform(8.0, 42.0))
        std_delta = float(np.random.uniform(2.0, 15.0))
        unique_users = float(np.random.choice([1, 2], p=[0.95, 0.05]))
        successes = float(max(1, int(np.random.poisson(lam=1.5))))
        ratio = float(round(failed_attempts / (successes + 1.0), 4))
        is_campus = float(np.random.choice([1, 0], p=[0.75, 0.25]))

        records.append({
            "failed_attempts_per_min": failed_attempts,
            "mean_time_delta": mean_delta,
            "std_time_delta": std_delta,
            "unique_usernames_tried": unique_users,
            "failure_to_success_ratio": ratio,
            "is_campus_ip": is_campus,
            "class_label": 0
        })

    # 2. Class 0 - Part B: Shared Hostel NAT Exam Rushes (2,500 samples)
    n_c0_rush = 2500
    for _ in range(n_c0_rush):
        failed_attempts = float(np.random.uniform(0.0, 5.0))
        mean_delta = float(np.random.uniform(0.05, 1.8))
        std_delta = float(np.random.uniform(0.02, 0.8))
        unique_users = float(np.random.randint(12, 70))
        success_count = float(np.random.uniform(20.0, 90.0))
        ratio = float(round(failed_attempts / (success_count + 1.0), 4))
        is_campus = 1.0

        records.append({
            "failed_attempts_per_min": failed_attempts,
            "mean_time_delta": mean_delta,
            "std_time_delta": std_delta,
            "unique_usernames_tried": unique_users,
            "failure_to_success_ratio": ratio,
            "is_campus_ip": is_campus,
            "class_label": 0
        })

    # 3. Class 1: Campus Lab Password Spraying (2,000 samples)
    n_c1 = 2000
    for _ in range(n_c1):
        failed_attempts = float(np.random.uniform(5.0, 40.0))
        mean_delta = float(np.random.uniform(0.05, 3.5))
        std_delta = float(np.random.uniform(0.01, 1.2))
        unique_users = float(np.random.randint(5, 55))
        success_count = float(np.random.choice([0.0, 1.0], p=[0.95, 0.05]))
        ratio = float(round(failed_attempts / (success_count + 1.0), 4))
        is_campus = 1.0

        records.append({
            "failed_attempts_per_min": failed_attempts,
            "mean_time_delta": mean_delta,
            "std_time_delta": std_delta,
            "unique_usernames_tried": unique_users,
            "failure_to_success_ratio": ratio,
            "is_campus_ip": is_campus,
            "class_label": 1
        })

    # 4. Class 2: External High-Speed Brute-Force Attacks (2,000 samples)
    n_c2 = 2000
    for _ in range(n_c2):
        failed_attempts = float(np.random.uniform(15.0, 250.0))
        mean_delta = float(np.random.uniform(0.02, 0.8))
        std_delta = float(np.random.uniform(0.005, 0.35))
        unique_users = float(np.random.choice([1, 2, 3], p=[0.85, 0.12, 0.03]))
        ratio = float(round(failed_attempts / 1.0, 4))
        is_campus = 0.0

        records.append({
            "failed_attempts_per_min": failed_attempts,
            "mean_time_delta": mean_delta,
            "std_time_delta": std_delta,
            "unique_usernames_tried": unique_users,
            "failure_to_success_ratio": ratio,
            "is_campus_ip": is_campus,
            "class_label": 2
        })

    df = pd.DataFrame(records)
    # Shuffle rows
    df = df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    return df

def train_and_export_uni_model(df: pd.DataFrame):
    """
    Train a 120-tree Random Forest classifier, save uni_rf_model.pkl and
    uni_feature_importance.png.
    """
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(MODEL_DIR, exist_ok=True)

    # 1. Save dataset
    print(f"[*] Saving generated dataset to '{DATA_PATH}' ({len(df):,} rows)...")
    df.to_csv(DATA_PATH, index=False)
    print("    [+] CSV dataset successfully saved.")

    X = df[FEATURE_NAMES]
    y = df["class_label"]

    print("\n[*] Splitting dataset (80% train / 20% test, stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"    Train size: {X_train.shape[0]:,} | Test size: {X_test.shape[0]:,}")
    print("    Class distribution in Test Set:")
    for label, count in y_test.value_counts().items():
        class_name = {
            0: "Class 0 (Normal / Hostel Exam Rush)",
            1: "Class 1 (Campus Lab Password Spray)",
            2: "Class 2 (External Brute-Force)"
        }.get(label, str(label))
        print(f"      {class_name}: {count:,} ({count / len(y_test) * 100:.1f}%)")

    # 2. Train 120-tree Random Forest Classifier
    print("\n[*] Training 120-tree Random Forest Classifier...")
    rf_clf = RandomForestClassifier(
        n_estimators=120,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    )
    rf_clf.fit(X_train, y_train)
    print("    [+] Random Forest training completed.")

    # 3. Evaluate
    y_pred = rf_clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n[+] Model Test Accuracy: {acc * 100:.2f}%")

    target_names = [
        "Class 0 (Normal/Exam Rush)",
        "Class 1 (Campus Spray)",
        "Class 2 (External Brute-Force)"
    ]
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=target_names, digits=4))

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # 4. Save trained model
    print(f"\n[*] Exporting trained model to '{MODEL_PATH}'...")
    joblib.dump(rf_clf, MODEL_PATH)
    print("    [+] University RF model successfully exported.")

    # 5. Feature Importance Visualization
    print(f"[*] Generating feature importance chart at '{IMPORTANCE_IMG_PATH}'...")
    importances = rf_clf.feature_importances_
    feat_df = pd.DataFrame({
        "Feature": FEATURE_NAMES,
        "Importance": importances
    }).sort_values(by="Importance", ascending=False)

    plt.figure(figsize=(9, 5.5))
    sns.set_theme(style="darkgrid")
    palette = sns.color_palette("mako", len(feat_df))

    ax = sns.barplot(
        x="Importance",
        y="Feature",
        data=feat_df,
        palette=palette,
        hue="Feature",
        legend=False
    )
    for p in ax.patches:
        width = p.get_width()
        ax.annotate(
            f"{width:.4f}",
            (width + 0.005, p.get_y() + p.get_height() / 2),
            va="center",
            fontsize=10,
            fontweight="bold"
        )

    plt.title(
        "University Auth Defense: 120-Tree Random Forest Feature Importance\n(Distinguishing Normal/Hostel Rush vs Lab Spray vs External Brute-Force)",
        fontsize=12,
        fontweight="bold",
        pad=15
    )
    plt.xlabel("Gini Importance Score", fontsize=11, fontweight="bold")
    plt.ylabel("Sliding-Window Feature", fontsize=11, fontweight="bold")
    plt.xlim(0, max(importances) * 1.15)
    plt.tight_layout()
    plt.savefig(IMPORTANCE_IMG_PATH, dpi=300)
    plt.close()
    print("    [+] Feature importance chart successfully exported.")

    print("\nFeature Importance Rankings:")
    for idx, row in feat_df.iterrows():
        print(f"    {row['Feature']:<26}: {row['Importance']:.4f}")

def main():
    print("=" * 80)
    print(" UNIVERSITY AUTHENTICATION BEHAVIORAL DATASET GENERATION & MODEL TRAINING")
    print("=" * 80)

    dataset = generate_university_dataset(n_total=12000, random_state=42)
    train_and_export_uni_model(dataset)

    print("\n[SUCCESS] 2_train_uni_model.py execution completed successfully.")

if __name__ == "__main__":
    main()
