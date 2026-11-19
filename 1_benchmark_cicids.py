#!/usr/bin/env python3
"""
1_benchmark_cicids.py
======================
Benchmark ML models on the CSE-CIC-IDS2018 Brute-Force dataset (02-14-2018.csv).
Preprocesses network flows, trains Logistic Regression, Decision Tree, and Random Forest,
evaluates comparative metrics on an 80/20 stratified split, and exports the model and confusion matrix.
"""

import os
import sys
import tempfile
os.environ.setdefault("MPLCONFIGDIR", os.path.join(tempfile.gettempdir(), "matplotlib"))

import time
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

DATA_PATH = os.path.join("data", "02-14-2018.csv")
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "cicids_rf_model.pkl")
CM_PATH = os.path.join(MODEL_DIR, "cicids_confusion_matrix.png")

def preprocess_cicids(file_path: str):
    """
    Load and clean CSE-CIC-IDS2018 dataset:
    - Remove duplicate headers where Label == 'Label'
    - Drop Timestamp column
    - Coerce features to numeric
    - Replace inf/-inf with NaN and drop missing values
    - Encode labels: Benign -> 0, FTP-BruteForce/SSH-BruteForce -> 1
    """
    print(f"[*] Loading raw dataset from '{file_path}'...")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Dataset not found at {file_path}")

    # Read CSV with low_memory=False to handle mixed types cleanly
    df = pd.read_csv(file_path, low_memory=False)
    initial_len = len(df)
    print(f"    Raw records loaded: {initial_len:,}")

    # Remove duplicate header rows where Label == 'Label'
    df = df[df["Label"] != "Label"].copy()
    print(f"    After dropping duplicate header rows: {len(df):,}")

    # Drop Timestamp column
    if "Timestamp" in df.columns:
        df = df.drop(columns=["Timestamp"])
        print("    Dropped 'Timestamp' column.")

    # Target encoding
    # Benign -> 0, FTP-BruteForce / SSH-BruteForce -> 1
    raw_labels = df["Label"].copy()
    label_counts = raw_labels.value_counts().to_dict()
    print("    Raw label distribution:", label_counts)

    y = raw_labels.apply(lambda val: 0 if str(val).strip().lower() == "benign" else 1)

    # Feature coercion
    feature_cols = [col for col in df.columns if col != "Label"]
    print(f"    Coercing {len(feature_cols)} features to numeric...")
    X = df[feature_cols].apply(pd.to_numeric, errors="coerce")

    # Replace inf and -inf with NaN, then drop NaNs
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    valid_mask = ~X.isna().any(axis=1)

    X_clean = X.loc[valid_mask].copy()
    y_clean = y.loc[valid_mask].copy()

    print(f"    Cleaned records retained: {len(X_clean):,} (dropped {initial_len - len(X_clean):,} invalid/inf/nan rows)")
    print(f"    Class distribution in clean dataset -> Benign (0): {(y_clean == 0).sum():,}, BruteForce (1): {(y_clean == 1).sum():,}")

    return X_clean, y_clean

def train_and_evaluate(X, y):
    """
    Compare Logistic Regression, Decision Tree, and Random Forest on 80/20 stratified split.
    """
    print("\n[*] Splitting dataset into 80% train / 20% test (stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"    Train size: {X_train.shape[0]:,} | Test size: {X_test.shape[0]:,} | Features: {X_train.shape[1]}")

    models = {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=1000, random_state=42, solver="lbfgs"))
        ]),
        "Decision Tree": DecisionTreeClassifier(random_state=42, max_depth=15),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    }

    results = []
    trained_clfs = {}

    print("\n[*] Benchmarking Models...")
    print("-" * 85)
    print(f"{'Model Name':<24} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'ROC-AUC':<10}")
    print("-" * 85)

    for name, model in models.items():
        t0 = time.time()
        model.fit(X_train, y_train)
        fit_time = time.time() - t0

        y_pred = model.predict(X_test)
        
        # Determine probability for ROC-AUC
        if hasattr(model, "predict_proba"):
            y_prob = model.predict_proba(X_test)[:, 1]
        elif hasattr(model, "decision_function"):
            y_prob = model.decision_function(X_test)
        else:
            y_prob = y_pred

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        roc = roc_auc_score(y_test, y_prob)

        results.append({
            "model": name,
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "roc_auc": roc,
            "time_sec": fit_time,
            "y_pred": y_pred,
            "y_prob": y_prob
        })
        trained_clfs[name] = model

        print(f"{name:<24} | {acc * 100:>8.2f}% | {prec * 100:>8.2f}% | {rec * 100:>8.2f}% | {f1 * 100:>8.2f}% | {roc * 100:>8.2f}%")

    print("-" * 85)
    return results, trained_clfs, X_test, y_test

def export_artifacts(results, trained_clfs, y_test):
    """
    Export Random Forest model and Confusion Matrix heatmap.
    """
    os.makedirs(MODEL_DIR, exist_ok=True)
    rf_model = trained_clfs["Random Forest"]
    rf_result = next(r for r in results if r["model"] == "Random Forest")
    y_pred = rf_result["y_pred"]

    # 1. Save Model
    print(f"\n[*] Exporting Random Forest classifier to '{MODEL_PATH}'...")
    joblib.dump(rf_model, MODEL_PATH)
    print("    [+] Model successfully saved.")

    # 2. Confusion Matrix Plot
    print(f"[*] Generating Confusion Matrix heatmap at '{CM_PATH}'...")
    cm = confusion_matrix(y_test, y_pred)

    plt.figure(figsize=(7, 6))
    sns.set_theme(style="darkgrid")
    ax = sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        cbar=True,
        xticklabels=["Benign (0)", "BruteForce (1)"],
        yticklabels=["Benign (0)", "BruteForce (1)"]
    )
    plt.title("CSE-CIC-IDS2018 Brute-Force Detection\nRandom Forest Confusion Matrix", fontsize=13, fontweight="bold", pad=12)
    plt.xlabel("Predicted Label", fontsize=11, fontweight="bold")
    plt.ylabel("True Label", fontsize=11, fontweight="bold")
    plt.tight_layout()
    plt.savefig(CM_PATH, dpi=300)
    plt.close()
    print("    [+] Heatmap plot successfully exported.")

    print("\n[+] Classification Report for Random Forest:")
    print(classification_report(y_test, y_pred, target_names=["Benign (0)", "BruteForce (1)"], digits=4))

def main():
    print("=" * 85)
    print(" CSE-CIC-IDS2018 BRUTE-FORCE BENCHMARK PIPELINE")
    print("=" * 85)
    
    X, y = preprocess_cicids(DATA_PATH)
    results, trained_clfs, X_test, y_test = train_and_evaluate(X, y)
    export_artifacts(results, trained_clfs, y_test)

    print("\n[SUCCESS] CIC-IDS benchmark and artifact export completed.")

if __name__ == "__main__":
    main()
