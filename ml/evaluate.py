#!/usr/bin/env python3
"""ASVD Demo — Machine Learning Model Evaluation.

Evaluates the trained ASVD scam detection classifier on the held-out test split,
generating precision, recall, F1, confusion matrix, and per-category breakdown.

Usage:
    python ml/evaluate.py
    python ml/evaluate.py --test-data data/processed/test.csv
"""

import argparse
import json
import os
import sys

# Windows encoding fix
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import hstack
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_TEST_PATH = os.path.join(PROJECT_ROOT, "data", "processed", "test.csv")
DEFAULT_MODEL_PATH = os.path.join(PROJECT_ROOT, "backend", "app", "model", "model.joblib")
DEFAULT_VEC_PATH = os.path.join(PROJECT_ROOT, "backend", "app", "model", "vectorizer.joblib")
OUTPUT_REPORT_PATH = os.path.join(PROJECT_ROOT, "ml", "evaluation_results.json")

INDICATOR_COLS = [
    "urgency", "authority_impersonation", "financial_request",
    "otp_request", "credential_request", "threat_detected",
    "emotional_manipulation", "secrecy_request",
]


def evaluate_test_set(
    test_path: str = DEFAULT_TEST_PATH,
    model_path: str = DEFAULT_MODEL_PATH,
    vec_path: str = DEFAULT_VEC_PATH,
) -> dict:
    """Run full evaluation on held-out test split."""
    if not os.path.exists(test_path):
        raise FileNotFoundError(f"Test data file not found at {test_path}")
    if not os.path.exists(model_path) or not os.path.exists(vec_path):
        raise FileNotFoundError(f"Model or Vectorizer not found at {model_path} / {vec_path}")

    print(f"Loading test dataset from {test_path}...")
    df_test = pd.read_csv(test_path, encoding="utf-8-sig")

    print(f"Loading model & vectorizer from {model_path}...")
    model = joblib.load(model_path)
    vectorizer = joblib.load(vec_path)

    X_text = df_test["conversation_text"].fillna("").astype(str)
    y_true = df_test["label"].values

    # Feature transformation
    X_tfidf = vectorizer.transform(X_text)
    X_ind = df_test[INDICATOR_COLS].values.astype(np.float64)
    X_combined = hstack([X_tfidf, X_ind])

    # Predictions
    y_pred = model.predict(X_combined)
    y_proba = model.predict_proba(X_combined)

    # Classes
    classes = list(model.classes_)
    scam_idx = classes.index("SCAM")
    y_scores = y_proba[:, scam_idx]
    y_true_binary = (y_true == "SCAM").astype(int)

    # Core Metrics
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, pos_label="SCAM")
    rec = recall_score(y_true, y_pred, pos_label="SCAM")
    f1 = f1_score(y_true, y_pred, pos_label="SCAM")
    roc_auc = roc_auc_score(y_true_binary, y_scores)
    cm = confusion_matrix(y_true, y_pred, labels=["SAFE", "SCAM"]).tolist()

    # Per-category accuracy breakdown
    category_breakdown = {}
    if "scam_category" in df_test.columns:
        categories = df_test["scam_category"].fillna("Safe/None").unique()
        for cat in categories:
            if cat == "Safe/None":
                cat_mask = df_test["scam_category"].isna() | (df_test["scam_category"] == "None")
            else:
                cat_mask = df_test["scam_category"] == cat
            
            if cat_mask.sum() > 0:
                sub_true = y_true[cat_mask]
                sub_pred = y_pred[cat_mask]
                cat_acc = accuracy_score(sub_true, sub_pred)
                category_breakdown[str(cat)] = {
                    "total_samples": int(cat_mask.sum()),
                    "accuracy": round(float(cat_acc), 4)
                }

    results = {
        "test_samples": len(df_test),
        "metrics": {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "roc_auc": round(float(roc_auc), 4),
        },
        "confusion_matrix": {
            "labels": ["SAFE", "SCAM"],
            "matrix": cm,
            "true_negative": cm[0][0],
            "false_positive": cm[0][1],
            "false_negative": cm[1][0],
            "true_positive": cm[1][1],
        },
        "category_breakdown": category_breakdown,
        "classification_report": classification_report(y_true, y_pred, output_dict=True),
    }

    # Save to json
    os.makedirs(os.path.dirname(OUTPUT_REPORT_PATH), exist_ok=True)
    with open(OUTPUT_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return results


def print_evaluation_summary(results: dict):
    """Format and print test evaluation summary to console."""
    m = results["metrics"]
    cm = results["confusion_matrix"]

    print()
    print("=" * 60)
    print("        ASVD 2.O — MODEL TEST EVALUATION REPORT")
    print("=" * 60)
    print(f"\n  Total Test Conversations: {results['test_samples']:,}")
    print()
    print("  Overall Performance:")
    print("  -------------------")
    print(f"  Accuracy:  {m['accuracy'] * 100:.2f}%")
    print(f"  Precision: {m['precision'] * 100:.2f}%")
    print(f"  Recall:    {m['recall'] * 100:.2f}%")
    print(f"  F1 Score:  {m['f1_score']:.4f}")
    print(f"  ROC-AUC:   {m['roc_auc']:.4f}")
    print()
    print("  Confusion Matrix:")
    print("  -------------------")
    print(f"  True Safe (TN):   {cm['true_negative']:>4}   | False Scam (FP):  {cm['false_positive']:>4}")
    print(f"  False Safe (FN):  {cm['false_negative']:>4}   | True Scam (TP):   {cm['true_positive']:>4}")
    print()
    print("  Category Performance Breakdown:")
    print("  ------------------------------")
    for cat, info in results.get("category_breakdown", {}).items():
        print(f"  {cat:<32} Samples: {info['total_samples']:>3}  Acc: {info['accuracy'] * 100:.1f}%")
    print()
    print(f"  [OK] Detailed report saved: {OUTPUT_REPORT_PATH}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="ASVD Demo — Evaluate ML Classifier")
    parser.add_argument("--test-data", default=DEFAULT_TEST_PATH, help="Path to test.csv")
    parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH, help="Path to model.joblib")
    parser.add_argument("--vec-path", default=DEFAULT_VEC_PATH, help="Path to vectorizer.joblib")
    args = parser.parse_args()

    results = evaluate_test_set(
        test_path=args.test_data,
        model_path=args.model_path,
        vec_path=args.vec_path,
    )
    print_evaluation_summary(results)


if __name__ == "__main__":
    main()
