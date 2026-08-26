#!/usr/bin/env python3
"""ASVD Demo — Machine Learning Model Training.

Trains a hybrid TF-IDF (word + n-gram) and NLP indicator-augmented
Logistic Regression classifier on the synthetic cyber-scam dataset.

Usage:
    python ml/train.py
    python ml/train.py --data-dir data/processed --output-dir ml/saved_model
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
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
DEFAULT_MODEL_DIR = os.path.join(PROJECT_ROOT, "backend", "app", "model")
ML_SAVED_DIR = os.path.join(PROJECT_ROOT, "ml", "saved_model")

INDICATOR_COLS = [
    "urgency", "authority_impersonation", "financial_request",
    "otp_request", "credential_request", "threat_detected",
    "emotional_manipulation", "secrecy_request",
]


def train_model(
    data_dir: str = DEFAULT_DATA_DIR,
    output_dirs: list = None,
    max_features: int = 5000,
    c_param: float = 1.0,
    random_state: int = 42,
) -> dict:
    """Train classifier on train split and validate on validation split."""
    if output_dirs is None:
        output_dirs = [DEFAULT_MODEL_DIR, ML_SAVED_DIR]

    train_path = os.path.join(data_dir, "train.csv")
    val_path = os.path.join(data_dir, "val.csv")

    if not os.path.exists(train_path) or not os.path.exists(val_path):
        raise FileNotFoundError(
            f"Training data not found in {data_dir}. Run 'python data/generate_dataset.py' first."
        )

    print(f"Loading training data from {train_path}...")
    train_df = pd.read_csv(train_path, encoding="utf-8-sig")
    val_df = pd.read_csv(val_path, encoding="utf-8-sig")

    X_train_text = train_df["conversation_text"].fillna("").astype(str)
    X_val_text = val_df["conversation_text"].fillna("").astype(str)

    y_train = train_df["label"]
    y_val = val_df["label"]

    print(f"Train samples: {len(train_df):,} (Scam: {(y_train == 'SCAM').sum()}, Safe: {(y_train == 'SAFE').sum()})")
    print(f"Validation samples: {len(val_df):,} (Scam: {(y_val == 'SCAM').sum()}, Safe: {(y_val == 'SAFE').sum()})")

    # TF-IDF Vectorizer
    print("Fitting TF-IDF Vectorizer (1-2 ngrams)...")
    vectorizer = TfidfVectorizer(
        max_features=max_features,
        ngram_range=(1, 2),
        stop_words=None,  # keep Hinglish / Hindi tokens intact
        sublinear_tf=True,
    )
    X_train_tfidf = vectorizer.fit_transform(X_train_text)
    X_val_tfidf = vectorizer.transform(X_val_text)

    # Indicator Features
    X_train_ind = train_df[INDICATOR_COLS].values.astype(np.float64)
    X_val_ind = val_df[INDICATOR_COLS].values.astype(np.float64)

    # Hybrid Feature Space
    X_train_combined = hstack([X_train_tfidf, X_train_ind])
    X_val_combined = hstack([X_val_tfidf, X_val_ind])

    # Model Training
    print("Training Logistic Regression Model...")
    model = LogisticRegression(
        max_iter=1000,
        C=c_param,
        solver="lbfgs",
        random_state=random_state,
    )
    model.fit(X_train_combined, y_train)

    # Validation Evaluation
    y_pred = model.predict(X_val_combined)
    metrics = {
        "accuracy": round(float(accuracy_score(y_val, y_pred)), 4),
        "precision": round(float(precision_score(y_val, y_pred, pos_label="SCAM")), 4),
        "recall": round(float(recall_score(y_val, y_pred, pos_label="SCAM")), 4),
        "f1": round(float(f1_score(y_val, y_pred, pos_label="SCAM")), 4),
        "samples_train": len(train_df),
        "samples_val": len(val_df),
    }

    # Save to all target directories
    for out_dir in output_dirs:
        os.makedirs(out_dir, exist_ok=True)
        model_file = os.path.join(out_dir, "model.joblib")
        vec_file = os.path.join(out_dir, "vectorizer.joblib")
        met_file = os.path.join(out_dir, "metrics.json")

        joblib.dump(model, model_file)
        joblib.dump(vectorizer, vec_file)
        with open(met_file, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)
        print(f"[OK] Saved model artefacts to {out_dir}")

    return metrics


def main():
    parser = argparse.ArgumentParser(description="ASVD Demo — Train ML Classifier")
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR, help="Path to processed train/val/test data")
    parser.add_argument("--max-features", type=int, default=5000, help="Max TF-IDF features")
    parser.add_argument("--c", type=float, default=1.0, help="Inverse regularization parameter C")
    args = parser.parse_args()

    print("=" * 60)
    print("    ASVD 2.O — ML Scam Detection Model Training")
    print("=" * 60)

    metrics = train_model(
        data_dir=args.data_dir,
        max_features=args.max_features,
        c_param=args.c
    )

    print()
    print(f"Validation Metrics:")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1 Score:  {metrics['f1']:.4f}")
    print("=" * 60)


if __name__ == "__main__":
    main()
