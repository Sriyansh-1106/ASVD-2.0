"""ASVD Demo - Train TF-IDF + Logistic Regression Classifier.

Loads the processed train/val CSVs, builds a TF-IDF vectorizer over
conversation_text, concatenates binary indicator columns, trains a
Logistic Regression model, evaluates it, and saves artefacts.

Usage:
    python -m backend.app.model.train_classifier

Outputs:
    backend/app/model/model.joblib
    backend/app/model/vectorizer.joblib
    backend/app/model/metrics.json
"""

import os
import sys
import json

import numpy as np
import pandas as pd
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib

# ====================================================================
# PATHS
# ====================================================================

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
MODEL_DIR = os.path.dirname(os.path.abspath(__file__))

TRAIN_PATH = os.path.join(DATA_DIR, "train.csv")
VAL_PATH = os.path.join(DATA_DIR, "val.csv")

MODEL_PATH = os.path.join(MODEL_DIR, "model.joblib")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "vectorizer.joblib")
METRICS_PATH = os.path.join(MODEL_DIR, "metrics.json")

# Binary indicator columns used as extra features
INDICATOR_COLS = [
    "urgency", "authority_impersonation", "financial_request",
    "otp_request", "credential_request", "threat_detected",
    "emotional_manipulation", "secrecy_request",
]


# ====================================================================
# TRAINING PIPELINE
# ====================================================================

def run_training() -> dict:
    """Train the classifier and return evaluation metrics.

    Returns:
        dict with accuracy, precision, recall, f1, samples_train, samples_val.
    """
    # ------------------------------------------------------------------
    # 1. Load data
    # ------------------------------------------------------------------
    train_df = pd.read_csv(TRAIN_PATH, encoding="utf-8-sig")
    val_df = pd.read_csv(VAL_PATH, encoding="utf-8-sig")

    X_train_text = train_df["conversation_text"].fillna("").astype(str)
    X_val_text = val_df["conversation_text"].fillna("").astype(str)

    y_train = train_df["label"]
    y_val = val_df["label"]

    # ------------------------------------------------------------------
    # 2. TF-IDF on conversation text
    # ------------------------------------------------------------------
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        stop_words=None,       # keep Hindi/Hinglish words
        sublinear_tf=True,
    )

    X_train_tfidf = vectorizer.fit_transform(X_train_text)
    X_val_tfidf = vectorizer.transform(X_val_text)

    # ------------------------------------------------------------------
    # 3. Concatenate binary indicator columns
    # ------------------------------------------------------------------
    X_train_indicators = train_df[INDICATOR_COLS].values.astype(np.float64)
    X_val_indicators = val_df[INDICATOR_COLS].values.astype(np.float64)

    X_train_combined = hstack([X_train_tfidf, X_train_indicators])
    X_val_combined = hstack([X_val_tfidf, X_val_indicators])

    # ------------------------------------------------------------------
    # 4. Train Logistic Regression
    # ------------------------------------------------------------------
    model = LogisticRegression(
        max_iter=1000,
        C=1.0,
        solver="lbfgs",
        random_state=42,
    )
    model.fit(X_train_combined, y_train)

    # ------------------------------------------------------------------
    # 5. Evaluate
    # ------------------------------------------------------------------
    y_pred = model.predict(X_val_combined)

    metrics = {
        "accuracy": round(accuracy_score(y_val, y_pred), 4),
        "precision": round(precision_score(y_val, y_pred, pos_label="SCAM"), 4),
        "recall": round(recall_score(y_val, y_pred, pos_label="SCAM"), 4),
        "f1": round(f1_score(y_val, y_pred, pos_label="SCAM"), 4),
        "samples_train": len(train_df),
        "samples_val": len(val_df),
    }

    # ------------------------------------------------------------------
    # 6. Save artefacts
    # ------------------------------------------------------------------
    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)

    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    return metrics


# ====================================================================
# CLI ENTRY POINT
# ====================================================================

if __name__ == "__main__":
    # Reconfigure stdout for Windows
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    print("=" * 55)
    print("    ASVD Demo - Training ML Classifier")
    print("=" * 55)
    print()

    m = run_training()

    print(f"  Samples (train):  {m['samples_train']:,}")
    print(f"  Samples (val):    {m['samples_val']:,}")
    print()
    print(f"  Accuracy:         {m['accuracy']:.4f}")
    print(f"  Precision:        {m['precision']:.4f}")
    print(f"  Recall:           {m['recall']:.4f}")
    print(f"  F1 Score:         {m['f1']:.4f}")
    print()
    print(f"  [OK] Saved: {MODEL_PATH}")
    print(f"  [OK] Saved: {VECTORIZER_PATH}")
    print(f"  [OK] Saved: {METRICS_PATH}")
    print()
    print("=" * 55)
    print("  Training complete!")
    print("=" * 55)
