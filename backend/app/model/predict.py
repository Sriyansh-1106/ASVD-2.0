"""ASVD Demo - Prediction Helper.

Loads the trained model and vectorizer, runs the NLP indicator detector,
and returns a structured prediction result.

Usage:
    from backend.app.model.predict import predict_conversation
    result = predict_conversation("Turant Rs 50,000 bhej do, OTP batao")
"""

import os
import numpy as np
from scipy.sparse import hstack
import joblib

from backend.app.detection.indicators import detect_indicators, normalize_speech_text

# ====================================================================
# PATHS
# ====================================================================

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(MODEL_DIR, "model.joblib")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "vectorizer.joblib")

# Binary indicator column names (must match training order)
INDICATOR_COLS = [
    "urgency", "authority_impersonation", "financial_request",
    "otp_request", "credential_request", "threat_detected",
    "emotional_manipulation", "secrecy_request",
]

from typing import Any

# ====================================================================
# LAZY-LOADED GLOBALS (loaded once on first call)
# ====================================================================

_model: Any = None
_vectorizer: Any = None


def _load_model():
    """Load model and vectorizer from disk (once). Auto-trains if missing."""
    global _model, _vectorizer
    if _model is None:
        if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
            try:
                from ml.train import train_model
                train_model()
            except Exception as e:
                print(f"Auto-training fallback triggered: {e}")
        _model = joblib.load(MODEL_PATH)
        _vectorizer = joblib.load(VECTORIZER_PATH)


# ====================================================================
# THREAT LEVEL CALCULATION
# ====================================================================

def _calculate_threat_level(confidence: float, indicator_count: int) -> str:
    """Determine threat level from model confidence and indicator count.

    Rules:
        - CRITICAL: confidence >= 0.90 AND 4+ indicators
        - HIGH:     confidence >= 0.75 AND 3+ indicators
        - MEDIUM:   confidence >= 0.55 AND 1+ indicators
        - LOW:      everything else (safe conversations)
    """
    if confidence >= 0.90 and indicator_count >= 4:
        return "CRITICAL"
    elif confidence >= 0.75 and indicator_count >= 3:
        return "HIGH"
    elif confidence >= 0.55 and indicator_count >= 1:
        return "MEDIUM"
    else:
        return "LOW"


# ====================================================================
# PREDICTION FUNCTION
# ====================================================================

def predict_conversation(text: str) -> dict:
    """Predict whether a conversation is SCAM or SAFE.

    Args:
        text: Conversation text in English, Hindi, or Hinglish.

    Returns:
        dict with:
            - label: "SCAM" or "SAFE"
            - confidence: float 0.0-1.0
            - threat_level: "LOW", "MEDIUM", "HIGH", "CRITICAL"
            - indicators: list of detected indicator names
            - indicator_count: number of indicators detected
    """
    _load_model()
    assert _vectorizer is not None and _model is not None

    # Normalize accent & phonetic speech variations
    clean_text = normalize_speech_text(text or "")

    # 1. Run NLP indicator detection
    indicator_result = detect_indicators(clean_text)

    # 2. Build feature vector (TF-IDF + binary indicators)
    text_tfidf = _vectorizer.transform([clean_text])

    indicator_values = np.array([[
        1.0 if indicator_result.get(col, False) else 0.0
        for col in INDICATOR_COLS
    ]])

    X_combined = hstack([text_tfidf, indicator_values])

    # 3. Predict
    label = _model.predict(X_combined)[0]

    # 4. Get confidence (probability of the predicted class)
    probas = _model.predict_proba(X_combined)[0]
    class_index = list(_model.classes_).index(label)
    confidence = float(round(probas[class_index], 4))

    # 5. Calculate threat level
    indicator_count = indicator_result["indicator_count"]
    indicators = indicator_result["detected_list"]

    if label == "SAFE":
        threat_level = "LOW"
    else:
        threat_level = _calculate_threat_level(confidence, indicator_count)

    return {
        "label": label,
        "confidence": confidence,
        "threat_level": threat_level,
        "indicators": indicators,
        "indicator_count": indicator_count,
    }
