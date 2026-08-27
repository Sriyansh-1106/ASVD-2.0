"""ASVD Demo — ML Classifier Interface.

Provides a unified classification interface for cyber-scam detection
leveraging TF-IDF n-grams + binary indicator features with Logistic Regression.
"""

from typing import Dict, Any
from backend.app.model.predict import predict_conversation, _load_model


class ScamClassifier:
    """Classifier wrapper for ASVD scam voice detection."""

    def __init__(self):
        _load_model()

    def predict(self, text: str) -> Dict[str, Any]:
        """Predict whether the input transcript is SCAM or SAFE.

        Args:
            text: Conversation transcript in English, Hindi, or Hinglish.

        Returns:
            Dict containing label, confidence, threat_level, indicators, indicator_count.
        """
        return predict_conversation(text)

    def is_scam(self, text: str, threshold: float = 0.5) -> bool:
        """Convenience helper to check if text is classified as a scam."""
        res = self.predict(text)
        return res["label"] == "SCAM" and res["confidence"] >= threshold


# Singleton instance
classifier = ScamClassifier()


def classify_text(text: str) -> Dict[str, Any]:
    """Functional interface for text classification."""
    return classifier.predict(text)
