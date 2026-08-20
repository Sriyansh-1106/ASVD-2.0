"""ASVD Demo - ML Classifier Tests.

TDD Red Phase: Tests written BEFORE the classifier is implemented.
Tests the TF-IDF + Logistic Regression pipeline for SCAM/SAFE classification.

Run:
    python -m pytest backend/tests/test_classifier.py -v
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))


MODEL_DIR = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "app", "model"
))


# ====================================================================
# 1. MODEL ARTEFACT EXISTENCE
# ====================================================================

class TestModelArtefacts:
    """Trained model files must exist after training."""

    def test_model_file_exists(self):
        assert os.path.isfile(os.path.join(MODEL_DIR, "model.joblib")), \
            "model.joblib not found — run train_classifier.py first"

    def test_vectorizer_file_exists(self):
        assert os.path.isfile(os.path.join(MODEL_DIR, "vectorizer.joblib")), \
            "vectorizer.joblib not found — run train_classifier.py first"

    def test_metrics_file_exists(self):
        assert os.path.isfile(os.path.join(MODEL_DIR, "metrics.json")), \
            "metrics.json not found — run train_classifier.py first"


# ====================================================================
# 2. TRAINING FUNCTION
# ====================================================================

class TestTrainingFunction:
    """The training function must work end-to-end."""

    def test_run_training_returns_metrics(self):
        from backend.app.model.train_classifier import run_training
        metrics = run_training()
        assert isinstance(metrics, dict)

    def test_metrics_has_required_keys(self):
        from backend.app.model.train_classifier import run_training
        metrics = run_training()
        required = ["accuracy", "precision", "recall", "f1", "samples_train", "samples_val"]
        for key in required:
            assert key in metrics, f"Missing metric: {key}"

    def test_accuracy_above_threshold(self):
        from backend.app.model.train_classifier import run_training
        metrics = run_training()
        assert metrics["accuracy"] >= 0.85, \
            f"Accuracy {metrics['accuracy']:.2f} is below 0.85 threshold"

    def test_f1_above_threshold(self):
        from backend.app.model.train_classifier import run_training
        metrics = run_training()
        assert metrics["f1"] >= 0.85, \
            f"F1 {metrics['f1']:.2f} is below 0.85 threshold"


# ====================================================================
# 3. PREDICTION FUNCTION
# ====================================================================

class TestPredictionFunction:
    """predict_conversation must return well-structured results."""

    def test_predict_returns_dict(self):
        from backend.app.model.predict import predict_conversation
        result = predict_conversation("Hello, how are you?")
        assert isinstance(result, dict)

    def test_predict_has_required_keys(self):
        from backend.app.model.predict import predict_conversation
        result = predict_conversation("Test message")
        required_keys = [
            "label", "confidence", "threat_level",
            "indicators", "indicator_count",
        ]
        for key in required_keys:
            assert key in result, f"Missing key: {key}"

    def test_label_is_scam_or_safe(self):
        from backend.app.model.predict import predict_conversation
        result = predict_conversation("Test message")
        assert result["label"] in ("SCAM", "SAFE")

    def test_confidence_is_float(self):
        from backend.app.model.predict import predict_conversation
        result = predict_conversation("Test message")
        assert isinstance(result["confidence"], float)
        assert 0.0 <= result["confidence"] <= 1.0

    def test_threat_level_is_valid(self):
        from backend.app.model.predict import predict_conversation
        result = predict_conversation("Test message")
        assert result["threat_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


# ====================================================================
# 4. KNOWN SCAM CONVERSATIONS
# ====================================================================

class TestKnownScamPredictions:
    """Known scam messages should be classified as SCAM."""

    def test_otp_scam(self):
        from backend.app.model.predict import predict_conversation
        result = predict_conversation(
            "Hello, customer care bol raha hoon. Aapke account mein "
            "problem hai. Jo OTP aaya hai wo bata dijiye turant."
        )
        assert result["label"] == "SCAM"

    def test_financial_scam(self):
        from backend.app.model.predict import predict_conversation
        result = predict_conversation(
            "Inspector Sharma bol raha hoon. Aapke khilaf FIR hai. "
            "Rs 2,00,000 turant transfer karo warna arrest ho jaoge."
        )
        assert result["label"] == "SCAM"

    def test_impersonation_scam(self):
        from backend.app.model.predict import predict_conversation
        result = predict_conversation(
            "Main aapka bhai bol raha hoon. Mera accident ho gaya hai. "
            "Rs 50,000 bhej do turant. Papa ko mat batana."
        )
        assert result["label"] == "SCAM"


# ====================================================================
# 5. KNOWN SAFE CONVERSATIONS
# ====================================================================

class TestKnownSafePredictions:
    """Normal conversations should be classified as SAFE."""

    def test_casual_conversation(self):
        from backend.app.model.predict import predict_conversation
        result = predict_conversation(
            "Kal movie dekhne chalein? Naya wala release hua hai."
        )
        assert result["label"] == "SAFE"

    def test_family_conversation(self):
        from backend.app.model.predict import predict_conversation
        result = predict_conversation(
            "Ghar pe dinner ke liye aa jana. Mummy ne biryani banayi hai."
        )
        assert result["label"] == "SAFE"

    def test_work_conversation(self):
        from backend.app.model.predict import predict_conversation
        result = predict_conversation(
            "Meeting 3 baje hai conference room mein. Presentation ready hai."
        )
        assert result["label"] == "SAFE"


# ====================================================================
# 6. INDICATORS INTEGRATION
# ====================================================================

class TestIndicatorsIntegration:
    """predict_conversation must also return detected indicators."""

    def test_scam_has_indicators(self):
        from backend.app.model.predict import predict_conversation
        result = predict_conversation(
            "Turant Rs 50,000 bhej do, OTP batao, kisi ko mat batana"
        )
        assert result["indicator_count"] > 0
        assert isinstance(result["indicators"], list)

    def test_safe_has_no_indicators(self):
        from backend.app.model.predict import predict_conversation
        result = predict_conversation(
            "Aaj ka dinner bahut achha tha, kal phir milte hain"
        )
        assert result["indicator_count"] == 0
