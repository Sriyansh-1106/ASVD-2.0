"""ASVD Demo - Risk Engine Tests.

TDD Red Phase: Tests written BEFORE risk_engine.py is implemented.
Tests the unified risk scoring engine that combines ML classification
with NLP indicators to produce a 0-100 risk score.

Run:
    python -m pytest backend/tests/test_risk_engine.py -v
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))


from backend.app.detection.risk_engine import assess_risk


# ====================================================================
# 1. RETURN FORMAT
# ====================================================================

class TestReturnFormat:
    """assess_risk must return a well-structured result."""

    def test_returns_dict(self):
        result = assess_risk("Hello, how are you?")
        assert isinstance(result, dict)

    def test_has_required_keys(self):
        result = assess_risk("Test message")
        required_keys = [
            "risk_score",          # 0-100 integer
            "risk_level",          # LOW / MEDIUM / HIGH / CRITICAL
            "label",               # SCAM / SAFE
            "confidence",          # float 0-1
            "indicators",          # list of detected indicator names
            "indicator_count",     # int
            "summary",             # human-readable explanation
            "recommended_action",  # what the user should do
        ]
        for key in required_keys:
            assert key in result, f"Missing key: {key}"

    def test_risk_score_is_int(self):
        result = assess_risk("Test message")
        assert isinstance(result["risk_score"], int)

    def test_risk_score_in_range(self):
        result = assess_risk("Test message")
        assert 0 <= result["risk_score"] <= 100

    def test_summary_is_string(self):
        result = assess_risk("Test message")
        assert isinstance(result["summary"], str)
        assert len(result["summary"]) > 0

    def test_recommended_action_is_string(self):
        result = assess_risk("Test message")
        assert isinstance(result["recommended_action"], str)
        assert len(result["recommended_action"]) > 0


# ====================================================================
# 2. RISK SCORE RANGES
# ====================================================================

class TestRiskScoreRanges:
    """Risk scores must align with risk levels."""

    def test_safe_conversation_low_risk(self):
        result = assess_risk("Aaj mausam bahut achha hai, park chalein?")
        assert result["risk_score"] <= 25
        assert result["risk_level"] == "LOW"

    def test_casual_family_talk_low_risk(self):
        result = assess_risk("Ghar pe dinner ke liye aa jana. Biryani banayi hai.")
        assert result["risk_score"] <= 25
        assert result["risk_level"] == "LOW"

    def test_obvious_scam_high_risk(self):
        result = assess_risk(
            "Inspector Sharma bol raha hoon Cyber Crime se. "
            "Aapke khilaf FIR hai. Rs 2,00,000 turant transfer karo "
            "warna arrest ho jaoge. Kisi ko mat batana."
        )
        assert result["risk_score"] >= 75

    def test_otp_scam_high_risk(self):
        result = assess_risk(
            "SBI fraud prevention team se call hai. Aapke account se "
            "Rs 45,000 ka suspicious transaction hua. Turant OTP batayein."
        )
        assert result["risk_score"] >= 60


# ====================================================================
# 3. RISK LEVEL MAPPING
# ====================================================================

class TestRiskLevelMapping:
    """Risk level must match the score range."""

    def test_low_level_for_safe_message(self):
        result = assess_risk("Movie dekhne chalein Saturday ko?")
        assert result["risk_level"] == "LOW"
        assert result["label"] == "SAFE"

    def test_high_or_critical_for_scam(self):
        result = assess_risk(
            "Main aapka bhai bol raha hoon. Mera accident ho gaya hai. "
            "Rs 50,000 bhej do turant. Papa ko mat batana. Please help."
        )
        assert result["risk_level"] in ("HIGH", "CRITICAL")
        assert result["label"] == "SCAM"


# ====================================================================
# 4. SUMMARY GENERATION
# ====================================================================

class TestSummaryGeneration:
    """Summary must be meaningful and context-aware."""

    def test_safe_summary_mentions_safe(self):
        result = assess_risk("Kal office mein milte hain meeting ke liye")
        summary_lower = result["summary"].lower()
        assert "safe" in summary_lower or "normal" in summary_lower or "no threat" in summary_lower

    def test_scam_summary_mentions_indicators(self):
        result = assess_risk(
            "Turant Rs 50,000 bhej do, OTP batao, kisi ko mat batana"
        )
        summary_lower = result["summary"].lower()
        # Summary should mention at least one detected indicator
        assert any(word in summary_lower for word in [
            "urgency", "financial", "otp", "secrecy",
            "scam", "fraud", "suspicious", "threat",
        ])


# ====================================================================
# 5. RECOMMENDED ACTIONS
# ====================================================================

class TestRecommendedActions:
    """Recommended actions must be relevant to the threat type."""

    def test_safe_action(self):
        result = assess_risk("Biryani bahut achhi bani hai aaj")
        action_lower = result["recommended_action"].lower()
        assert any(word in action_lower for word in [
            "no action", "normal", "safe", "no threat",
        ])

    def test_otp_scam_action_warns_about_otp(self):
        result = assess_risk(
            "Customer care se call hai, OTP bata dijiye verification ke liye"
        )
        if result["label"] == "SCAM":
            action_lower = result["recommended_action"].lower()
            assert any(word in action_lower for word in [
                "otp", "share", "never", "verify", "bank", "official",
            ])

    def test_financial_scam_action_warns_about_money(self):
        result = assess_risk(
            "Rs 1,00,000 turant transfer karo nahi toh jail hogi"
        )
        if result["label"] == "SCAM":
            action_lower = result["recommended_action"].lower()
            assert any(word in action_lower for word in [
                "transfer", "money", "pay", "verify", "official", "never",
            ])


# ====================================================================
# 6. EDGE CASES
# ====================================================================

class TestEdgeCases:
    """Handle edge cases gracefully."""

    def test_empty_string(self):
        result = assess_risk("")
        assert result["risk_score"] == 0
        assert result["risk_level"] == "LOW"
        assert result["label"] == "SAFE"

    def test_none_input(self):
        result = assess_risk(None)
        assert result["risk_score"] == 0
        assert result["risk_level"] == "LOW"

    def test_very_short_message(self):
        result = assess_risk("Hi")
        assert isinstance(result["risk_score"], int)
        assert result["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_long_safe_message(self):
        long_msg = "Aaj bahut achha din hai. " * 50
        result = assess_risk(long_msg)
        assert result["risk_level"] == "LOW"
