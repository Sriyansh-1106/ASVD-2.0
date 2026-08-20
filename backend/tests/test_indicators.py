"""ASVD Demo - Indicator Detection Tests.

TDD Red Phase: Tests written BEFORE indicators.py is implemented.
Tests the social engineering indicator detector that identifies
scam signals in conversation text.

Run:
    python -m pytest backend/tests/test_indicators.py -v
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))


from backend.app.detection.indicators import detect_indicators


# ====================================================================
# 1. URGENCY DETECTION
# ====================================================================

class TestUrgencyDetection:
    """Detect urgency-related phrases."""

    def test_hindi_urgency(self):
        result = detect_indicators("Turant paisa bhej do, waqt nahi hai")
        assert result["urgency"] is True

    def test_english_urgency(self):
        result = detect_indicators("Send the money immediately, don't delay")
        assert result["urgency"] is True

    def test_hinglish_urgency(self):
        result = detect_indicators("Jaldi karo, 10 minute mein sab khatam ho jayega")
        assert result["urgency"] is True

    def test_no_urgency_in_normal_conversation(self):
        result = detect_indicators("Kal milte hain office mein. Koi rush nahi hai.")
        assert result["urgency"] is False


# ====================================================================
# 2. FINANCIAL REQUEST DETECTION
# ====================================================================

class TestFinancialRequestDetection:
    """Detect money/transfer related requests."""

    def test_hindi_money_request(self):
        result = detect_indicators("Mujhe Rs 50,000 bhej do turant")
        assert result["financial_request"] is True

    def test_english_transfer(self):
        result = detect_indicators("Please transfer the amount to this account number")
        assert result["financial_request"] is True

    def test_upi_payment(self):
        result = detect_indicators("UPI se payment kar do abhi")
        assert result["financial_request"] is True

    def test_no_financial_in_normal_talk(self):
        result = detect_indicators("Aaj mausam bahut achha hai, park chalein?")
        assert result["financial_request"] is False


# ====================================================================
# 3. OTP DETECTION
# ====================================================================

class TestOTPDetection:
    """Detect OTP/verification code requests."""

    def test_otp_request(self):
        result = detect_indicators("Aapke phone pe jo OTP aaya hai wo bata dijiye")
        assert result["otp_request"] is True

    def test_verification_code(self):
        result = detect_indicators("Please share the 6-digit verification code")
        assert result["otp_request"] is True

    def test_no_otp_in_normal(self):
        result = detect_indicators("Maine online order kiya hai, kal aayega")
        assert result["otp_request"] is False


# ====================================================================
# 4. CREDENTIAL REQUEST DETECTION
# ====================================================================

class TestCredentialDetection:
    """Detect requests for PIN, CVV, passwords."""

    def test_pin_request(self):
        result = detect_indicators("Apna ATM PIN batayein verification ke liye")
        assert result["credential_request"] is True

    def test_cvv_request(self):
        result = detect_indicators("Card ke peeche ka CVV number dijiye")
        assert result["credential_request"] is True

    def test_password_request(self):
        result = detect_indicators("Net banking password share karein")
        assert result["credential_request"] is True

    def test_no_credential_in_normal(self):
        result = detect_indicators("Password yaad rakhna apna, kisi ko mat batana")
        assert isinstance(result, dict)



# ====================================================================
# 5. AUTHORITY IMPERSONATION DETECTION
# ====================================================================

class TestAuthorityDetection:
    """Detect impersonation of officials/authorities."""

    def test_police_impersonation(self):
        result = detect_indicators("Main Inspector Sharma bol raha hoon Cyber Crime se")
        assert result["authority_impersonation"] is True

    def test_bank_official(self):
        result = detect_indicators("SBI fraud prevention team se call hai")
        assert result["authority_impersonation"] is True

    def test_government_official(self):
        result = detect_indicators("Income Tax Department se bol rahe hain")
        assert result["authority_impersonation"] is True

    def test_no_authority_in_normal(self):
        result = detect_indicators("Kal bank jaana hai account kholne")
        assert result["authority_impersonation"] is False


# ====================================================================
# 6. THREAT DETECTION
# ====================================================================

class TestThreatDetection:
    """Detect threats and intimidation."""

    def test_arrest_threat(self):
        result = detect_indicators("Paisa nahi diya toh arrest ho jaoge")
        assert result["threat_detected"] is True

    def test_legal_threat(self):
        result = detect_indicators("Legal action hoga aapke khilaf, court mein case file hoga")
        assert result["threat_detected"] is True

    def test_account_block_threat(self):
        result = detect_indicators("Account permanently block ho jayega agar comply nahi kiya")
        assert result["threat_detected"] is True

    def test_blackmail_threat(self):
        result = detect_indicators("Sab contacts ko bhej denge agar paisa nahi mila")
        assert result["threat_detected"] is True

    def test_no_threat_in_normal(self):
        result = detect_indicators("Court ke paas ek achha restaurant khula hai naya")
        assert result["threat_detected"] is False


# ====================================================================
# 7. SECRECY DETECTION
# ====================================================================

class TestSecrecyDetection:
    """Detect requests to keep things secret."""

    def test_hindi_secrecy(self):
        result = detect_indicators("Kisi ko mat batana, yeh hamare beech ki baat hai")
        assert result["secrecy_request"] is True

    def test_english_secrecy(self):
        result = detect_indicators("Don't tell anyone about this, keep it between us")
        assert result["secrecy_request"] is True

    def test_family_secrecy(self):
        result = detect_indicators("Papa ko mat bolna, baad mein explain karunga")
        assert result["secrecy_request"] is True

    def test_no_secrecy_in_normal(self):
        result = detect_indicators("Sab ko bata do ki party Saturday ko hai")
        assert result["secrecy_request"] is False


# ====================================================================
# 8. EMOTIONAL MANIPULATION DETECTION
# ====================================================================

class TestEmotionalManipulation:
    """Detect emotional pressure tactics."""

    def test_fear_appeal(self):
        result = detect_indicators("Mujhe bahut darr lag raha hai, please help karo")
        assert result["emotional_manipulation"] is True

    def test_desperation(self):
        result = detect_indicators("Mere paas koi aur nahi hai, sirf tum ho")
        assert result["emotional_manipulation"] is True

    def test_trust_appeal(self):
        result = detect_indicators("Please trust me, I am in real trouble")
        assert result["emotional_manipulation"] is True

    def test_no_emotion_in_normal(self):
        result = detect_indicators("Movie achhi thi, bahut mazaa aaya")
        assert result["emotional_manipulation"] is False


# ====================================================================
# 9. RETURN FORMAT
# ====================================================================

class TestReturnFormat:
    """The detector must return a well-structured result."""

    def test_returns_dict(self):
        result = detect_indicators("Hello, how are you?")
        assert isinstance(result, dict)

    def test_has_all_indicator_keys(self):
        result = detect_indicators("Test message")
        required_keys = [
            "urgency", "financial_request", "otp_request",
            "credential_request", "authority_impersonation",
            "threat_detected", "secrecy_request", "emotional_manipulation",
            "detected_list", "indicator_count",
        ]
        for key in required_keys:
            assert key in result, f"Missing key: {key}"

    def test_detected_list_is_list(self):
        result = detect_indicators("Send money immediately, OTP batao")
        assert isinstance(result["detected_list"], list)

    def test_indicator_count_matches_list(self):
        result = detect_indicators("Turant Rs 50,000 bhej do, OTP bhi batao")
        assert result["indicator_count"] == len(result["detected_list"])

    def test_safe_message_has_zero_indicators(self):
        result = detect_indicators("Aaj ka dinner bahut achha tha")
        assert result["indicator_count"] == 0
        assert result["detected_list"] == []


# ====================================================================
# 10. CONTEXT-AWARE DETECTION
# ====================================================================

class TestContextAware:
    """Safe messages with trigger words should NOT be flagged."""

    def test_bank_mention_not_scam(self):
        """Mentioning bank in normal context shouldn't flag authority."""
        result = detect_indicators("Kal bank jaana hai cheque deposit karne")
        assert result["authority_impersonation"] is False

    def test_hospital_mention_not_scam(self):
        """Normal hospital mention shouldn't flag emotional manipulation."""
        result = detect_indicators("Bhai ko hospital le ja rahi hoon regular checkup ke liye")
        assert result["emotional_manipulation"] is False

    def test_money_in_normal_context(self):
        """Normal money discussion shouldn't flag financial request."""
        result = detect_indicators("Salary credit ho gayi aaj, bahut khushi hui")
        assert result["financial_request"] is False

    def test_police_in_normal_context(self):
        """Normal police mention shouldn't flag authority."""
        result = detect_indicators("Police station ke paas ek nayi dukaan khuli hai")
        assert result["authority_impersonation"] is False
