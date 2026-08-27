"""Unit tests for ASVD NLP Indicator Detection Engine."""

from backend.app.detection.indicators import detect_indicators


def test_detect_urgency():
    text = "Turant paise bhejo, jaldi karo abhi ke abhi"
    res = detect_indicators(text)
    assert res["urgency"] is True
    assert "urgency" in res["detected_list"]


def test_detect_otp_request():
    text = "Aapke phone par 6-digit OTP aaya hai, jaldi share karein"
    res = detect_indicators(text)
    assert res["otp_request"] is True
    assert "otp_request" in res["detected_list"]


def test_detect_credential_request():
    text = "Debit card ka CVV aur ATM PIN share karein account verification ke liye"
    res = detect_indicators(text)
    assert res["credential_request"] is True
    assert "credential_request" in res["detected_list"]


def test_detect_authority_impersonation():
    text = "Main Police Cyber Crime branch se Inspector bol raha hoon"
    res = detect_indicators(text)
    assert res["authority_impersonation"] is True
    assert "authority_impersonation" in res["detected_list"]


def test_detect_financial_request():
    text = "Rs 50,000 transfer karo mere bank account mein"
    res = detect_indicators(text)
    assert res["financial_request"] is True
    assert "financial_request" in res["detected_list"]


def test_detect_threat():
    text = "Agar paise nahi diye toh FIR hogi aur arrest warrant issue hoga"
    res = detect_indicators(text)
    assert res["threat_detected"] is True
    assert "threat_detected" in res["detected_list"]


def test_detect_secrecy():
    text = "Yeh baat kisi ko mat batana, bilkul secret rakhna"
    res = detect_indicators(text)
    assert res["secrecy_request"] is True
    assert "secrecy_request" in res["detected_list"]


def test_detect_safe_conversation():
    text = "Mummy main sham ko 7 baje ghar aaunga, dinner sath mein karenge"
    res = detect_indicators(text)
    assert res["indicator_count"] == 0
    assert len(res["detected_list"]) == 0


def test_detect_hospital_emergency_manipulation():
    text = "Unki tabiyat bahut kharab hai hospital mein admit hai please paise bhejo"
    res = detect_indicators(text)
    assert res["emotional_manipulation"] is True
    assert "emotional_manipulation" in res["detected_list"]

