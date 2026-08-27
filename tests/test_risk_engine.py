"""Unit tests for ASVD Risk Scoring Engine."""

from backend.app.detection.risk_engine import assess_risk


def test_assess_risk_empty_input():
    res = assess_risk("")
    assert res["risk_score"] == 0
    assert res["risk_level"] == "LOW"
    assert res["label"] == "SAFE"


def test_assess_risk_safe_text():
    text = "Good morning team, let us review the quarterly report in the meeting today."
    res = assess_risk(text)
    assert res["label"] == "SAFE"
    assert res["risk_score"] <= 25
    assert res["risk_level"] == "LOW"


def test_assess_risk_critical_scam():
    text = (
        "Main Inspector Cyber Cell se bol raha hoon. Aapke khilaf arrest warrant hai. "
        "Turant Rs 1,00,000 transfer karo, OTP batao aur kisi ko mat batana."
    )
    res = assess_risk(text)
    assert res["label"] == "SCAM"
    assert res["risk_score"] >= 50
    assert res["risk_level"] in ["HIGH", "CRITICAL"]
    assert "recommended_action" in res
    assert len(res["indicators"]) >= 3
