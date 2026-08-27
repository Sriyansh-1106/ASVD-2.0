"""ASVD Demo — Risk Scoring Engine.

Combines ML classification (Phase 3) with NLP indicator detection (Phase 2)
to produce a unified 0-100 risk score with human-readable explanations.

Usage:
    from backend.app.detection.risk_engine import assess_risk
    result = assess_risk("Turant Rs 50,000 bhej do, OTP batao")

Returns:
    dict with risk_score, risk_level, label, confidence, indicators,
    indicator_count, summary, and recommended_action.
"""

from backend.app.model.predict import predict_conversation



# ====================================================================
# INDICATOR WEIGHTS (for risk score calculation)
# ====================================================================

INDICATOR_WEIGHTS = {
    "urgency":                5,
    "financial_request":     10,
    "otp_request":           15,
    "credential_request":    15,
    "authority_impersonation": 10,
    "threat_detected":       10,
    "secrecy_request":        8,
    "emotional_manipulation":  7,
}

# Maximum possible indicator score
MAX_INDICATOR_SCORE = sum(INDICATOR_WEIGHTS.values())  # 80


# ====================================================================
# RISK LEVEL THRESHOLDS
# ====================================================================

def _score_to_level(score: int) -> str:
    """Map a 0-100 risk score to a risk level."""
    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    else:
        return "LOW"


# ====================================================================
# SUMMARY GENERATION
# ====================================================================

INDICATOR_DESCRIPTIONS = {
    "urgency":                "Urgency pressure detected",
    "financial_request":      "Financial/money request detected",
    "otp_request":            "OTP/verification code request detected",
    "credential_request":     "PIN/password/CVV request detected",
    "authority_impersonation": "Authority impersonation detected",
    "threat_detected":        "Threats/intimidation detected",
    "secrecy_request":        "Secrecy/isolation request detected",
    "emotional_manipulation": "Emotional manipulation detected",
}


def _generate_summary(label: str, confidence: float, indicators: list, risk_score: int) -> str:
    """Generate a human-readable risk summary."""
    if label == "SAFE":
        return "No threat detected. This appears to be a normal, safe conversation."

    # Build indicator breakdown
    parts = []
    for ind in indicators:
        desc = INDICATOR_DESCRIPTIONS.get(ind, ind)
        parts.append(desc)

    indicator_text = "; ".join(parts) if parts else "Suspicious patterns"

    if risk_score >= 75:
        severity = "CRITICAL threat"
    elif risk_score >= 50:
        severity = "HIGH threat"
    else:
        severity = "Suspicious activity"

    return (
        f"{severity} detected (confidence: {confidence:.0%}). "
        f"Indicators: {indicator_text}."
    )


# ====================================================================
# RECOMMENDED ACTIONS
# ====================================================================

def _generate_action(label: str, indicators: list) -> str:
    """Generate recommended action based on detected indicators."""
    if label == "SAFE":
        return "No action required. This appears to be a normal conversation."

    actions = []

    if "otp_request" in indicators or "credential_request" in indicators:
        actions.append(
            "Never share OTP, PIN, CVV, or passwords with anyone. "
            "Banks and officials will never ask for these over the phone."
        )

    if "authority_impersonation" in indicators:
        actions.append(
            "Verify the caller's identity by calling the official helpline "
            "number from the organisation's website."
        )

    if "financial_request" in indicators:
        actions.append(
            "Do not transfer money to unknown accounts. "
            "Verify the request through a trusted, independent channel."
        )

    if "threat_detected" in indicators:
        actions.append(
            "Do not panic. No legitimate authority threatens arrest or "
            "account blocking over the phone. Report to Cyber Crime helpline 1930."
        )

    if "secrecy_request" in indicators:
        actions.append(
            "Talk to a trusted family member or friend before taking any action."
        )

    if "emotional_manipulation" in indicators:
        actions.append(
            "Stay calm. Scammers fabricate fake hospital emergencies, accidents, or distress to extort money. Directly call your family member to verify."
        )

    if not actions:
        actions.append(
            "Exercise caution. Verify the caller's identity and purpose "
            "before sharing any personal information."
        )

    return " ".join(actions)


# ====================================================================
# MAIN ASSESSMENT FUNCTION
# ====================================================================

def assess_risk(text: str) -> dict:
    """Assess the risk level of a conversation.

    Combines ML classification with NLP indicator detection to produce
    a unified risk score (0-100) with human-readable explanations.

    Args:
        text: Conversation text in English, Hindi, or Hinglish.

    Returns:
        dict with:
            - risk_score: int 0-100
            - risk_level: LOW / MEDIUM / HIGH / CRITICAL
            - label: SCAM / SAFE
            - confidence: float 0-1
            - indicators: list of detected indicator names
            - indicator_count: int
            - summary: human-readable explanation
            - recommended_action: what the user should do
    """
    # Handle empty/None input
    if not text or not str(text).strip():
        return {
            "risk_score": 0,
            "risk_level": "LOW",
            "label": "SAFE",
            "confidence": 1.0,
            "indicators": [],
            "indicator_count": 0,
            "summary": "No threat detected. This appears to be a normal, safe conversation.",
            "recommended_action": "No action required. This appears to be a normal conversation.",
        }

    text = str(text).strip()

    # ------------------------------------------------------------------
    # 1. Run ML prediction (includes indicator detection internally)
    # ------------------------------------------------------------------
    prediction = predict_conversation(text)

    label = prediction["label"]
    confidence = prediction["confidence"]
    indicators = prediction["indicators"]
    indicator_count = prediction["indicator_count"]

    # ------------------------------------------------------------------
    # 2. Calculate risk score (0-100)
    #
    # Formula:
    #   - ML confidence contributes up to 50 points
    #   - Indicator weights contribute up to 50 points
    #   - Critical override: kidnapping, murder threats, OTP demands
    #     force score to CRITICAL (85-100)
    # ------------------------------------------------------------------
    has_critical_indicator = any(
        ind in indicators
        for ind in ["threat_detected", "otp_request", "credential_request"]
    )

    # Force label to SCAM if strong indicators or critical threat found
    if has_critical_indicator or indicator_count >= 2:
        label = "SCAM"
        confidence = max(confidence, 0.92)

    if label == "SAFE" and not indicators:
        risk_score = 0
    else:
        # ML component: confidence mapped to 0-50
        ml_score = confidence * 50

        # Indicator component: weighted sum
        indicator_score = 0
        for ind in indicators:
            indicator_score += INDICATOR_WEIGHTS.get(ind, 8)

        # Normalize indicator score to 0-50 range
        indicator_normalized = min((indicator_score / MAX_INDICATOR_SCORE) * 50, 50)
        risk_score = int(round(ml_score + indicator_normalized))

        # Critical Escalation Override
        if has_critical_indicator:
            # Kidnapping, physical threat, or OTP demands are always CRITICAL (85-100)
            bonus = 15 if "threat_detected" in indicators else 10
            risk_score = max(85, min(100, risk_score + bonus))
        elif indicator_count >= 2:
            risk_score = max(65, min(100, risk_score))

        risk_score = max(0, min(100, risk_score))  # clamp

    # ------------------------------------------------------------------
    # 3. Determine risk level
    # ------------------------------------------------------------------
    risk_level = _score_to_level(risk_score)

    # ------------------------------------------------------------------
    # 4. Generate human-readable outputs
    # ------------------------------------------------------------------
    summary = _generate_summary(label, confidence, indicators, risk_score)
    recommended_action = _generate_action(label, indicators)

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "label": label,
        "confidence": confidence,
        "indicators": indicators,
        "indicator_count": indicator_count,
        "summary": summary,
        "recommended_action": recommended_action,
    }
