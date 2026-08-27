"""Integration tests for FastAPI REST Endpoints."""

from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_stats_endpoint():
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert "model" in data
    assert "database" in data


def test_analyse_endpoint_safe():
    payload = {
        "text": "Hello mummy, I reached office safely.",
        "session_id": "test-session-safe",
        "caller_id": "Mom"
    }
    response = client.post("/api/analyse", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["label"] == "SAFE"
    assert data["risk_score"] <= 25
    assert data["risk_level"] == "LOW"


def test_analyse_endpoint_scam():
    payload = {
        "text": "Urgent call from SBI. Share your 6-digit OTP right now or account will be blocked!",
        "session_id": "test-session-scam",
        "caller_id": "Fake Bank"
    }
    response = client.post("/api/analyse", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["label"] == "SCAM"
    assert data["risk_score"] >= 50
    assert "otp_request" in data["indicators"]


def test_history_endpoint():
    response = client.get("/api/history?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_analyse_endpoint_cumulative_context():
    """Verify /api/analyse accumulates conversation context across chunks in a session.

    Word-by-word ke baad risk score progressively badhna chahiye because the full
    conversation is passed to assess_risk each time, not just the latest chunk.
    """
    session_id = "test-session-cumulative-ctx"

    # Chunk 1: innocent opening — should be LOW risk on its own
    r1 = client.post("/api/analyse", json={
        "text": "Main SBI bank ka fraud prevention officer hoon.",
        "session_id": session_id,
        "caller_id": "Scammer"
    })
    assert r1.status_code == 200
    score1 = r1.json()["risk_score"]

    # Chunk 2: adds urgency + OTP demand — cumulative text should trigger SCAM
    r2 = client.post("/api/analyse", json={
        "text": "Aapka account block hone wala hai. Turant 6-digit OTP share karein.",
        "session_id": session_id,
        "caller_id": "Scammer"
    })
    assert r2.status_code == 200
    score2 = r2.json()["risk_score"]

    # Cumulative score should be >= first chunk score, and the second call
    # should detect SCAM since full conversation is now being evaluated
    assert score2 >= score1, (
        f"Cumulative risk score should not drop: got {score2} after {score1}"
    )
    assert r2.json()["label"] == "SCAM"

