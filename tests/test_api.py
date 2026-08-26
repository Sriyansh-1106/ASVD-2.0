"""Integration tests for FastAPI REST Endpoints."""

import pytest
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
