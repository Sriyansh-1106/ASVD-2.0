"""ASVD Demo - FastAPI Backend Tests.

TDD Red Phase: Tests written BEFORE API endpoints and database logic are implemented.
Tests REST API endpoints:
- GET /api/health
- POST /api/analyse
- GET /api/stats
- GET /api/history

Run:
    python -m pytest backend/tests/test_api.py -v
"""

import sys
import os
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))


from backend.app.main import app

client = TestClient(app)


# ====================================================================
# 1. HEALTH CHECK ENDPOINT
# ====================================================================

class TestHealthEndpoint:
    """Test /api/health endpoint."""

    def test_health_returns_200(self):
        response = client.get("/api/health")
        assert response.status_code == 200

    def test_health_response_structure(self):
        response = client.get("/api/health")
        data = response.json()
        assert data.get("status") == "ok"
        assert "version" in data


# ====================================================================
# 2. ANALYSE ENDPOINT
# ====================================================================

class TestAnalyseEndpoint:
    """Test POST /api/analyse endpoint."""

    def test_analyse_scam_text(self):
        payload = {
            "text": "SBI fraud prevention team se call hai. Aapke account se Rs 45,000 deduct hue hain. Turant OTP batayein."
        }
        response = client.post("/api/analyse", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert data["label"] == "SCAM"
        assert data["risk_score"] > 50
        assert data["risk_level"] in ("HIGH", "CRITICAL")
        assert "otp_request" in data["indicators"]
        assert "summary" in data
        assert "recommended_action" in data

    def test_analyse_safe_text(self):
        payload = {
            "text": "Hi mummy, main market mein hoon. Shaam ko 7 baje dinner ke liye ghar aa jaunga."
        }
        response = client.post("/api/analyse", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert data["label"] == "SAFE"
        assert data["risk_score"] == 0
        assert data["risk_level"] == "LOW"
        assert data["indicators"] == []

    def test_analyse_empty_text(self):
        payload = {"text": ""}
        response = client.post("/api/analyse", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["risk_score"] == 0
        assert data["risk_level"] == "LOW"

    def test_analyse_missing_body(self):
        response = client.post("/api/analyse", json={})
        # Empty text defaults or returns 422 if required
        assert response.status_code in (200, 422)


# ====================================================================
# 3. STATS & HISTORY ENDPOINTS
# ====================================================================

class TestStatsAndHistoryEndpoints:
    """Test /api/stats and /api/history endpoints."""

    def test_get_stats(self):
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert "dataset" in data or "model" in data or "total_scans" in data

    def test_get_history(self):
        # Post one item first
        client.post("/api/analyse", json={"text": "Hello test call for history"})
        response = client.get("/api/history")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
