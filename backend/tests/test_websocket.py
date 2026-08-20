"""ASVD Demo - Speech & WebSocket Tests.

Tests:
- SpeechToText processor / speech transcript accumulation
- ConnectionManager room management and threat streaming pipeline

Run:
    python -m pytest backend/tests/test_websocket.py -v
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))


from backend.app.speech.speech_to_text import transcribe_audio_chunk, SpeechPipeline
from backend.app.api.websocket import ConnectionManager
from backend.app.detection.risk_engine import assess_risk


# ====================================================================
# 1. SPEECH PIPELINE TESTS
# ====================================================================

class TestSpeechPipeline:
    """Test SpeechToText processor logic."""

    def test_transcribe_audio_chunk_text_fallback(self):
        result = transcribe_audio_chunk(b"fake_pcm_data", mock_text="Aapka OTP batao")
        assert result == "Aapka OTP batao"

    def test_speech_pipeline_accumulate(self):
        pipeline = SpeechPipeline()
        pipeline.add_transcript_chunk("Hello sir, ")
        pipeline.add_transcript_chunk("bank se bol rahe hain.")
        full_text = pipeline.get_full_transcript()
        assert full_text == "Hello sir, bank se bol rahe hain."

    def test_speech_pipeline_reset(self):
        pipeline = SpeechPipeline()
        pipeline.add_transcript_chunk("Initial chunk")
        pipeline.reset()
        assert pipeline.get_full_transcript() == ""


# ====================================================================
# 2. CONNECTION MANAGER & STREAMING TESTS
# ====================================================================

class DummyWebSocket:
    """Mock WebSocket for testing ConnectionManager."""
    def __init__(self):
        self.accepted = False
        self.sent_messages = []

    async def accept(self):
        self.accepted = True

    async def send_json(self, message: dict):
        self.sent_messages.append(message)


class TestWebSocketStreaming:
    """Test WebSocket session connection and threat detection streaming."""

    @pytest.mark.asyncio
    async def test_connection_manager_room_lifecycle(self):
        manager = ConnectionManager()
        ws1 = DummyWebSocket()
        ws2 = DummyWebSocket()

        await manager.connect(ws1, "session_test")
        await manager.connect(ws2, "session_test")

        assert len(manager.active_rooms["session_test"]) == 2

        # Broadcast test message
        test_payload = {"type": "ping", "data": "test"}
        await manager.broadcast_to_session("session_test", test_payload)

        assert len(ws1.sent_messages) == 1
        assert len(ws2.sent_messages) == 1
        assert ws1.sent_messages[0] == test_payload

        # Disconnect
        manager.disconnect(ws1, "session_test")
        assert len(manager.active_rooms["session_test"]) == 1
        manager.disconnect(ws2, "session_test")
        assert "session_test" not in manager.active_rooms

    def test_threat_assessment_integration_for_stream(self):
        sample_scam = "SBI fraud prevention team se call hai. Turant OTP batayein warna account block hoga."
        assessment = assess_risk(sample_scam)

        assert assessment["label"] == "SCAM"
        assert assessment["risk_score"] >= 50
        assert assessment["risk_level"] in ("HIGH", "CRITICAL")
        assert "otp_request" in assessment["indicators"]
