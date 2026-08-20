"""ASVD Demo — WebSocket Real-Time Threat Detection Handler.

Manages active connections between:
- Caller Device (Device 1 - Audio/Speech input)
- Receiver Device (Device 2 - Real-time Threat HUD)
- Risk Scoring & Threat Engine Pipeline

Flow:
Voice/Speech -> NLP Indicators -> ML Classification -> Risk Assessment -> WebSocket Broadcast
"""

import json
from typing import Dict, List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.app.detection.risk_engine import assess_risk
from backend.app.database.database import save_analysis
from backend.app.speech.speech_to_text import SpeechPipeline

ws_router = APIRouter(tags=["WebSocket Realtime"])


class ConnectionManager:
    """Manages multi-device WebSocket rooms for live call scam detection."""

    def __init__(self):
        # session_id -> list of active websockets
        self.active_rooms: Dict[str, List[WebSocket]] = {}
        # session_id -> SpeechPipeline
        self.session_pipelines: Dict[str, SpeechPipeline] = {}

    async def connect(self, websocket: WebSocket, session_id: str):
        await websocket.accept()
        if session_id not in self.active_rooms:
            self.active_rooms[session_id] = []
            self.session_pipelines[session_id] = SpeechPipeline(session_id)
        self.active_rooms[session_id].append(websocket)

    def disconnect(self, websocket: WebSocket, session_id: str):
        if session_id in self.active_rooms:
            if websocket in self.active_rooms[session_id]:
                self.active_rooms[session_id].remove(websocket)
            if not self.active_rooms[session_id]:
                del self.active_rooms[session_id]
                if session_id in self.session_pipelines:
                    del self.session_pipelines[session_id]

    async def broadcast_to_session(self, session_id: str, message: dict):
        """Send message to all devices in the session room."""
        if session_id in self.active_rooms:
            for connection in self.active_rooms[session_id]:
                try:
                    await connection.send_json(message)
                except Exception:
                    pass

    def get_pipeline(self, session_id: str) -> SpeechPipeline:
        if session_id not in self.session_pipelines:
            self.session_pipelines[session_id] = SpeechPipeline(session_id)
        return self.session_pipelines[session_id]


manager = ConnectionManager()


@ws_router.websocket("/ws/call/{session_id}")
async def websocket_call_endpoint(websocket: WebSocket, session_id: str, role: str = "receiver"):
    """WebSocket endpoint for real-time scam detection streaming.

    Roles:
    - 'caller': Transmits live audio transcription chunks
    - 'receiver': Receives live transcript + threat detection alerts
    """
    await manager.connect(websocket, session_id)
    pipeline = manager.get_pipeline(session_id)

    try:
        # Broadcast user connection event
        await manager.broadcast_to_session(session_id, {
            "type": "device_status",
            "role": role,
            "status": "connected",
            "session_id": session_id,
        })

        while True:
            raw_data = await websocket.receive_text()
            try:
                msg = json.loads(raw_data)
            except Exception:
                msg = {"text": raw_data, "type": "audio_transcript"}

            msg_type = msg.get("type", "audio_transcript")

            if msg_type == "audio_transcript":
                chunk_text = msg.get("text", "").strip()
                if chunk_text:
                    # Accumulate ongoing conversation transcript
                    cumulative_transcript = pipeline.add_transcript_chunk(chunk_text)

                    # Run Real-Time Scam Assessment Pipeline
                    assessment = assess_risk(cumulative_transcript)

                    # Save to database log if final or high threat
                    if msg.get("is_final", False) or assessment["risk_score"] >= 50:
                        save_analysis(
                            conversation_text=cumulative_transcript,
                            assessment=assessment,
                            session_id=session_id,
                            caller_id=msg.get("caller_id", "Live Caller"),
                        )

                    # Broadcast Threat Alert & Live Transcript to Receiver device
                    broadcast_payload = {
                        "type": "threat_alert",
                        "session_id": session_id,
                        "chunk": chunk_text,
                        "full_transcript": cumulative_transcript,
                        "data": assessment,
                    }
                    await manager.broadcast_to_session(session_id, broadcast_payload)

            elif msg_type == "call_start":
                pipeline.reset()
                await manager.broadcast_to_session(session_id, {
                    "type": "call_status",
                    "status": "active",
                    "caller_id": msg.get("caller_id", "Unknown Caller"),
                })

            elif msg_type == "call_end":
                await manager.broadcast_to_session(session_id, {
                    "type": "call_status",
                    "status": "ended",
                })
                pipeline.reset()

            elif msg_type == "ping":
                await websocket.send_json({"type": "pong"})

    except WebSocketDisconnect:
        manager.disconnect(websocket, session_id)
        await manager.broadcast_to_session(session_id, {
            "type": "device_status",
            "role": role,
            "status": "disconnected",
            "session_id": session_id,
        })
