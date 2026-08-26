"""ASVD Demo — REST API Routes.

FastAPI route handlers for:
- POST /api/analyse — analyse conversation text
- GET /api/health — health check endpoint
- GET /api/stats — dataset and model statistics
- GET /api/history — recent analysis logs
"""

import os
import json
from typing import Optional, List
from fastapi import APIRouter
from pydantic import BaseModel, Field


from backend.app.detection.risk_engine import assess_risk
from backend.app.database.database import save_analysis, get_recent_history, get_db_stats

router = APIRouter(prefix="/api", tags=["Detection API"])

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
METRICS_PATH = os.path.join(PROJECT_ROOT, "backend", "app", "model", "metrics.json")
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
DATASET_CSV = os.path.join(DATA_DIR, "synthetic_cyber_calls.csv")


# ====================================================================
# REQUEST / RESPONSE SCHEMAS
# ====================================================================

class AnalyseRequest(BaseModel):
    text: str = Field(default="", description="Conversation text/transcript to analyse")
    session_id: Optional[str] = Field(default=None, description="Optional call/session ID")
    caller_id: Optional[str] = Field(default=None, description="Optional caller name or number")


class AnalyseResponse(BaseModel):
    id: Optional[int] = None
    risk_score: int
    risk_level: str
    label: str
    confidence: float
    indicators: List[str]
    indicator_count: int
    summary: str
    recommended_action: str


# ====================================================================
# ROUTES
# ====================================================================

@router.get("/health")
def health_check():
    """Health check endpoint."""
    return {
        "status": "ok",
        "service": "ASVD 2.O Scam Voice Detection Engine",
        "version": "2.0.0"
    }


from backend.app.api.websocket import manager

@router.post("/analyse", response_model=AnalyseResponse)
async def analyse_text(request: AnalyseRequest):
    """Analyse conversation text for cyber scam indicators and risk score."""
    assessment = assess_risk(request.text)
    
    # Persist analysis to database
    record_id = save_analysis(
        conversation_text=request.text,
        assessment=assessment,
        session_id=request.session_id,
        caller_id=request.caller_id,
    )

    # Broadcast to WebSocket room if session provided
    if request.session_id:
        await manager.broadcast_to_session(request.session_id, {
            "type": "threat_alert",
            "session_id": request.session_id,
            "chunk": request.text,
            "full_transcript": request.text,
            "data": assessment,
        })
    
    return {
        "id": record_id,
        **assessment,
    }


@router.get("/stats")
def get_system_stats():
    """Return model performance metrics and dataset statistics."""
    model_metrics = {}
    if os.path.exists(METRICS_PATH):
        try:
            with open(METRICS_PATH, "r", encoding="utf-8") as f:
                model_metrics = json.load(f)
        except Exception:
            pass

    db_stats = get_db_stats()

    return {
        "model": model_metrics,
        "database": db_stats,
        "status": "operational",
    }


from fastapi import Request, UploadFile, File, Form
from backend.app.speech.speech_to_text import transcribe_audio_chunk

@router.post("/speech_to_text")
async def speech_to_text_endpoint(
    audio: Optional[UploadFile] = File(None),
    language: str = Form("en-IN"),
    session_id: Optional[str] = Form("live-call-001"),
    caller_id: Optional[str] = Form("Live Caller")
):
    """Receive raw voice audio file from browser microphone, transcribe to text, and run threat assessment."""
    if not audio:
        return {"text": "", "threat": None}

    audio_bytes = await audio.read()
    transcribed_text = transcribe_audio_chunk(audio_bytes, language=language)

    assessment = None
    if transcribed_text:
        assessment = assess_risk(transcribed_text)
        save_analysis(
            conversation_text=transcribed_text,
            assessment=assessment,
            session_id=session_id,
            caller_id=caller_id,
        )
        if session_id:
            await manager.broadcast_to_session(session_id, {
                "type": "threat_alert",
                "session_id": session_id,
                "chunk": transcribed_text,
                "full_transcript": transcribed_text,
                "data": assessment,
            })

    return {
        "text": transcribed_text,
        "threat": assessment
    }


@router.get("/history")
def get_history(limit: int = 50):
    """Return recent scan and detection logs."""
    return get_recent_history(limit=limit)
