"""ASVD Demo — FastAPI Application Entry Point.

Creates and configures the FastAPI app with:
- CORS middleware
- API routes (/api/...)
- WebSocket endpoints (/ws/...)
- Static file serving for Frontend UI
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.app.api.routes import router as api_router
from backend.app.api.websocket import ws_router
from backend.app.database.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup: initialize database
    init_db()
    yield
    # Shutdown


app = FastAPI(
    title="ASVD 2.O — AI Scam Voice Detection API",
    description="Real-time voice-to-words-to-nlp-to-threat detection for cyber scams",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API and WebSocket routes
app.include_router(api_router)
app.include_router(ws_router)


# Mount frontend directory if exists
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")

if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/")
def root():
    """Root landing endpoint."""
    return {
        "app": "ASVD 2.O — AI Scam Voice Detection System",
        "status": "online",
        "docs_url": "/docs",
        "endpoints": {
            "health": "/api/health",
            "analyse": "/api/analyse",
            "stats": "/api/stats",
            "history": "/api/history",
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
