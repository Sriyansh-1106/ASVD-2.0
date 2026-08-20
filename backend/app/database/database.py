"""ASVD Demo — SQLite Database Storage.

Manages SQLite storage for:
- Analysis logs
- Session statistics
- Call transcripts & threat detection records
"""

import sqlite3
import os
import json
from typing import List, Dict, Any, Optional


DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DB_DIR, "asvd_history.db")


def get_db_connection() -> sqlite3.Connection:
    """Create a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database tables if they do not exist."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS call_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                caller_id TEXT,
                conversation_text TEXT,
                label TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                confidence REAL,
                indicators TEXT,
                indicator_count INTEGER,
                summary TEXT,
                recommended_action TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


def save_analysis(
    conversation_text: str,
    assessment: Dict[str, Any],
    session_id: Optional[str] = None,
    caller_id: Optional[str] = None,
) -> int:
    """Save an analysis record to the database."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO call_logs (
                session_id, caller_id, conversation_text, label,
                risk_score, risk_level, confidence, indicators,
                indicator_count, summary, recommended_action
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id or "demo_session",
            caller_id or "Unknown Caller",
            conversation_text,
            assessment.get("label", "SAFE"),
            assessment.get("risk_score", 0),
            assessment.get("risk_level", "LOW"),
            assessment.get("confidence", 0.0),
            json.dumps(assessment.get("indicators", [])),
            assessment.get("indicator_count", 0),
            assessment.get("summary", ""),
            assessment.get("recommended_action", ""),
        ))
        conn.commit()
        return cursor.lastrowid


def get_recent_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve recent call analysis logs."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM call_logs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        
        results = []
        for row in rows:
            item = dict(row)
            try:
                item["indicators"] = json.loads(item["indicators"]) if item["indicators"] else []
            except Exception:
                item["indicators"] = []
            results.append(item)
        return results


def get_db_stats() -> Dict[str, Any]:
    """Retrieve aggregate scan statistics."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM call_logs")
        total_scans = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM call_logs WHERE label = 'SCAM'")
        scam_scans = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM call_logs WHERE label = 'SAFE'")
        safe_scans = cursor.fetchone()[0]

        return {
            "total_scans": total_scans,
            "scam_detected": scam_scans,
            "safe_calls": safe_scans,
        }
