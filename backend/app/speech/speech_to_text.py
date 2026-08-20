"""ASVD Demo — Speech-to-Text Processing Pipeline.

Handles:
- Ingestion of live audio buffers or streaming transcript segments
- Audio chunk transcription / normalization
- Conversation accumulation for multi-turn threat detection
"""

from typing import Optional, List


def transcribe_audio_chunk(audio_bytes: bytes, mock_text: Optional[str] = None) -> str:
    """Transcribe raw audio data to text.

    If mock_text is provided (e.g. from Web Speech API stream or test harness),
    it is normalized and returned.
    """
    if mock_text:
        return mock_text.strip()
    return ""


class SpeechPipeline:
    """Accumulates speech segments and provides complete conversation context."""

    def __init__(self, session_id: str = "default_session"):
        self.session_id = session_id
        self.transcript_chunks: List[str] = []

    def add_transcript_chunk(self, chunk: str) -> str:
        """Append a new transcript chunk and return the updated cumulative text."""
        cleaned = chunk.strip()
        if cleaned:
            self.transcript_chunks.append(cleaned)
        return self.get_full_transcript()

    def get_full_transcript(self) -> str:
        """Return the combined transcript of the entire ongoing call."""
        return " ".join(self.transcript_chunks).strip()

    def reset(self):
        """Clear conversation history."""
        self.transcript_chunks.clear()
