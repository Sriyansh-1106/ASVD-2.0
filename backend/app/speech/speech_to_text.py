"""ASVD Demo — Speech-to-Text Processing Pipeline.

Handles:
- Ingestion of live audio buffers or streaming transcript segments
- Audio chunk transcription / normalization
- Conversation accumulation for multi-turn threat detection
"""

from typing import Optional, List


import io
import speech_recognition as sr

def transcribe_audio_chunk(audio_bytes: bytes, mock_text: Optional[str] = None, language: str = "en-IN") -> str:
    """Transcribe raw audio data (WAV bytes) to text.

    If mock_text is provided, it is returned directly.
    Otherwise, uses SpeechRecognition engine to decode the audio.
    """
    if mock_text:
        return mock_text.strip()
    
    if not audio_bytes:
        return ""

    try:
        r = sr.Recognizer()
        audio_file = io.BytesIO(audio_bytes)
        with sr.AudioFile(audio_file) as source:
            audio_data = r.record(source)
            text = r.recognize_google(audio_data, language=language)
            return text.strip()
    except Exception as e:
        return ""


class SpeechPipeline:
    """Accumulates speech segments and provides complete conversation context."""

    def __init__(self, session_id: str = "default_session"):
        self.session_id = session_id
        self.full_transcript: str = ""
        self.transcript_chunks: List[str] = []

    def set_transcript(self, text: str) -> str:
        """Set or replace the current conversation transcript."""
        self.full_transcript = text.strip()
        return self.full_transcript

    def add_transcript_chunk(self, chunk: str) -> str:
        """Append a new transcript chunk or update cumulative transcript."""
        cleaned = chunk.strip()
        if not cleaned:
            return self.get_full_transcript()

        # If incoming chunk already starts with previous transcript, update it directly
        if self.full_transcript and cleaned.startswith(self.full_transcript):
            self.full_transcript = cleaned
        elif cleaned == self.full_transcript:
            pass
        elif not self.full_transcript:
            self.full_transcript = cleaned
            self.transcript_chunks.append(cleaned)
        else:
            self.transcript_chunks.append(cleaned)
            self.full_transcript = (self.full_transcript + " " + cleaned).strip()

        return self.get_full_transcript()

    def get_full_transcript(self) -> str:
        """Return the combined transcript of the entire ongoing call."""
        return self.full_transcript or " ".join(self.transcript_chunks).strip()

    def reset(self):
        """Clear conversation history."""
        self.full_transcript = ""
        self.transcript_chunks.clear()
