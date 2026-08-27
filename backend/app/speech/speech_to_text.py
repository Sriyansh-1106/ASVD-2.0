"""ASVD Demo — Speech-to-Text Processing Pipeline.

Handles:
- Ingestion of live audio buffers or streaming transcript segments
- Digital Signal Processing (DSP) bandpass noise reduction and ambient calibration
- Audio chunk transcription / normalization
- Conversation accumulation for multi-turn threat detection
"""

import io
import wave
from typing import Optional, List
import numpy as np
from scipy import signal
import speech_recognition as sr


def apply_audio_noise_filter(
    audio_bytes: bytes,
    lowcut: float = 60.0,
    highcut: float = 7500.0,
) -> bytes:
    """Apply gentle wideband digital filter to suppress deep sub-rumble while preserving vocal formants."""
    if not audio_bytes or len(audio_bytes) < 44:  # WAV header minimum size
        return audio_bytes

    try:
        with wave.open(io.BytesIO(audio_bytes), "rb") as wav_in:
            params = wav_in.getparams()
            sample_rate = wav_in.getframerate()
            n_channels = wav_in.getnchannels()
            sampwidth = wav_in.getsampwidth()
            n_frames = wav_in.getnframes()

            if sampwidth != 2 or sample_rate <= 0:  # 16-bit PCM standard
                return audio_bytes

            raw_frames = wav_in.readframes(n_frames)
            if not raw_frames:
                return audio_bytes

            audio_array = np.frombuffer(raw_frames, dtype=np.int16).astype(np.float32)

            nyquist = 0.5 * sample_rate
            if highcut >= nyquist:
                highcut = max(60.0, nyquist - 100.0)
            if lowcut >= highcut or lowcut <= 0:
                return audio_bytes

            sos = signal.butter(2, [lowcut, highcut], btype="bandpass", fs=sample_rate, output="sos")

            if n_channels > 1:
                audio_reshaped = audio_array.reshape(-1, n_channels)
                filtered_channels = []
                for c in range(n_channels):
                    filtered_channels.append(signal.sosfilt(sos, audio_reshaped[:, c]))
                filtered = np.column_stack(filtered_channels).flatten()
            else:
                filtered = signal.sosfilt(sos, audio_array)

            filtered = np.clip(filtered, -32768, 32767).astype(np.int16)

            out_buf = io.BytesIO()
            with wave.open(out_buf, "wb") as wav_out:
                wav_out.setparams(params)
                wav_out.writeframes(filtered.tobytes())
            return out_buf.getvalue()
    except Exception:
        return audio_bytes


# ====================================================================
# NEURAL WHISPER ENGINE (OFFLINE LOCAL SPEECH RECOGNITION)
# ====================================================================

_whisper_model = None
_whisper_available = True


def get_whisper_model():
    """Lazy-load the lightweight Faster-Whisper int8 model on CPU."""
    global _whisper_model, _whisper_available
    if not _whisper_available:
        return None
    if _whisper_model is None:
        try:
            from faster_whisper import WhisperModel
            # Try base model for high accuracy, fallback to tiny if base not cached
            try:
                _whisper_model = WhisperModel("base", device="cpu", compute_type="int8")
            except Exception:
                _whisper_model = WhisperModel("tiny", device="cpu", compute_type="int8")
        except Exception:
            _whisper_available = False
            _whisper_model = None
    return _whisper_model


def transcribe_with_whisper(audio_bytes: bytes, language: str = "hi-IN") -> str:
    """Transcribe audio chunk using local Whisper neural model."""
    try:
        model = get_whisper_model()
        if model is None:
            return ""

        whisper_lang = "hi" if language.startswith("hi") else ("en" if language.startswith("en") else None)

        audio_io = io.BytesIO(audio_bytes)
        segments, _ = model.transcribe(
            audio_io,
            language=whisper_lang,
            beam_size=3,
            best_of=3,
            temperature=0.0,
            condition_on_previous_text=False,
            vad_filter=False, # Raw audio already VAD-framed in client
        )
        texts = [seg.text.strip() for seg in segments if seg.text and seg.text.strip()]
        return " ".join(texts).strip()
    except Exception:
        return ""


def transcribe_audio_chunk(
    audio_bytes: bytes,
    mock_text: Optional[str] = None,
    language: str = "hi-IN",
    enable_denoise: bool = True,
) -> str:
    """Transcribe raw audio data (WAV bytes) to text with ambient noise reduction.

    Tries local offline Whisper neural engine first. If unavailable, falls back
    to Google Speech Recognition.
    """
    if mock_text:
        return mock_text.strip()

    if not audio_bytes or len(audio_bytes) < 100:
        return ""

    try:
        # Step 1: Apply DSP bandpass noise filter
        processed_bytes = apply_audio_noise_filter(audio_bytes) if enable_denoise else audio_bytes

        # Step 2: Try local Neural Whisper first (100% offline, accurate for accents)
        whisper_result = transcribe_with_whisper(processed_bytes, language=language)
        if whisper_result and whisper_result.strip():
            return whisper_result.strip()

        # Step 3: Fallback to Google SpeechRecognition
        r = sr.Recognizer()
        r.dynamic_energy_threshold = True
        r.energy_threshold = 250

        audio_file = io.BytesIO(processed_bytes)
        with sr.AudioFile(audio_file) as source:
            try:
                r.adjust_for_ambient_noise(source, duration=0.2)
            except Exception:
                pass
            audio_data = r.record(source)
            
            try:
                text = r.recognize_google(audio_data, language=language)
                if text and text.strip():
                    return text.strip()
            except Exception:
                pass

            fallback_lang = "en-IN" if language.startswith("hi") else "hi-IN"
            try:
                text = r.recognize_google(audio_data, language=fallback_lang)
                return text.strip() if text else ""
            except Exception:
                return ""
    except Exception:
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
