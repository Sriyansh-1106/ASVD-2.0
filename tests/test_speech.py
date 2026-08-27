"""Unit tests for Speech Processing, Audio Noise Filtering & Transcription Accumulator."""

import io
import wave
import numpy as np
from backend.app.speech.speech_to_text import (
    SpeechPipeline,
    transcribe_audio_chunk,
    apply_audio_noise_filter,
)


def _generate_synthetic_wav(freq: float = 1000.0, sample_rate: int = 16000, duration_sec: float = 0.5) -> bytes:
    """Helper to generate a valid in-memory 16-bit mono WAV byte stream."""
    t = np.linspace(0, duration_sec, int(sample_rate * duration_sec), endpoint=False)
    signal = 0.5 * np.sin(2 * np.pi * freq * t)  # 1000 Hz tone
    audio_int16 = (signal * 32767).astype(np.int16)

    buf = io.BytesIO()
    with wave.open(buf, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(sample_rate)
        wav.writeframes(audio_int16.tobytes())
    return buf.getvalue()


def test_apply_audio_noise_filter_synthetic_wav():
    """Verify that DSP bandpass filtering runs on valid WAV audio without corruption."""
    wav_bytes = _generate_synthetic_wav(freq=1000.0)
    filtered = apply_audio_noise_filter(wav_bytes)

    assert isinstance(filtered, bytes)
    assert len(filtered) > 44  # Valid WAV header + frames

    # Verify that the output is still readable as a valid WAV
    with wave.open(io.BytesIO(filtered), "rb") as wav_out:
        assert wav_out.getnchannels() == 1
        assert wav_out.getsampwidth() == 2
        assert wav_out.getframerate() == 16000
        assert wav_out.getnframes() > 0


def test_apply_audio_noise_filter_invalid_bytes_fallback():
    """Verify graceful fallback on non-wav or empty bytes."""
    assert apply_audio_noise_filter(b"") == b""
    assert apply_audio_noise_filter(b"corrupted_short_payload") == b"corrupted_short_payload"


def test_transcribe_audio_chunk_mock():
    text = transcribe_audio_chunk(b"dummy_bytes", mock_text="  hello scam alert  ", enable_denoise=True)
    assert text == "hello scam alert"


def test_transcribe_audio_chunk_empty():
    assert transcribe_audio_chunk(b"") == ""


def test_speech_pipeline_accumulation():
    pipeline = SpeechPipeline(session_id="test_session")
    assert pipeline.get_full_transcript() == ""

    t1 = pipeline.add_transcript_chunk("Hello")
    assert t1 == "Hello"

    t2 = pipeline.add_transcript_chunk("give me your OTP")
    assert t2 == "Hello give me your OTP"
    assert pipeline.get_full_transcript() == "Hello give me your OTP"

    pipeline.reset()
    assert pipeline.get_full_transcript() == ""
