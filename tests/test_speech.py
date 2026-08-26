"""Unit tests for Speech Processing & Transcription Accumulator."""

from backend.app.speech.speech_to_text import SpeechPipeline, transcribe_audio_chunk


def test_transcribe_audio_chunk_mock():
    text = transcribe_audio_chunk(b"dummy_bytes", mock_text="  hello scam alert  ")
    assert text == "hello scam alert"


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
