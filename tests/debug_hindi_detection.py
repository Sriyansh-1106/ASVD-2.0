import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
from backend.app.detection.risk_engine import assess_risk
from backend.app.detection.indicators import normalize_speech_text

# Test several pure Hindi STT scenarios
tests = [
    ("Bank OTP scam",       "मैं एसबीआई से बोल रहा हूं। आपका खाता बंद हो जाएगा। ओटीपी बताइए।",   70),
    ("Police threat scam",  "मैं इंस्पेक्टर शर्मा हूं। आपके खिलाफ एफआईआर दर्ज हुआ है। गिरफ्तारी से बचना है तो दो लाख रुपये देने होंगे।", 70),
    ("Accident scam",       "मैं आपका बेटा बोल रहा हूं। मेरा एक्सीडेंट हो गया। अस्पताल में हूं। पचास हजार रुपये जल्दी भेज दो। किसी को मत बताना।", 70),
    ("Safe conversation",   "नमस्ते मम्मी। मैं ऑफिस से निकल गई हूं। खाना तैयार होगा?", 0),
]

for name, text, min_score in tests:
    r = assess_risk(text)
    norm = normalize_speech_text(text)
    if min_score == 0:
        status = "OK" if r["risk_score"] <= 20 else "FALSE_POS"
    else:
        status = "OK" if r["risk_score"] >= min_score else "MISS"
    print(f"[{status}] {name}")
    print(f"  Score={r['risk_score']} Label={r['label']} Indicators={r['indicators']}")
    print(f"  Normalized: {norm[:100]}")
    print()
