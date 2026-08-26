import sys
import asyncio
import json
import websockets
import httpx

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

async def test_live_system():
    print("=" * 60)
    print("[TEST] Running Live End-to-End Test of ASVD 2.O System")
    print("=" * 60)

    base_url = "http://127.0.0.1:8000"
    session_id = "test-live-session-999"

    # 1. Health check
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{base_url}/api/health")
        print(f"[1] Health Check: {resp.status_code} -> {resp.json()}")
        assert resp.status_code == 200

    # 2. Connect Receiver WebSocket
    receiver_ws_url = f"ws://127.0.0.1:8000/ws/call/{session_id}?role=receiver"
    caller_ws_url = f"ws://127.0.0.1:8000/ws/call/{session_id}?role=caller"

    print(f"\n[2] Connecting Receiver to {receiver_ws_url}...")
    async with websockets.connect(receiver_ws_url) as receiver_ws:
        init_msg = await receiver_ws.recv()
        print(f"    Receiver connected: {init_msg}")

        print(f"\n[3] Connecting Caller to {caller_ws_url}...")
        async with websockets.connect(caller_ws_url) as caller_ws:
            caller_init = await caller_ws.recv()
            print(f"    Caller connected: {caller_init}")

            # 4. Caller starts call
            await caller_ws.send(json.dumps({
                "type": "call_start",
                "caller_id": "+91 98765 43210 (Scammer)",
                "session_id": session_id
            }))
            receiver_event = await receiver_ws.recv()
            print(f"    Receiver received event: {receiver_event}")

            # 5. Caller transmits a real scam speech chunk
            scam_text = "SBI fraud prevention team se call hai. Aapke account se Rs 45,000 ka suspicious transaction hua hai. Turant 6-digit OTP batayein warna account permanently block ho jayega. Bahut urgent hai."
            print(f"\n[4] Caller transmitting live scam transcript:\n    \"{scam_text}\"")

            await caller_ws.send(json.dumps({
                "type": "audio_transcript",
                "text": scam_text,
                "is_final": True,
                "caller_id": "+91 98765 43210 (Scammer)",
                "session_id": session_id
            }))

            # 6. Receiver receives real-time threat alert
            alert = None
            for _ in range(5):
                raw = await receiver_ws.recv()
                msg = json.loads(raw)
                print(f"    -> Receiver got message: {msg.get('type')}")
                if msg.get("type") == "threat_alert":
                    alert = msg
                    break

            assert alert is not None
            print(f"\n[5] Receiver HUD Alert Verified:")
            print(f"    - Type: {alert.get('type')}")
            print(f"    - Risk Score: {alert.get('data', {}).get('risk_score')}/100")
            print(f"    - Threat Level: {alert.get('data', {}).get('risk_level')}")
            print(f"    - Detected Indicators: {alert.get('data', {}).get('indicators')}")
            print(f"    - Recommended Action: {alert.get('data', {}).get('recommended_action')}")

            assert alert.get("type") == "threat_alert"
            assert alert.get("data", {}).get("risk_score") >= 80
            assert "otp_request" in alert.get("data", {}).get("indicators")

    # 7. Test REST Analysis Endpoint
    print("\n[6] Testing REST Analysis Endpoint (/api/analyse)...")
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{base_url}/api/analyse", json={
            "text": "Main Inspector Sharma Cyber Crime se bol raha hoon. Rs 2,00,000 turant transfer karo warna arrest ho jaoge.",
            "session_id": session_id,
            "caller_id": "Fake Police"
        })
        res_data = resp.json()
        print(f"    - Risk Score: {res_data.get('risk_score')}/100")
        print(f"    - Risk Level: {res_data.get('risk_level')}")
        print(f"    - Flags: {res_data.get('indicators')}")
        assert res_data.get("risk_score") >= 70

    print("\n" + "=" * 60)
    print("ALL LIVE REAL-TIME TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(test_live_system())
