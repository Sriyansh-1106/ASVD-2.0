"""ASVD 2.O — Quick Launcher Script.

Runs the complete AI Scam Voice Detection system:
- Starts FastAPI server on http://localhost:8000
- Opens the Web Portal in your browser
"""

import os
import sys
import webbrowser
import threading
import time
import subprocess
import uvicorn

def free_port(port=8000):
    """Free port 8000 if another orphaned python/uvicorn process is holding it on Windows."""
    if sys.platform == "win32":
        try:
            cmd = f'powershell -Command "Get-NetTCPConnection -LocalPort {port} -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess"'
            res = subprocess.check_output(cmd, shell=True).decode().strip()
            if res:
                for pid_str in res.split():
                    pid = int(pid_str.strip())
                    if pid != os.getpid():
                        print(f"  ⚡ Freeing occupied port {port} (PID {pid})...")
                        subprocess.run(f"powershell -Command Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue", shell=True)
                        time.sleep(1)
        except Exception:
            pass

def find_chrome():
    """Find the path to Google Chrome on Windows."""
    paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%PROGRAMFILES%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%PROGRAMFILES(X86)%\Google\Chrome\Application\chrome.exe"),
    ]
    for p in paths:
        if os.path.exists(p):
            return p
    return None

def open_browser():
    time.sleep(1.5)
    chrome_path = find_chrome()
    if chrome_path:
        print(f"  🌐 Launching Google Chrome: {chrome_path}")
        try:
            # Open Caller (Device 1) and Receiver (Device 2) in Chrome
            subprocess.Popen([chrome_path, "http://localhost:8000/caller", "http://localhost:8000/receiver"])
            return
        except Exception as e:
            print(f"  Chrome launch notice: {e}")

    # Fallback to default browser
    webbrowser.open("http://localhost:8000")

import socket

def get_local_ip():
    """Find the local Wi-Fi / LAN IP address for phone connection."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "localhost"

if __name__ == "__main__":
    if sys.platform == "win32":
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")

    free_port(8000)
    local_ip = get_local_ip()

    print("=" * 65)
    print("  🚀 ASVD 2.0 — Real-Time AI Scam Voice Detection System")
    print("=" * 65)
    print()
    print(f"  📱 PHONE CALLER (Open on Phone): http://{local_ip}:8000/caller")
    print(f"  🛡️ LAPTOP RECEIVER HUD:         http://localhost:8000/receiver")
    print(f"  🌐 MAIN PORTAL:                 http://localhost:8000")
    print(f"  📖 API DOCS:                    http://localhost:8000/docs")
    print()
    print("=" * 65)
    print("  💡 LIVE DEMO PROTOCOL:")
    print("  1. Keep the Receiver HUD open on your Laptop.")
    print("  2. Open the Phone Caller link on your Mobile connected to same Wi-Fi.")
    print("  3. Tap 'Start Speaking (Mic)' or tap any Preset on your Phone.")
    print("  4. Watch your Laptop HUD light up with instant Threat Defense alerts!")
    print("=" * 65)
    print()

    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=False)
