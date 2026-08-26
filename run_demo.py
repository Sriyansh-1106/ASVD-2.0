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

if __name__ == "__main__":
    if sys.platform == "win32":
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")

    free_port(8000)

    print("=" * 60)
    print("  🚀 Starting ASVD 2.O — AI Scam Voice Detection System")
    print("=" * 60)
    print()
    print("  🌐 Main Portal:    http://localhost:8000")
    print("  📞 Caller Device:  http://localhost:8000/caller")
    print("  🛡️ Receiver HUD:   http://localhost:8000/receiver")
    print("  📖 API Docs:       http://localhost:8000/docs")
    print()
    print("=" * 60)

    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=False)
