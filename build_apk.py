"""ASVD 2.O — Android APK Builder & Project Generator.

Prepares the web application as a standalone Android Capacitor project,
sets up all Android audio/microphone permissions, and prepares the APK build.
"""

import os
import sys
import shutil
import subprocess

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
MOBILE_DIR = os.path.join(PROJECT_ROOT, "mobile")
WWW_DIR = os.path.join(MOBILE_DIR, "www")
FRONTEND_CALLER_DIR = os.path.join(PROJECT_ROOT, "frontend", "caller")

def copy_frontend_assets():
    """Copy caller frontend assets into mobile/www."""
    print("📁 [1/4] Copying frontend caller assets to mobile/www...")
    if os.path.exists(WWW_DIR):
        shutil.rmtree(WWW_DIR)
    os.makedirs(WWW_DIR, exist_ok=True)

    for item in os.listdir(FRONTEND_CALLER_DIR):
        src = os.path.join(FRONTEND_CALLER_DIR, item)
        dst = os.path.join(WWW_DIR, item)
        if os.path.isdir(src):
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
    print("    ✅ Frontend assets synced.")

def setup_capacitor():
    """Install capacitor npm modules and add Android platform if needed."""
    print("📦 [2/4] Installing mobile dependencies & Capacitor Android...")
    subprocess.run(["npm", "install"], cwd=MOBILE_DIR, shell=True, check=True)

    android_dir = os.path.join(MOBILE_DIR, "android")
    if not os.path.exists(android_dir):
        print("🤖 [3/4] Adding Android native platform project...")
        subprocess.run(["npx", "cap", "add", "android"], cwd=MOBILE_DIR, shell=True, check=True)
    else:
        print("🔄 [3/4] Syncing web code to Android platform...")
        subprocess.run(["npx", "cap", "sync", "android"], cwd=MOBILE_DIR, shell=True, check=True)

def inject_android_permissions():
    """Ensure AndroidManifest.xml has all necessary microphone and network permissions."""
    print("🛡️ [4/4] Injecting Android Audio & Microphone Permissions...")
    manifest_path = os.path.join(MOBILE_DIR, "android", "app", "src", "main", "AndroidManifest.xml")
    if not os.path.exists(manifest_path):
        print("    ⚠️ AndroidManifest.xml not found yet. Run 'npx cap add android' first.")
        return

    with open(manifest_path, "r", encoding="utf-8") as f:
        content = f.read()

    permissions = [
        '<uses-permission android:name="android.permission.INTERNET" />',
        '<uses-permission android:name="android.permission.RECORD_AUDIO" />',
        '<uses-permission android:name="android.permission.MODIFY_AUDIO_SETTINGS" />',
        '<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />',
        '<uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />',
    ]

    modified = False
    for perm in permissions:
        if perm not in content:
            content = content.replace("</manifest>", f"    {perm}\n</manifest>")
            modified = True

    if modified:
        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write(content)
        print("    ✅ Audio and Network permissions added to AndroidManifest.xml")
    else:
        print("    ✅ Permissions already present.")

def try_build_apk():
    """Attempt gradle build if gradlew exists."""
    gradlew = os.path.join(MOBILE_DIR, "android", "gradlew.bat" if sys.platform == "win32" else "gradlew")
    if os.path.exists(gradlew):
        print("\n🔨 Building Android APK with Gradle...")
        try:
            res = subprocess.run([gradlew, "assembleDebug"], cwd=os.path.join(MOBILE_DIR, "android"), shell=True)
            apk_path = os.path.join(MOBILE_DIR, "android", "app", "build", "outputs", "apk", "debug", "app-debug.apk")
            if os.path.exists(apk_path):
                print("\n" + "=" * 68)
                print("  🎉 APK BUILT SUCCESSFULLY!")
                print("=" * 68)
                print(f"  📍 APK File Location: {apk_path}")
                print("=" * 68)
                return
        except Exception as e:
            print(f"  Gradle build note: {e}")

    print("\n" + "=" * 68)
    print("  📱 ANDROID PROJECT READY!")
    print("=" * 68)
    print("  To build/install the APK on your phone:")
    print("  1. Open Android Studio -> Open project -> Select 'mobile/android' folder")
    print("  2. Click 'Build' -> 'Build Bundle(s) / APK(s)' -> 'Build APK(s)'")
    print("  3. Transfer the generated APK to your phone and install!")
    print("=" * 68)

if __name__ == "__main__":
    copy_frontend_assets()
    setup_capacitor()
    inject_android_permissions()
    try_build_apk()
