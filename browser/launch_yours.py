"""Give you a working, visible Chrome with the virtual security key attached.

Root cause of the earlier failures, isolated by A/B on the same binary, flags,
DISPLAY and filesystem:

  ~/.config/probe-chrome                 BOUND
  ~/probe-chrome                         BOUND
  /tmp/x1/x2/x3/prof                     BOUND
  ~/.config/google-chrome (yours)        NO BIND   <- only this one
  a full copy of your profile, in /tmp   BOUND

So it is not the profile, not its contents, not the parent directory and not the
filesystem.  That one directory suppresses --remote-debugging-port, and I have
not found what in it does so.  Two things follow: this does not touch your
profile at all, and it does not block what you asked for.

The fix is to run on a copy.  Your bookmarks, history, extensions and profile
settings are all copied; the WebAuthn store starts empty, because a credential
registered on a copy must not pollute the real one.

  browser/launch_yours.sh      relaunch THIS, headed on :1, key attached
  browser/drive.py             attach the key and report the flags
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

REAL = os.path.expanduser("~/.config/google-chrome")
WORK = "/home/ubuntu/.hermes/cache/scratch/chrome-work"
PORT = 9222
ORIGIN = "https://lab.example:8443"
SRC = "/home/ubuntu/.hermes/cache/scratch/hke/src"


def port_open(p, t=1.5):
    s = socket.socket()
    s.settimeout(t)
    try:
        s.connect(("127.0.0.1", p))
        return True
    except OSError:
        return False
    finally:
        s.close()


def kill_chrome():
    subprocess.run(["pkill", "-9", "-f", "/opt/google/chrome"], check=False)
    subprocess.run(["pkill", "-9", "-f", "chrome_crashpad"], check=False)
    time.sleep(4)


def sync_profile():
    """Copy your profile, excluding caches and any live singleton."""
    if os.path.isdir(WORK):
        shutil.rmtree(WORK, ignore_errors=True)
    shutil.copytree(REAL, WORK, symlinks=True,
                    ignore=shutil.ignore_patterns(
                        "Singleton*", "*.lock", "Crashpad", "Cache",
                        "Code Cache", "GPUCache", "GrShaderCache",
                        "ShaderCache", "GraphiteDawnCache", "DawnCache",
                        "Service Worker/CacheStorage"))
    for n in ("SingletonLock", "SingletonCookie", "SingletonSocket"):
        p = os.path.join(WORK, n)
        if os.path.islink(p) or os.path.exists(p):
            os.unlink(p)


def ensure_lab():
    if port_open(8443):
        return True
    env = dict(os.environ)
    env["PYTHONPATH"] = (
        "/home/ubuntu/.hermes/cache/scratch/hkev/lib/python3.12/site-packages:"
        + SRC)
    subprocess.Popen(
        [sys.executable, os.path.join(SRC, "lab_server.py"), "--port", "8443"],
        cwd=SRC, env=env, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, start_new_session=True)
    for _ in range(30):
        time.sleep(1)
        if port_open(8443):
            return True
    return False


def launch(url=None):
    page = url or (ORIGIN + "/")
    args = [
        "/usr/bin/google-chrome-stable",
        f"--remote-debugging-port={PORT}", "--remote-allow-origins=*",
        f"--user-data-dir={WORK}",
        "--test-type", "--password-store=basic",
        "--use-gl=angle", "--use-angle=swiftshader-webgl",
        "--ignore-certificate-errors",
        f"--unsafely-treat-insecure-origin-as-secure={ORIGIN}",
        "--disable-features=WebAuthnVirtualAuthenticatorPrompt",
        "--disable-dev-shm-usage", "--disable-features=DBus",
        "--window-size=1600,1000", "--window-position=20,20",
        page,
    ]
    env = dict(os.environ)
    env["DISPLAY"] = ":1"
    subprocess.Popen(args, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True, env=env)
    for _ in range(50):
        time.sleep(1)
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{PORT}/json/version", timeout=3) as r:
                return json.load(r)
        except Exception:
            pass
    return None


def attach_key():
    """Add the virtual authenticator that Chrome presents as a USB security key."""
    sys.path.insert(0, SRC)
    os.chdir(SRC)
    import asyncio
    import chrome_bridge

    async def go():
        async with chrome_bridge.ChromeBridge(port=PORT) as b:
            aid = await b.add_authenticator(
                transport="usb", resident_key=True, user_verification=True,
                backup_eligibility=False)
            creds = await b.credentials()
            return aid, len(creds)

    return asyncio.run(go())


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=ORIGIN + "/",
                    help="page to open; defaults to the lab RP")
    a = ap.parse_args()
    kill_chrome()
    print("syncing your profile ->", WORK)
    sync_profile()
    print("  ok")
    print("lab RP:", "up" if ensure_lab() else "DOWN")
    info = launch(a.url)
    if not info:
        print("FAILED: DevTools still did not bind")
        raise SystemExit(1)
    print("Chrome:", info.get("Browser"), "on DISPLAY :1")
    print("  profile:", WORK, "(a copy -- your real one is untouched)")
    for t in json.load(urllib.request.urlopen(
            f"http://127.0.0.1:{PORT}/json", timeout=5)):
        print(f"  tab {t.get('type','?'):<6} {t.get('title','')[:36]:<36} "
              f"{t.get('url','')[:48]}")
    aid, n = attach_key()
    print()
    print("virtual security key attached:", aid)
    print("  transport=usb  defaultBackupEligibility=False")
    print("  credentials seeded:", n)
    print()
    # Land on a real secure page, not about:blank: navigator.credentials only
    # exists on a secure context, and a blank tab has none of the WebAuthn API.
    print()
    print(f"Window open on {a.url}")
    print("Register from the page, then confirm what it registered as:")
    print(f"  python3 browser/drive.py --site {a.url}")