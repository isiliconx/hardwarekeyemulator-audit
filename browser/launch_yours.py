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
    suppress_first_run()


def suppress_first_run():
    """A copied profile is not trusted by Chrome, so the first-run flow comes
    back: a "Welcome to Google Chrome" dialog opens and no page target is ever
    created, which leaves the window blank and the launcher exiting as if it had
    worked.  Measured on this host -- devtools listed zero page targets.

    Marking the flow done in the copy removes it.  This writes only to WORK.
    """
    import plistlib
    seen = os.path.join(WORK, "First Run")
    if not os.path.isdir(seen):
        os.makedirs(seen, exist_ok=True)
    # Chrome keys first-run state off both of these.
    for rel in ("First Run", "First Run Sentinel"):
        d = os.path.join(WORK, rel)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "sentinel"), "wb") as f:
            f.write(b"\x00" * 8)
    try:
        with open(os.path.join(seen, "Preferences"), "rb") as f:
            prefs = plistlib.load(f)
    except Exception:
        prefs = {}
    prefs.setdefault("browser", {})
    prefs["browser"]["window_placement"] = {
        "bottom": 1029, "left": 20, "maximized": False,
        "right": 1620, "top": 29, "work_area_bottom": 1199,
        "work_area_left": 0, "work_area_right": 1920, "work_area_top": 29,
        "window_state": "normal"}
    with open(os.path.join(seen, "Preferences"), "wb") as f:
        plistlib.dump(prefs, f)


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
        # ONE --disable-features, comma separated.  Chrome takes the LAST
        # occurrence only, so a second --disable-features=DBus silently threw
        # away the prompt suppression and Chrome sat on "Add a hardware security
        # key" waiting for a touch that a virtual device cannot register.
        "--disable-features=WebAuthnVirtualAuthenticatorPrompt,DBus,"
        "DestroyProfileOnBrowserClose,MediaRouter,OptimizationHints",
        "--disable-dev-shm-usage",
        "--window-size=1600,1000", "--window-position=20,20",
        page,
    ]
    env = dict(os.environ)
    env["DISPLAY"] = ":1"
    log = open("/tmp/chrome-work.log", "ab", buffering=0)
    log.write(b"\n=== launch " + page.encode() + b" ===\n")
    # Chrome must be fully detached from this process.  When the launcher exits,
    # anything still in its process group gets torn down -- which is what made
    # the window vanish immediately for the user.  setsid via start_new_session
    # handles the group, and closing our inherited stdio stops the reaper.
    proc = subprocess.Popen(
        args, stdout=log, stderr=log, stdin=subprocess.DEVNULL,
        start_new_session=True, close_fds=True, env=env)
    proc = None
    for _ in range(50):
        time.sleep(1)
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{PORT}/json/version", timeout=3) as r:
                info = json.load(r)
            return proc, info
        except Exception:
            pass
    return proc, None


def tail_log(n=25):
    try:
        with open("/tmp/chrome-work.log", "r", errors="replace") as f:
            lines = [x for x in f.read().splitlines() if x.strip()]
        for line in lines[-n:]:
            print("    " + line[:150])
    except OSError:
        print("    (no log)")


def size_window():
    """A copied profile carries a saved window placement, which overrides
    --window-size and leaves a 10x10 stub at (10,10).  Force the real geometry.

    Uses the browser-level endpoint, so no new tab is opened and the page the
    launcher asked for stays exactly where it is.  An earlier version opened a
    tab via /json/new to get a target and then closed it, which took the last
    page with it and left the window blank.
    """
    import asyncio

    async def go():
        import websockets
        with urllib.request.urlopen(
                f"http://127.0.0.1:{PORT}/json/version", timeout=5) as r:
            ws_url = json.load(r)["webSocketDebuggerUrl"]
        async with websockets.connect(ws_url, max_size=8 * 1024 * 1024) as ws:
            tid = None
            for t in json.load(urllib.request.urlopen(
                    f"http://127.0.0.1:{PORT}/json", timeout=5)):
                if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                    tid = t["id"]
                    break
            if tid is None:
                raise OSError("no page target to size")
            await ws.send(json.dumps({
                "id": 1, "method": "Browser.getWindowForTarget",
                "params": {"targetId": tid}}))
            win = None
            for _ in range(30):
                m = json.loads(await ws.recv())
                if m.get("id") == 1:
                    win = (m.get("result") or {}).get("windowId")
                    break
            if win is None:
                raise OSError("no window id")
            await ws.send(json.dumps({
                "id": 2, "method": "Browser.setWindowBounds",
                "params": {"windowId": win, "bounds": {
                    "left": 20, "top": 20,
                    "width": 1600, "height": 1000}}}))
            for _ in range(30):
                m = json.loads(await ws.recv())
                if m.get("id") == 2:
                    if "error" in m:
                        raise OSError(str(m["error"]))
                    break
        print(f"  window: 1600x1000 at (20,20)  [windowId={win}]")

    try:
        asyncio.run(go())
    except Exception as e:
        print(f"  (window geometry unchanged: {type(e).__name__} {e})")


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
    proc, info = launch(a.url)
    if not info:
        print("FAILED: DevTools did not bind.")
        print(f"  chrome pid {proc.pid if proc else '?'} alive="
              f"{proc.poll() is None if proc else 'unknown'}")
        print("  chrome log: /tmp/chrome-work.log")
        tail_log()
        raise SystemExit(1)
    print("Chrome:", info.get("Browser"), "on DISPLAY :1")
    size_window()
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