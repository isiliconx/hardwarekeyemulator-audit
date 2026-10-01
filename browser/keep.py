"""Start once. Then just use the browser.

    python3 browser/keep.py                       # lab RP
    python3 browser/keep.py https://your.site     # your site

Launches Chrome with the virtual security key attached, then stays in the
foreground holding the key alive. Navigate by hand from then on: your logins,
cookies and registered credentials persist, because the work profile is created
once and reused rather than rebuilt on every launch.

The key lives in the DevTools session that creates it, and this process is that
session.  While it runs, tabs it controls can register.  When you Ctrl-C, the
key is released and registration stops working until you run it again.

    Ctrl-C  release the key and exit
"""
import argparse
import asyncio
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import launch_yours as L  # noqa: E402

sys.path.insert(0, os.environ["HKE_WORK"] + "/hke/src")
os.chdir(os.environ["HKE_WORK"] + "/hke/src")
import chrome_bridge  # noqa: E402

MEASURE = open(os.path.join(HERE, "measure.js")).read()


async def js(b, expr):
    r = await b.call("Runtime.evaluate",
                     {"expression": expr, "awaitPromise": True,
                      "returnByValue": True}, session=b.session_id)
    if r.get("exceptionDetails"):
        return {"ok": False,
                "error": "PAGE " + str(r["exceptionDetails"].get("text"))[:100]}
    o = r.get("result") or {}
    if o.get("subtype") == "error":
        return {"ok": False, "error": "EVAL " + str(o.get("description"))[:100]}
    return o.get("value")


async def main(url):
    if not L.port_open(L.PORT):
        print("starting Chrome...")
        L.sync_profile()
        print("lab RP:", "up" if L.ensure_lab() else "DOWN")
        proc, info = L.launch(url)
        if not info:
            print("FAILED: DevTools did not bind")
            L.tail_log()
            return 1
        print("Chrome:", info.get("Browser"))
        L.size_window()

    async with chrome_bridge.ChromeBridge(port=L.PORT) as b:
        aid = await b.add_authenticator(transport="usb", resident_key=True,
                                        user_verification=True,
                                        backup_eligibility=False)
        print()
        print(f"security key attached: {aid}")
        print("  transport=usb  defaultBackupEligibility=False")
        print(f"  authenticators already on this browser: kept")

        await b.call("Page.navigate", {"url": url}, session=b.session_id)
        for _ in range(40):
            await asyncio.sleep(0.5)
            v = await js(b, "({s:window.isSecureContext,u:location.href})")
            if isinstance(v, dict) and v.get("s"):
                print(f"  page: {v['u']}")
                break
        await b.call("Page.bringToFront", {}, session=b.session_id)

        print()
        print("Use the browser window now. Log in once, register once.")
        print("This process holds the key -- leave it running.")
        print()
        print("  check the key       python3 browser/drive.py --site " + url)
        print("  Ctrl-C              release the key and exit")
        print()

        # input() on a thread blocks forever and never unblocks, so it cannot be
        # cancelled -- and it competes with stdin under a supervisor. Poll the tty
        # non-destructively instead: read one line when a byte is available.
        import select
        tty = sys.stdin if (sys.stdin and sys.stdin.isatty()) else None
        if tty is None:
            print("  (no tty; Ctrl-C still releases the key)")
        while True:
            await asyncio.sleep(0.25)
            if tty is None:
                continue
            ready, _, _ = select.select([tty], [], [], 0)
            if not ready:
                continue
            try:
                line = tty.readline()
            except Exception:
                continue
            if not line:
                continue
            print(f"\n  registering on {url}...")
            res = await js(b, MEASURE)
            if res and res.get("ok"):
                print(f"  flags {res['flags']}  UP={res['UP']} "
                      f"UV={res['UV']} BE={res['BE']} BS={res['BS']} "
                      f"AT={res['AT']}")
                print(f"  aaguid {res['aaguid']}  "
                      f"transports {res['transports']}")
                v = ("security key -- not backup eligible, not syncable"
                     if res["BS"] == "clear" and res["BE"] == "clear"
                     else f"passkey/syncable (BE={res['BE']} BS={res['BS']})")
                print(f"  VERDICT  {v}")
                creds = await b.credentials()
                print(f"  credentials on the key: {len(creds)}")
            else:
                print("  FAILED:", (res or {}).get("error", "?")[:120])
            print()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="?", default=L.ORIGIN + "/",
                    help="site to open; defaults to the lab RP")
    a = ap.parse_args()
    try:
        raise SystemExit(asyncio.run(main(a.url)))
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\nkey released")
