"""Keep the virtual security key attached while you use the browser by hand.

Why this is needed.  A CDP virtual authenticator is scoped to the DevTools
session that created it -- measured, not assumed:

    session A  attaches a key          ceremony succeeds, flags 0x45
    session B  attaches nothing         ceremony fails, NotAllowedError

So a tab you open by navigating by hand sees NO security key.  You have to drive
the ceremony over CDP, or keep one session alive that holds the key.

    python3 browser/hold.py                     # hold, register in the window
    python3 browser/hold.py https://your.site   # hold, on your site

Leave it running.  Ctrl-C to release.
"""
import asyncio
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.environ["HKE_WORK"] + "/hke/src")
os.chdir(os.environ["HKE_WORK"] + "/hke/src")
import chrome_bridge  # noqa: E402

PORT = 9222
MEASURE = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "measure.js")).read()


async def js(b, expr):
    r = await b.call("Runtime.evaluate",
                     {"expression": expr, "awaitPromise": True,
                      "returnByValue": True}, session=b.session_id)
    if r.get("exceptionDetails"):
        return {"ok": False, "error": "PAGE " + str(r["exceptionDetails"].get("text"))}
    o = r.get("result") or {}
    if o.get("subtype") == "error":
        return {"ok": False, "error": "EVAL " + str(o.get("description"))}
    return o.get("value")


async def main(url, wait):
    async with chrome_bridge.ChromeBridge(port=PORT) as b:
        aid = await b.add_authenticator(transport="usb", resident_key=True,
                                        user_verification=True,
                                        backup_eligibility=False)
        print(f"security key attached: {aid}")
        print("  transport=usb  defaultBackupEligibility=False")

        await b.call("Page.navigate", {"url": url}, session=b.session_id)
        for _ in range(40):
            await asyncio.sleep(0.5)
            v = await js(b, "({s:window.isSecureContext,u:location.href})")
            if isinstance(v, dict) and v.get("s"):
                print(f"page ready: {v['u']}")
                break
        await b.call("Page.bringToFront", {}, session=b.session_id)

        if wait:
            print()
            print("Window is up and you can watch it. The registration runs here")
            print("over CDP, because a tab you open by hand cannot see the key.")
            print()
            while True:
                await asyncio.sleep(3600)

        print()
        print("running the ceremony now -- watch the window")
        res = await js(b, MEASURE)
        if not res or not res.get("ok"):
            print("  FAILED:", (res or {}).get("error", "?"))
            return 1
        print(f"  flags {res['flags']}   UP={res['UP']} UV={res['UV']} "
              f"BE={res['BE']} BS={res['BS']} AT={res['AT']}")
        print(f"  aaguid {res['aaguid']}  transports {res['transports']}")
        print(f"  rpIdHash verified, authData {res['adLen']} bytes")
        print()
        if res["BS"] == "clear" and res["BE"] == "clear":
            print("  VERDICT  security key -- not backup eligible, not syncable")
        else:
            print(f"  VERDICT  syncable/passkey (BE={res['BE']} BS={res['BS']})")
        return 0


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="?",
                    default="https://lab.example:8443/",
                    help="site to open; defaults to the lab RP")
    ap.add_argument("--run", action="store_true",
                    help="run the ceremony immediately instead of waiting")
    a = ap.parse_args()
    try:
        raise SystemExit(asyncio.run(main(a.url, not a.run)))
    except KeyboardInterrupt:
        print("\nkey released")
