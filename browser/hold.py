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
# tooling.paths already defaults HKE_WORK to a sibling directory, so these
# scripts must never require the variable to be exported by hand.  Reading
# os.environ["HKE_WORK"] directly made every hand-run fail with KeyError.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tooling.paths import BASELINE_SRC, DEFAULT_WORK  # noqa: E402

def _find_target():
    """Locate the upstream checkout when the default sibling dir is absent.

    The default in tooling.paths is right for a fresh clone, but a machine that
    already has the checkout somewhere else should not have to export anything.
    Search the usual spots and the Hermes scratch area, then give up loudly.
    """
    import glob
    if os.path.isdir(BASELINE_SRC):
        return BASELINE_SRC, DEFAULT_WORK
    roots = [
        os.path.join(os.path.expanduser("~"), ".hermes", "cache", "scratch"),
        os.path.join(os.path.expanduser("~"), ".hermes", "web"),
        os.path.expanduser("~"),
    ]
    for root in roots:
        if not os.path.isdir(root):
            continue
        for cand in sorted(glob.glob(os.path.join(root, "**", "hke", "src"),
                                     recursive=True)):
            if os.path.isfile(os.path.join(cand, "ctap2_core.py")):
                work = os.path.dirname(os.path.dirname(cand))
                return cand, work
    sys.exit(
        "upstream target not found.\n"
        "  looked for <HKE_WORK>/hke/src containing ctap2_core.py\n"
        "  default: " + DEFAULT_WORK + "\n"
        "  fix:     HKE_WORK=<dir> ./recon/fetch.sh")


BASELINE_SRC, HKE_WORK = _find_target()

sys.path.insert(0, BASELINE_SRC)
os.chdir(BASELINE_SRC)
def _step(msg):
    """Print and flush.  os.execv discards buffered output, so progress written
    before a re-exec would vanish."""
    print(msg, flush=True)


_SELF = os.path.abspath(__file__)


def _ensure_deps():
    """Re-exec under an interpreter that has the upstream dependencies.

    chrome_bridge needs cbor2 and flask.  Whatever python3 is first on PATH may
    not have them, and this project may have no venv of its own.  Candidates are
    tried in order: the project venv, any Hermes scratch venv, then the system
    python.  Doing it here means a hand-run needs no environment setup at all.
    """
    try:
        import cbor2  # noqa: F401
        return
    except ImportError:
        pass

    import glob
    import subprocess as _sp
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cands = [os.path.join(root, ".venv", "bin", "python3")]
    cands += sorted(glob.glob(os.path.join(
        os.path.expanduser("~"), ".hermes", "cache", "scratch",
        "*", "bin", "python3")))
    cands += ["/usr/bin/python3"]
    # Do NOT compare realpath: every venv here symlinks to the same base
    # interpreter, so the guard would skip every candidate and declare the
    # dependency missing when it is present.  Compare the path as written, and
    # guard the loop with a hop counter instead so a re-exec cannot loop.
    if os.environ.get("_HKE_DEPS_HOPS"):
        sys.exit("missing dependency: cbor2 (needed by chrome_bridge)\n"
                 "  this interpreter lacks it after one re-exec attempt\n"
                 "  fix:  pip install -r requirements.txt")
    for cand in cands:
        if not os.path.exists(cand) or cand == sys.executable:
            continue
        try:
            r = _sp.run([cand, "-c", "import cbor2, flask"],
                        capture_output=True, timeout=30)
        except Exception:
            continue
        if r.returncode == 0:
            # execv replaces the process image and discards unflushed stdout,
            # so everything printed before this point would be lost.
            print(f"[deps] using {cand}")
            sys.stdout.flush()
            sys.stderr.flush()
            os.environ["_HKE_DEPS_HOPS"] = "1"
            os.execv(cand, [cand, _SELF] + sys.argv[1:])
    sys.exit(
        "missing dependency: cbor2 (needed by the target's chrome_bridge)\n"
        "  no interpreter found with cbor2 + flask\n"
        "  fix:  pip install -r requirements.txt   (or: ./build.sh deps)")


_ensure_deps()
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
