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
    not have them, and this project may have no venv of its own.  Candidate
    interpreters are tried in order: the project venv, then any Hermes scratch
    venv, then a normal site-packages install.  Doing it here means a hand-run
    needs no environment setup at all.
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
    cands += ["/usr/bin/python3", sys.executable]
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
