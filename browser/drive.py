"""Attach the key to the running browser and report what it actually registers as.

The measurement must be a real navigator.credentials.create() on a real secure
context.  Three earlier readings were wrong the same way -- an assumption about
byte layout instead of a check:

  * flags read at a fixed offset past a "text header".  attestationObject is a
    CBOR *map* (0xa3), so that offset landed inside the COSE key.  The tell was
    fmt='cfm', which is not a format name.
  * the same again after assuming a one-byte header.
  * CDP options read back and reported as a classification.  A mirror, not a
    measurement: it reports what was asked for.

So this decodes the CBOR properly and refuses to report flags unless the first
32 bytes of authData hash-match the RP ID.  A wrong parse cannot print a clean
table.

    python3 browser/drive.py [--site https://your.site]
"""
import argparse
import asyncio
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

# Normally exported by recon/paths.sh via build.sh; needed when these run bare.
os.environ.setdefault(
    "HKE_WORK",
    os.path.join(os.path.dirname(ROOT), ".hke-work"))
from tooling.paths import BASELINE_SRC  # noqa: E402

sys.path.insert(0, BASELINE_SRC)
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

JS = open(os.path.join(HERE, "measure.js")).read()

LAB = "https://lab.example:8443/"


async def js(b, expr):
    res = await b.call("Runtime.evaluate",
                       {"expression": expr, "awaitPromise": True,
                        "returnByValue": True}, session=b.session_id)
    if res.get("exceptionDetails"):
        return {"ok": False,
                "error": "PAGE " + str(res["exceptionDetails"].get("text"))}
    out = res.get("result") or {}
    if out.get("subtype") == "error":
        return {"ok": False, "error": "EVAL " + str(out.get("description"))}
    return out.get("value")


async def main(site):
    os.chdir(BASELINE_SRC)
    url = site or LAB
    async with chrome_bridge.ChromeBridge(port=PORT) as b:
        tabs = json.load(urllib.request.urlopen(
            f"http://127.0.0.1:{PORT}/json", timeout=5))
        print(f"{len(tabs)} tab(s) open; testing {url}")

        # Virtual authenticators are scoped to the DevTools session that created
        # them (chrome_bridge's own header says so).  Entering the bridge makes a
        # NEW page target, so a key attached by an earlier run is invisible here
        # and every ceremony fails with NotAllowedError.  Attach on this session.
        aid = await b.add_authenticator(
            transport="usb", resident_key=True, user_verification=True,
            backup_eligibility=False)
        print(f"virtual key attached on this session: {aid}")
        print("  transport=usb  defaultBackupEligibility=False")

        await b.call("Page.navigate", {"url": url}, session=b.session_id)
        for _ in range(40):
            await asyncio.sleep(0.5)
            st = await js(b, "({s:window.isSecureContext,u:location.href})")
            if isinstance(st, dict) and st.get("s"):
                break
        else:
            print("the page never became a secure context")
            return 1

        res = await js(b, JS)
        if not res or not res.get("ok"):
            print("MEASUREMENT FAILED:", (res or {}).get("error"))
            return 1

        print()
        print(f"  site        {res['site']}")
        print(f"  fmt         {res['fmt']}")
        print(f"  authData    {res['adLen']} bytes, rpIdHash verified")
        print(f"  flags       {res['flags']}")
        print(f"    UP={res['UP']}  UV={res['UV']}  BE={res['BE']}  "
              f"BS={res['BS']}  AT={res['AT']}")
        print(f"  aaguid      {res['aaguid']}")
        print(f"  signCount   {res['signCount']}")
        print(f"  attachment  {res['attachment']}   transports={res['transports']}")
        print(f"  attStmt     {res['attStmtKeys']}")
        print()
        if res["BS"] == "clear" and res["BE"] == "clear":
            print("  VERDICT  security key -- not backup eligible, not syncable")
        else:
            print(f"  VERDICT  syncable/passkey (BE={res['BE']} BS={res['BS']})")
        return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--site", "--url", dest="site",
                    help="a URL to test against; defaults to the lab RP")
    a = ap.parse_args()
    raise SystemExit(asyncio.run(main(a.site)))
