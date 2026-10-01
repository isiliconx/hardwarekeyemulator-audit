"""
Every module runs, every PoC behaves as documented, and the expected severities
do not drift.

Run:  python3 tests/test_modules.py
"""

import contextlib
import importlib
import io
import sys

sys.path.insert(0, "/home/ubuntu/.hermes/web/hardwarekeyemulator-audit")

MODULES = [
    "vuln.uv_bypass",
    "vuln.attestation",
    "vuln.rp_verifier",
    "vuln.policy_shapes",
    "vuln.device_conformance",
]

# id -> severity it must carry.  A finding that changes severity is a change in
# what the audit claims, so it fails here rather than silently in a report.
#
# This file runs against the PRISTINE tree by default, so the four entries
# marked patched-only must NOT appear here -- their absence on the pristine tree
# is the whole point, and tests/test_differential.py proves the matching
# positives on the patched tree.
EXPECTED = {
    "UV-CAPABILITY-ADVERTISED": "informational",
    "UV-ASSERTED-WITHOUT-VERIFICATION": "critical",
    # Registration and assertion share one _uv() path, so the assertion-side
    # variant is not a separate finding; the detector reports their agreement as
    # UV-ASSERTION-PATH-AGREES instead.
    "UV-ASSERTION-PATH-AGREES": "informational",
    "UV-SATISFIED-BY-PIN": "informational",
    "UV-NO-GATE-NO-PIN": "informational",
    "UV-FAILED-VERIFICATION-IS-REFUSED": "informational",
    "FIDO-AAGUID-EXTENSION-DOUBLE-WRAPPED": "high",
    "ATTESTATION-TERMINATES-AT-LOCAL-CA": "informational",
    "ANALYSER-MISSES-MALFORMED-EXTENSION": "medium",
    "RP-REFUSES-FORGED-ATTESTATION": "informational",
    "RP-ATTESTATION-VERIFIED-FLAG-FOLLOWS-POLICY": "medium",
    # An RP replay-cache gap, not an authenticator bypass: the authenticator
    # cannot stop a replay from an assertion alone.  Recorded, not escalated.
    "RP-IDENTICAL-REPLAY-ACCEPTED": "informational",
    "POLICY-THREE-OF-FOUR-SHAPES-ACCEPT-FORGED-SIG": "high",
    "POLICY-CHAIN-ONLY-GATE-IS-AVAILABLE": "informational",
    "POLICY-SYNCABILITY-IS-CLIENT-CONTROLLED": "informational",
    "GETINFO-MISSING-CTAP21-KEYS": "medium",
    "GETINFO-UV-WITHOUT-A-UV-MECHANISM": "high",
    "DEVICE-CREDENTIAL-ISOLATION": "informational",
    "DEVICE-SIGN-COUNTER": "informational",
    "DEVICE-EXCLUDE-LIST": "informational",
}

ok = fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  PASS  {name}")
    else:
        fail += 1
        print(f"  FAIL  {name} {extra}")


print("== every module imports and produces findings ==")
seen = {}
for name in MODULES:
    mod = importlib.import_module(name)
    try:
        produced = mod.run() or []
        check(f"{name} ran", len(produced) > 0)
        for f in produced:
            check(f"  no module error: {f.id}",
                  not f.id.startswith("MODULE-ERROR"), f.detail[:60])
            seen[f.id] = f
    except Exception as exc:  # noqa: BLE001
        check(f"{name} ran", False, f"{type(exc).__name__}: {exc}")

print("\n== severities match what the audit claims ==")
for fid, expected in EXPECTED.items():
    f = seen.get(fid)
    if f is None:
        check(f"{fid} present", False)
    else:
        check(f"{fid} == {expected}", f.severity == expected, f"got {f.severity}")

print("\n== the strict findings carry usable evidence ==")
for fid in ("UV-ASSERTED-WITHOUT-VERIFICATION",
            "FIDO-AAGUID-EXTENSION-DOUBLE-WRAPPED"):
    f = seen.get(fid)
    if f is None:
        check(f"{fid} present", False)
        continue
    check(f"{fid} has evidence", len(f.evidence) >= 3, str(f.evidence)[:60])
    check(f"{fid} has remediation", bool(f.remediation))
    check(f"{fid} has a reference", bool(f.references))

print("\n== PoCs behave as documented ==")
from exploit import aaguid_mismatch, uv_forge  # noqa: E402


def run_poc(fn, argv):
    """Run a PoC, swallow its output, return (exit code, output)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = fn.main(argv)
    return code, buf.getvalue()


# `a and check() or check()` is not usable as an assertion: the and-expression
# evaluates to the check's return value, which is None, so the or-branch always
# runs and both checks fire.  Compare the exit code explicitly instead.
code, _ = run_poc(uv_forge, [])
check("uv_forge finds UV without a PIN", code == 0, f"exit {code}")

code, _ = run_poc(uv_forge, ["--gate", "false"])
check("uv_forge control: gate=false does not forge UV", code == 1, f"exit {code}")

code, _ = run_poc(aaguid_mismatch, [])
check("aaguid_mismatch reports the malformed extension", code == 0, f"exit {code}")

_, out = run_poc(aaguid_mismatch, [])
check("aaguid_mismatch shows the 18-byte value", "18 bytes" in out)

print(f"\n{ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)