"""
Differential: the same detectors, run against two trees.

  baseline   the upstream checkout as published.  Every finding this audit
             reported must reproduce here, or the audit is wrong.
  patched    the same checkout after exploit/apply_fix.py, exploit/fix_tests.py
             and exploit/fix_uv_sites.py have been applied.

The rule this file enforces:

  * a finding the audit claims to have fixed must be present in baseline and
    absent from patched;
  * a finding the audit deliberately did NOT fix must be present in BOTH, and
    the test fails if applying the patch quietly closed it -- that would mean the
    remediation went beyond what findings.md claims, which is as much a defect
    as a finding that persists silently.

Severity is not compared for the informational probes: an informational finding
records a mechanism, and which mechanism fires changes with the code shape.

    HKE_BASELINE_SRC=/path/to/baseline/src \
    HKE_PATCHED_SRC=/path/to/patched/src \
        python3 tests/test_differential.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Self-locating: this file is run by path, so nothing puts the project on the
# path for us.  Without this, `from tooling.paths import ...` below fails on a
# cold clone.
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

PASS, FAIL = 0, 0


def check(ok: bool, label: str, extra: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}")
        for line in extra.rstrip().splitlines():
            print(f"          {line}")


def collect(src: str) -> dict[str, set[str]]:
    """Run every vuln module against `src` and return {finding_id: {severities}}.

    A subprocess, not an in-process re-import.  The modules import their target
    from sys.path at import time, and once ctap2_core / ctaphid / rp_verify are
    in sys.modules the first tree's code stays bound -- so an in-process sweep
    silently measures the same tree twice and every differential passes
    vacuously.  A fresh interpreter is the only honest way to switch targets.
    """
    env = dict(os.environ)
    env["HKE_SRC"] = src
    env["PYTHONPATH"] = ROOT
    tag = os.path.basename(os.path.dirname(os.path.abspath(src)))
    out = os.path.join(os.environ.get("TMPDIR", "/tmp"), f"hke-diff-{tag}.json")

    # run_all exits 1 when it finds a critical or high, because it is built to
    # gate a pipeline.  That is the expected outcome on the baseline tree, so
    # only a crash counts as failure here; the report itself is the evidence.
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tooling", "run_all.py"),
         "--out", out, "--quiet"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=900,
    )
    if not os.path.exists(out):
        print(proc.stdout[-2000:])
        print(proc.stderr[-2000:], file=sys.stderr)
        raise SystemExit(f"runner produced no report against {src}")
    if proc.returncode not in (0, 1):
        print(proc.stdout[-2000:])
        print(proc.stderr[-2000:], file=sys.stderr)
        raise SystemExit(f"runner crashed against {src} (rc={proc.returncode})")

    with open(out) as fh:
        report = json.load(fh)

    found: dict[str, set[str]] = {}
    for f in report["findings"]:
        found.setdefault(f["id"], set()).add(f["severity"])
    return found


# The audit's claims, as a table.  fixed=True means the finding was closed by the
# remediation; fixed=False means it was understood, documented, and left open on
# purpose.
CLAIMS = [
    ("UV-ASSERTED-WITHOUT-VERIFICATION", True,
     "critical: uv=true completed with no PIN and no verification"),
    ("UV-REFUSED-WITHOUT-A-MECHANISM", False,
     "the patched tree refuses instead of asserting"),
    ("FIDO-AAGUID-EXTENSION-DOUBLE-WRAPPED", True,
     "high: id-fido-gen-ce-aaguid carried nested DER"),
    ("GETINFO-UV-WITHOUT-A-UV-MECHANISM", True,
     "high: uv advertised with no clientPin"),
    ("ANALYSER-MISSES-MALFORMED-EXTENSION", True,
     "medium: the analyser read a bad value as present"),
    ("ANALYSER-VALIDATES-THE-AAGUID-EXTENSION", False,
     "the patched tree emits a conformant 16-byte value"),
    ("RP-ATTESTATION-VERIFIED-FLAG-FOLLOWS-POLICY", True,
     "medium: the field tracked policy, not the proof"),
    ("RP-ATTESTATION-VERIFIED-REPORTS-THE-PROOF", False,
     "the patched tree reports what the function verified"),
    # Left open on purpose: see findings.md, OPEN-1 and OPEN-2.
    ("POLICY-THREE-OF-FOUR-SHAPES-ACCEPT-FORGED-SIG", False,
     "RP-side policy shapes are the RP maintainer's choice"),
    ("GETINFO-MISSING-CTAP21-KEYS", False,
     "the project targets FIDO 2.0 deliberately"),
]


def main() -> int:
    from tooling.paths import BASELINE_SRC as default_baseline
    from tooling.paths import PATCHED_SRC as default_patched

    baseline_src = os.environ.get("HKE_BASELINE_SRC") or default_baseline
    patched_src = os.environ.get("HKE_PATCHED_SRC") or default_patched

    print("=" * 72)
    print("baseline", baseline_src)
    print("patched ", patched_src)
    print("=" * 72)

    for label, src in (("baseline", baseline_src), ("patched", patched_src)):
        if not os.path.isdir(src):
            print(f"missing {label} tree at {src}")
            return 2

    before = collect(baseline_src)
    after = collect(patched_src)

    print("\n== every fix claim reproduces on the baseline ==")
    for finding_id, fixed, _why in CLAIMS:
        if fixed:
            check(finding_id in before,
                  f"baseline reproduces {finding_id}",
                  f"absent from {baseline_src}")
        else:
            check(finding_id in before or finding_id in after,
                  f"{finding_id} is measured on at least one tree",
                  "absent from both trees, so the detector never ran")

    print("\n== remediation closes exactly what it claims ==")
    for finding_id, fixed, _why in CLAIMS:
        if fixed:
            check(finding_id not in after,
                  f"patched no longer reports {finding_id}",
                  f"still present: {sorted(after.get(finding_id, ()))}")

    print("\n== and nothing beyond that ==")
    for finding_id, fixed, _why in CLAIMS:
        if fixed:
            continue
        check(finding_id in after,
              f"patched still reports {finding_id}",
              "absent after patching -- the remediation closed more than "
              "findings.md claims, which is a defect in itself")

    print("\n== no module errored on either tree ==")
    for label, res in (("baseline", before), ("patched", after)):
        broken = sorted(k for k in res if k.startswith("MODULE-ERROR"))
        check(not broken, f"{label}: all five modules produced findings",
              f"errored: {broken}")

    print("\n== severity direction ==")
    check(any("critical" in v for v in before.values()),
          "baseline has at least one critical")
    check(not any("critical" in v for v in after.values()),
          "patched has no critical")

    print()
    print(f"{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())