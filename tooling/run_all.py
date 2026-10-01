"""
Run every vuln module and write findings.json.

    python3 -m tooling.run_all
    python3 -m tooling.run_all --only uv_bypass attestation
    python3 -m tooling.run_all --list

Exit 1 when a finding reaches severity.fail_on from config/target.yaml.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
import traceback
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tooling.harness import Finding  # noqa: E402

MODULES = [
    ("uv_bypass", "UV asserted without any verification"),
    ("attestation", "attestation chain, the FIDO AAGUID extension, their analyser"),
    ("rp_verifier", "their RP verifier: forged attestation, replay"),
    ("policy_shapes", "the four RP enforcement shapes against a forged signature"),
    ("device_conformance", "GetInfo shape, credential isolation, counters, exclude list"),
]

REPORT = "findings.json"


def load_config(path=None):
    import yaml

    path = path or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config", "target.yaml")
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="tooling.run_all")
    ap.add_argument("--config", default=None)
    ap.add_argument("--only", nargs="*", default=None)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--out", default=None)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    if args.list:
        for name, blurb in MODULES:
            print(f"{name:22s} {blurb}")
        return 0

    selected = args.only or [n for n, _ in MODULES]
    known = {n for n, _ in MODULES}
    unknown = [n for n in selected if n not in known]
    if unknown:
        print(f"unknown module(s): {', '.join(unknown)}", file=sys.stderr)
        print(f"known: {', '.join(n for n, _ in MODULES)}", file=sys.stderr)
        return 2

    cfg = load_config(args.config)
    out_path = args.out or (cfg.get("output", {}) or {}).get("findings_json", REPORT)
    fail_on = {
        s.lower()
        for s in (cfg.get("severity", {}) or {}).get("fail_on", ["critical", "high"])
    }

    findings: list[Finding] = []
    target = (cfg.get("target", {}) or {}).get("name", "hardwarekeyemulator")
    started = datetime.now(timezone.utc).isoformat()

    if not args.quiet:
        print(f"\033[1mtarget\033[0m  {target}")
        print(f"modules  {', '.join(selected)}\n")

    for name in selected:
        if not args.quiet:
            print(f"\033[1m-- {name} \033[0m", end="", flush=True)
        before = len(findings)
        try:
            module = importlib.import_module(f"vuln.{name}")
            produced = module.run() or []
            findings.extend(produced)
        except Exception as exc:  # noqa: BLE001
            findings.append(
                Finding(
                    id=f"MODULE-ERROR-{name.upper().replace('_', '-')}",
                    module=name,
                    severity="low",
                    title=f"{name} could not complete",
                    detail=f"{type(exc).__name__}: {exc}",
                    evidence={"traceback": traceback.format_exc()[-1200:]},
                )
            )
        if not args.quiet:
            print(f"  {len(findings) - before} finding(s)")

    counts = Counter(f.severity for f in findings)
    report = {
        "target": target,
        "commit": (cfg.get("target", {}) or {}).get("commit"),
        "generated": started,
        "counts": dict(counts),
        "findings": [
            {
                "id": f.id,
                "module": f.module,
                "severity": f.severity,
                "title": f.title,
                "detail": f.detail,
                "evidence": {k: str(v) for k, v in f.evidence.items()},
                "remediation": f.remediation,
                "references": f.references,
            }
            for f in findings
        ],
    }

    parent = os.path.dirname(os.path.abspath(out_path))
    os.makedirs(parent, exist_ok=True)
    with open(out_path, "w") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")

    if not args.quiet:
        print()
        for f in findings:
            print(f.render())
            print()
        print("counts: " + ", ".join(f"{n} {s}" for s, n in
                                      sorted(counts.items(),
                                             key=lambda kv: kv[0])))
        print(f"written to {out_path}")

    blocking = sum(n for s, n in counts.items() if s.lower() in fail_on)
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
