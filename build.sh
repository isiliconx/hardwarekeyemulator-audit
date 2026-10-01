#!/usr/bin/env bash
# Build and validate the hardwarekeyemulator audit.
#
#   ./build.sh          venv + requirements + the target's own selftests
#   ./build.sh test     then the vuln modules, the PoCs, and the full report
#   ./build.sh clean    drop the venv

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${ROOT}/.venv"
PY="${VENV}/bin/python"
export PYTHON="${PY}"

# Where the upstream checkout lives (pristine) and where the patched copy goes.
# See recon/paths.sh -- defaults to a sibling of this project.
# shellcheck source=recon/paths.sh
. "${ROOT}/recon/paths.sh"

find_python() {
  for c in python3.12 python3.13 python3.11 python3; do
    if command -v "$c" >/dev/null 2>&1 &&
       "$c" -c 'import sys; sys.exit(0 if sys.version_info>=(3,11) else 1)' 2>/dev/null; then
      echo "$c"; return 0
    fi
  done
  return 1
}

create_venv() {
  local base
  base="$(find_python)" || { echo "no python3.11+ found" >&2; exit 1; }
  echo "==> base interpreter: $base ($("$base" --version 2>&1))"

  # Some distributions ship python3 without ensurepip.  Fall back to
  # --without-pip and bootstrap rather than failing on a stock box.
  if "$base" -m venv "$VENV" 2>/dev/null && [ -x "$PY" ]; then
    "$PY" -m pip --version >/dev/null 2>&1 || "$PY" -m ensurepip --upgrade >/dev/null 2>&1 || true
  else
    echo "==> venv has no pip; bootstrapping"
    rm -rf "$VENV"
    "$base" -m venv --without-pip "$VENV"
    "$PY" - <<'PYEOF'
import urllib.request
urllib.request.urlretrieve("https://bootstrap.pypa.io/get-pip.py", "/tmp/get-pip.py")
PYEOF
    "$PY" /tmp/get-pip.py --quiet
  fi

  "$PY" -m pip install --quiet --upgrade pip wheel
  "$PY" -m pip install --quiet -r "${ROOT}/requirements.txt"
  echo "==> venv ready"
}

case "${1:-all}" in
  clean)
    rm -rf "$VENV"
    echo "removed ${VENV}"
    ;;
  all)
    [ -x "$PY" ] || create_venv
    echo "==> fetching the target"
    "${ROOT}/recon/fetch.sh"
    ;;
  test)
    [ -x "$PY" ] || create_venv
    echo "==> fetching the target"
    "${ROOT}/recon/fetch.sh"
    echo "==> audit modules"
    (cd "$ROOT" && "$PY" -m tooling.run_all --only uv_bypass attestation         rp_verifier policy_shapes device_conformance --out /tmp/hke-findings.json --quiet) || true
    echo "==> report"
    (cd "$ROOT" && "$PY" - <<'PYEOF'
import json
from collections import Counter
r = json.load(open("/tmp/hke-findings.json"))
c = Counter(f["severity"] for f in r["findings"])
print("  " + ", ".join(f"{n} {s}" for s, n in sorted(c.items())))
errs = [f["id"] for f in r["findings"] if f["id"].startswith("MODULE-ERROR")]
if errs:
    raise SystemExit(f"  modules failed: {', '.join(errs)}")
for f in r["findings"]:
    if f["severity"] in ("critical", "high"):
        print(f"  [{f['severity']:8s}] {f['id']}")
PYEOF
    )
    echo "==> PoCs"
    (cd "$ROOT" && "$PY" exploit/uv_forge.py | tail -4)
    (cd "$ROOT" && "$PY" exploit/aaguid_mismatch.py | tail -4)
    echo "==> tests"
    (cd "$ROOT" && "$PY" tests/test_modules.py)
    echo "==> remediation"
    (cd "$ROOT" && "$PY" exploit/apply_fix.py --check "$TARGET" >/dev/null) \
      && echo "  apply_fix.py    all hunks match"
    (cd "$ROOT" && "$PY" exploit/fix_tests.py --check "$TARGET" >/dev/null) \
      && echo "  fix_tests.py    all hunks match"
    (cd "$ROOT" && "$PY" exploit/fix_uv_sites.py --check "$TARGET" >/dev/null) \
      && echo "  fix_uv_sites.py all hunks match"
    echo "==> patching a working copy and running their suite"
    (cd "$ROOT" && ./recon/patch_tree.sh)
    echo "==> differential (baseline vs patched)"
    (cd "$ROOT" && "$PY" tests/test_differential.py | tail -3)
    ;;
  remediate)
    [ -x "$PY" ] || create_venv
    echo "==> applying the remediation to ${1:-$TARGET}"
    "$PY" "${ROOT}/exploit/apply_fix.py" "${1:-$TARGET}"
    "$PY" "${ROOT}/exploit/fix_tests.py" "${1:-$TARGET}"
    "$PY" "${ROOT}/exploit/fix_uv_sites.py" "${1:-$TARGET}"
    ;;
  *)
    echo "usage: $0 [all|test|remediate [checkout]|clean]" >&2
    exit 2
    ;;
esac
