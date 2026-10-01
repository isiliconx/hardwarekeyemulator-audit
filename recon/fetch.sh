#!/usr/bin/env bash
# Clone or update the target, record the commit, and confirm it imports.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=recon/paths.sh
. "${ROOT}/recon/paths.sh"
SRC="${TARGET}"
REPO="https://github.com/isiliconx/hardwarekeyemulator"

if [ -d "$SRC/.git" ]; then
  echo "==> updating existing checkout at $SRC"
  git -C "$SRC" fetch --quiet origin
  git -C "$SRC" checkout --quiet "${HKE_COMMIT:-0fac0f6}" 2>/dev/null \
    || git -C "$SRC" checkout --quiet main
else
  echo "==> cloning $REPO into $SRC"
  git clone --depth 1 "$REPO" "$SRC"
fi

echo "==> commit $(git -C "$SRC" rev-parse --short HEAD)"
echo "==> $(find "$SRC/src" -name '*.py' | wc -l) python file(s), $(find "$SRC/src" -name '*.py' | xargs wc -l | tail -1 | awk '{print $1}') lines"

# Import check: every module the audit touches must load.
echo "==> import check"
PYTHONPATH="$SRC/src" "${PYTHON:-python3}" - <<'EOF'
import importlib
mods = [
    "ctap2_core", "ctaphid", "rp_verify", "policy_lab",
    "analyze_attestation", "ctaphid_server",
]
bad = []
for m in mods:
    try:
        importlib.import_module(m)
        print(f"  ok    {m}")
    except Exception as exc:
        print(f"  FAIL  {m}: {type(exc).__name__}: {exc}")
        bad.append(m)
raise SystemExit(f"{len(bad)} module(s) failed to import" if bad else 0)
EOF

echo "==> their own selftests"
cd "$SRC"
for t in selftest_hid selftest_e2e selftest_uhid; do
  PYTHONPATH="$SRC/src" "${PYTHON:-python3}" "src/$t.py" 2>&1 | tail -1
done
