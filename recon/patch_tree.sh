#!/usr/bin/env bash
# Build the patched tree from the pristine checkout, every time.
#
# The differential in tests/test_differential.py compares two directories, so the
# second one has to be derivable from the first rather than hand-edited: a
# patched tree that accumulates edits across runs makes a "the fix works" claim
# unfalsifiable.  This script therefore always starts from a fresh copy.
#
#   ./patch_tree.sh              rebuild $PATCHED and run their suite there
#   ./patch_tree.sh --no-tests   rebuild only
#
# The audit's own checkout at $TARGET is never modified.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=recon/paths.sh
. "${ROOT}/recon/paths.sh"

[ -x "$PY" ] || PY="$(command -v python3)"

if [ ! -d "$TARGET/src" ]; then
  echo "no upstream checkout at ${TARGET}" >&2
  echo "run ./build.sh all first" >&2
  exit 2
fi

echo "  rebuilding ${PATCHED} from ${TARGET}"
rm -rf "$PATCHED"
cp -r "$TARGET" "$PATCHED"
find "$PATCHED" -name '*.orig' -delete
find "$PATCHED" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

for script in apply_fix fix_tests fix_uv_sites; do
  echo "  ${script}.py"
  "$PY" "${ROOT}/exploit/${script}.py" "$PATCHED" | sed 's/^/    /'
done

if [ "${1:-}" = "--no-tests" ]; then
  exit 0
fi

echo "  their suite, on the patched tree:"
fail=0
for t in selftest_hid selftest_e2e selftest_uhid; do
  line="$(cd "$PATCHED" && PYTHONPATH=src "$PY" "src/${t}.py" 2>&1 | tail -1)"
  printf '    %-14s %s\n' "$t" "$line"
  case "$line" in
    *"0 failed") ;;
    *) fail=1 ;;
  esac
done

if "$PY" -c 'import pytest' 2>/dev/null; then
  line="$(cd "$PATCHED" && PYTHONPATH=src "$PY" -m pytest tests -q 2>&1 | tail -1)"
  printf '    %-14s %s\n' "pytest tests" "$line"
  case "$line" in
    *"failed"*) fail=1 ;;
  esac
else
  echo "    pytest        not installed (skipping tests/)"
fi

if [ "$fail" -ne 0 ]; then
  echo "  the patched tree does not pass its own suite" >&2
  exit 1
fi
echo "  patched tree passes upstream's suite"