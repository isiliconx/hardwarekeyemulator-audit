#!/usr/bin/env bash
# Shared path resolution.  Source this; do not execute it.
#
#   . "$(dirname "$0")/recon/paths.sh"
#
# Every path in this project derives from HKE_WORK, so a clone runs on any
# machine with no edits.  Override by exporting HKE_WORK (or the individual
# variables) before sourcing.
#
#   <HKE_WORK>/hke         pristine upstream checkout, never modified
#   <HKE_WORK>/hke-fixed   rebuilt from pristine by recon/patch_tree.sh
#
# Defaults to a sibling directory of the project.

# Self-locating, so this file does not depend on the caller having set ROOT.
_PATHS_SH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${ROOT:-$(cd "${_PATHS_SH}/.." && pwd)}"

HKE_WORK="${HKE_WORK:-$(cd "${ROOT}/.." && pwd)/.hke-work}"
HKE_TARGET="${HKE_TARGET:-${HKE_WORK}/hke}"
HKE_PATCHED="${HKE_PATCHED:-${HKE_WORK}/hke-fixed}"

TARGET="${HKE_TARGET}"
TARGET_SRC="${TARGET}/src"
PATCHED="${HKE_PATCHED}"
PATCHED_SRC="${PATCHED}/src"

VENV="${ROOT}/.venv"
PY="${VENV}/bin/python"

export ROOT HKE_WORK TARGET TARGET_SRC PATCHED PATCHED_SRC VENV PY
export HKE_TARGET HKE_PATCHED

mkdir -p "$HKE_WORK"