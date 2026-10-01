"""
One place that decides where the upstream checkout and the patched copy live.

Everything else imports from here.  The rule: paths derive from HKE_WORK, which
defaults to a sibling directory of this project, so a clone runs on any machine
with no edits and no absolute paths baked into the source.

    <HKE_WORK>/hke         pristine upstream checkout, never modified
    <HKE_WORK>/hke-fixed   rebuilt from pristine by recon/patch_tree.sh

Override by exporting HKE_WORK before running anything.  HKE_SRC overrides the
pristine tree alone, which is what tests/test_differential.py uses to point one
sweep at a different tree.

Paths deliberately sit outside the project directory: recon/patch_tree.sh
deletes and re-copies the patched tree on every run, and a checkout kept inside
the tree being copied would delete itself.
"""

from __future__ import annotations

import os

HERE = os.path.dirname(os.path.abspath(__file__))          # .../hardwarekeyemulator-audit
ROOT = os.path.dirname(HERE)

# Sibling of the project directory, not inside it.
DEFAULT_WORK = os.path.join(os.path.dirname(ROOT), ".hke-work")


def _resolve() -> tuple[str, str]:
    """Return (baseline_src, patched_src)."""
    work = os.environ.get("HKE_WORK") or DEFAULT_WORK
    baseline = os.environ.get(
        "HKE_TARGET") or os.path.join(work, "hke")
    patched = os.environ.get(
        "HKE_PATCHED") or os.path.join(work, "hke-fixed")

    # An explicit HKE_SRC wins: a caller pointing at one specific tree (the
    # differential) means exactly that and should not have it overridden by a
    # stale HKE_TARGET.
    baseline_src = os.environ.get("HKE_SRC") or os.path.join(baseline, "src")
    return os.path.abspath(baseline_src), os.path.abspath(patched + "/src")


BASELINE_SRC, PATCHED_SRC = _resolve()


def describe() -> str:
    """One line naming both trees, for logs and error messages."""
    return f"baseline={BASELINE_SRC}  patched={PATCHED_SRC}"