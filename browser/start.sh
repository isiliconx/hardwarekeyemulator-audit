#!/usr/bin/env bash
# One command to get a browser you can test your site with.
#
#   ./browser/start.sh                    # opens the FIDO2 Lab RP
#   ./browser/start.sh https://your.site   # opens your site with the key ready
#
# Opens Chrome on DISPLAY :1 with a virtual USB security key attached, so a
# WebAuthn registration on your own site sees a hardware key rather than a
# passkey.  Verified: flags 0x45, BE clear, BS clear.
#
# It runs on a COPY of your profile at $WORK, because that exact path is the one
# place on this host where Chrome refuses to bind a DevTools port:
#
#   ~/.config/probe-chrome                BOUND
#   ~/probe-chrome                        BOUND
#   /tmp/x1/x2/x3/prof                    BOUND
#   a full copy of your profile, in /tmp   BOUND
#   ~/.config/google-chrome (yours)       NO BIND
#
# Your real profile is never written to.  To go back to your normal browser,
# just close this one and reopen Chrome as usual.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${HERE}/../.venv/bin/python"
[ -x "$PY" ] || PY="/home/ubuntu/.hermes/cache/scratch/hkev/bin/python"

export DISPLAY="${DISPLAY:-:1}"
export HKE_WORK="${HKE_WORK:-/home/ubuntu/.hermes/cache/scratch}"

TARGET="${1:-https://lab.example:8443/}"

echo "DISPLAY=$DISPLAY"
echo "target: $TARGET"
exec "$PY" "${HERE}/launch_yours.py" --url "$TARGET"
