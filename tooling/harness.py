"""
Shared harness for auditing hardwarekeyemulator.

Brings up their authenticator in-process over a real CTAPHID loopback, runs
ceremonies, and provides the finding type.  Every vuln module and PoC builds on
this so the ceremony setup is written once.

Nothing here touches the network or the kernel.  The loopback transport is their
own LoopbackTransport, which frames real 64-byte CTAPHID reports.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import sys
import tempfile
import threading
from dataclasses import dataclass, field

TARGET_SRC = os.environ.get(
    "HKE_SRC", "/home/ubuntu/.hermes/cache/scratch/hke/src"
)
if TARGET_SRC not in sys.path:
    sys.path.insert(0, TARGET_SRC)

import cbor2  # noqa: E402
from cryptography import x509  # noqa: E402
from ctap2_core import (  # noqa: E402
    FLAG_AT,
    FLAG_BE,
    FLAG_BS,
    FLAG_UP,
    FLAG_UV,
    Ctap2Authenticator,
)
from ctaphid import (  # noqa: E402
    CtapHidDevice,
    CtapHidDeviceSide,
    LoopbackTransport,
)

FIDO_AAGUID_OID = "1.3.6.1.4.1.45724.1.1.4"
RP_ID = "lab.example"
ORIGIN = f"https://{RP_ID}"

_store = tempfile.TemporaryDirectory(prefix="hke-audit-")


# ---------------------------------------------------------------- findings


SEVERITIES = ["informational", "low", "medium", "high", "critical"]


@dataclass
class Finding:
    id: str
    module: str
    severity: str
    title: str
    detail: str
    evidence: dict = field(default_factory=dict)
    remediation: str = ""
    references: list = field(default_factory=list)

    def render(self) -> str:
        lines = [f"[{self.severity.upper():8s}] {self.id}  ({self.module})",
                 f"    {self.title}"]
        if self.detail:
            for para in self.detail.strip().split("\n"):
                lines.append(f"    {para}")
        if self.evidence:
            lines.append("    evidence:")
            for k, v in self.evidence.items():
                lines.append(f"      {k}: {v}")
        if self.remediation:
            lines.append(f"    fix: {self.remediation}")
        for ref in self.references:
            lines.append(f"    ref: {ref}")
        return "\n".join(lines)


# ---------------------------------------------------------------- ceremony


def client_data(ceremony: str, challenge: bytes, origin: str = ORIGIN) -> bytes:
    """ClientDataJSON exactly as a page would build it."""
    return json.dumps({
        "type": ceremony,
        "challenge": base64.urlsafe_b64encode(challenge).decode().rstrip("="),
        "origin": origin,
        "crossOrigin": False,
    }).encode()


# The PIN the harness configures so uv=true can actually be satisfied.  On the
# pristine device a bare uv_gate=lambda: True would do; CTAP 2.1 s7.2 step 3 says
# uv is met only by clientPin or pinUvAuthToken, so the patched device refuses
# uv=true outright.  Both trees are driven the same way: a PIN is set and the
# gate collects it.
HARNESS_PIN = "123456"


def bring_up(attestation_mode: str = "packed_x5c", aaguid: bytes = bytes(16),
             uv="pin", up_gate=lambda: True, uv_gate=None, **kwargs):
    """Start their device behind a real CTAPHID loopback and return (auth, host).

    `uv` picks the verification configuration, because the question of whether
    the device can assert verification it never performed only has meaning
    against a specific configuration:

      "pin"            a PIN is configured and the gate collects it.  uv=true is
                       satisfiable; this is what an honest host embedding looks
                       like, and how both trees are driven by default.
      "unconditional"  no PIN, and a gate that returns True.  This is upstream's
                       own default -- their selftests and policy_lab.build_demo
                       attestation both construct the device exactly this way --
                       and it is the configuration under test.
      "none"           no PIN and no gate at all.

    `uv_gate` overrides the gate in the "pin" and "unconditional" modes.
    """
    auth = Ctap2Authenticator(
        store_path=os.path.join(
            _store.name, f"creds-{os.urandom(6).hex()}.json"),
        attestation_mode=attestation_mode,
        aaguid=aaguid,
        up_gate=up_gate,
        **kwargs,
    )
    if uv == "pin":
        auth.set_pin(HARNESS_PIN)
        auth.uv_gate = uv_gate or (lambda: auth.verify_pin(HARNESS_PIN))
    elif uv == "unconditional":
        # No PIN at all, and a gate that asserts verification without performing
        # it.  Upstream's default configuration.
        auth.uv_gate = uv_gate or (lambda: True)
    elif uv == "none":
        auth.uv_gate = None
    else:
        raise ValueError(f"uv must be 'pin', 'unconditional' or 'none', "
                         f"not {uv!r}")
    host_t = LoopbackTransport().open()
    dev_t = host_t.peer().open()
    side = CtapHidDeviceSide(dev_t, auth, verbose=False)
    threading.Thread(target=side.serve_forever, daemon=True).start()
    host = CtapHidDevice(host_t, verbose=False)
    host.init_sequence()
    return auth, host


def register(host, rp_id: str = RP_ID, origin: str = ORIGIN,
             challenge: bytes | None = None, options: dict | None = None,
             **extra_params):
    """MakeCredential.

    `options` is the CTAP2 options map (CTAP key 7).  `extra_params` are merged
    as top-level request keys, which is a different thing entirely: spreading
    options= into the request as a top-level key lands it where the device does
    not read it, and the ceremony silently completes with uv=false.
    """
    challenge = challenge or os.urandom(32)
    cd = client_data("webauthn.create", challenge, origin)
    params = {
        1: hashlib.sha256(cd).digest(),
        2: {"id": rp_id, "name": "Lab IdP"},
        3: {"id": os.urandom(16), "name": "alice", "displayName": "Alice"},
        4: [{"type": "public-key", "alg": -7}],
        7: dict(options) if options is not None
           else {"rk": True, "up": True, "uv": True},
    }
    params.update(extra_params)
    status, resp = host.make_credential(params)
    return status, resp, cd, challenge


def assert_credential(host, rp_id: str = RP_ID, credential_id: bytes | None = None,
                      challenge: bytes | None = None, origin: str = ORIGIN,
                      options: dict | None = None, **extra_params):
    """GetAssertion.  `options` is CTAP key 5; extras are top-level keys."""
    challenge = challenge or os.urandom(32)
    cd = client_data("webauthn.get", challenge, origin)
    params = {
        1: rp_id,
        2: hashlib.sha256(cd).digest(),
        5: dict(options) if options is not None else {"up": True, "uv": False},
    }
    if credential_id is not None:
        params[3] = [{"type": "public-key", "id": credential_id,
                      "transports": ["usb"]}]
    params.update(extra_params)
    status, resp = host.get_assertion(params)
    return status, resp, cd, challenge


# ---------------------------------------------------------------- parsing


def credential_id_from(auth_data: bytes) -> bytes:
    length = struct.unpack(">H", auth_data[53:55])[0]
    return auth_data[55:55 + length]


def flags_dict(auth_data: bytes) -> dict:
    f = auth_data[32]
    return {
        "raw": f"0x{f:02x}",
        "UP": bool(f & FLAG_UP),
        "UV": bool(f & FLAG_UV),
        "BE": bool(f & FLAG_BE),
        "BS": bool(f & FLAG_BS),
        "AT": bool(f & FLAG_AT),
    }


def aaguid_field(auth_data: bytes) -> bytes:
    return auth_data[37:53]


def leaf_of(stmt: dict):
    x5c = stmt.get("x5c") or []
    return x509.load_der_x509_certificate(x5c[0]) if x5c else None


def fido_extension_bytes(leaf) -> bytes | None:
    """Raw extnValue content, or None."""
    if leaf is None:
        return None
    for ext in leaf.extensions:
        if ext.oid.dotted_string == FIDO_AAGUID_OID:
            return ext.value.value
    return None


def webauthn_attestation(response_map: dict) -> dict:
    return {"fmt": response_map[1], "authData": response_map[2],
            "attStmt": response_map[3]}


def counter_of(auth_data: bytes) -> int:
    return struct.unpack(">I", auth_data[33:37])[0]
