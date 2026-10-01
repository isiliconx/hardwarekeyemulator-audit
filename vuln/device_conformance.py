"""
The authenticator itself: CTAP2 conformance, credential isolation, counters.

Most of this passes, and the report says so.  A conformance audit that only
lists failures is indistinguishable from one that found nothing, so each check
that passes is recorded as informational with the evidence that it passed.

The two real gaps found here are both in GetInfo's shape rather than in its
values: the device reports key 4 options without clientPin or pinUvAuthToken
while offering uv, and it omits the CTAP2.1 keys entirely.
"""

from __future__ import annotations

import os
import struct

from tooling.harness import Finding, ORIGIN, RP_ID, assert_credential, bring_up, client_data
from tooling.harness import counter_of, credential_id_from, flags_dict, register

MODULE = "device_conformance"


def run() -> list[Finding]:
    out: list[Finding] = []
    auth, host = bring_up("packed_self")

    # --- GetInfo shape ----------------------------------------------------
    st, info = host.ctap2(0x04, b"")
    keys = sorted(info)
    missing = []
    for key, name, why in (
        (3, "aaguid", "CTAP 2.1 s8.3 required"),
        (4, "options", "required"),
        (5, "maxMsgSize", "required"),
        (6, "pinUvAuthProtocols", "required in 2.1"),
        (0x0A, "algorithms", "required in 2.1"),
    ):
        if key not in info:
            missing.append(f"0x{key:02x} {name} ({why})")

    options = info.get(4, {})
    out.append(
        Finding(
            id="GETINFO-MISSING-CTAP21-KEYS",
            module=MODULE,
            severity="medium",
            title="GetInfo omits keys a CTAP 2.1 client expects",
            detail=(
                f"keys present: {[hex(k) for k in keys]}.  Missing: "
                f"{', '.join(missing) if missing else 'none'}.\n\n"
                "A client that reads key 6 to learn which PIN/UV auth protocols are "
                "supported gets a KeyError or a silent default rather than an "
                "answer, and one that reads key 0x0A for the algorithm list has "
                "nothing to validate an offered algorithm against.\n\n"
                "The device declares FIDO_2_0, so the omissions are defensible under "
                "2.0 -- except that it also reports uv, which only exists in 2.1."
            ),
            evidence={
                "keys_present": str(keys),
                "versions": str(info.get(1)),
                "missing": missing,
            },
            remediation="Emit the CTAP 2.1 keys, or declare only FIDO_2_0 and drop uv.",
            references=["CTAP 2.1 s8.3", "FIDO 2.1 s8.3 GetInfo response"],
        )
    )

    # uv and the mechanism that backs it must be reported together.  clientPin
    # True with uv True is coherent; uv True with neither clientPin nor
    # pinUvAuthToken is the promise no client can keep.
    uv_on = bool(options.get("uv"))
    client_pin = bool(options.get("clientPin"))
    pin_token = bool(options.get("pinUvAuthToken"))
    if uv_on and not (client_pin or pin_token):
        out.append(
            Finding(
                id="GETINFO-UV-WITHOUT-A-UV-MECHANISM",
                module=MODULE,
                severity="high",
                title="uv is advertised while no PIN or token option is reported",
                detail=(
                    f"options: {options}.  uv is True, but clientPin is "
                    f"{options.get('clientPin')} and pinUvAuthToken is "
                    f"{options.get('pinUvAuthToken')}.\n\n"
                    "CTAP 2.1 s8.3: uv indicates the authenticator supports some "
                    "form of built-in user verification.  With neither clientPin "
                    "nor pinUvAuthToken reported, no client has a way to obtain a "
                    "verified assertion, so advertising uv invites precisely the "
                    "request the device cannot honour."
                ),
                evidence={
                    "options": str(options),
                    "clientPin": options.get("clientPin"),
                    "pinUvAuthToken": options.get("pinUvAuthToken"),
                    "uv": options.get("uv"),
                },
                references=["CTAP 2.1 s8.3", "CTAP 2.1 s7.2"],
            )
        )
    else:
        out.append(
            Finding(
                id="GETINFO-UV-MECHANISM-CONSISTENT",
                module=MODULE,
                severity="informational",
                title="GetInfo reports uv only alongside the mechanism that backs it",
                detail=(
                    f"options: {options}.  uv={options.get('uv')} with "
                    f"clientPin={options.get('clientPin')} and a PIN configured="
                    f"{getattr(auth, '_pin_hash', None) is not None}.\n\n"
                    "The GetInfo promise and the device's actual capability "
                    "agree, so a client reading this map is told the truth about "
                    "what a uv=true ceremony can obtain."
                ),
                evidence={
                    "options": str(options),
                    "uv": options.get("uv"),
                    "clientPin": options.get("clientPin"),
                    "pin_configured": getattr(auth, "_pin_hash", None) is not None,
                },
                references=["CTAP 2.1 s8.3"],
            )
        )

    # --- credential isolation --------------------------------------------
    auth2, host2 = bring_up("packed_self")
    st, r_a, _, _ = register(host2, rp_id="site-a.example",
                            origin="https://site-a.example")
    cid = credential_id_from(r_a[2])

    cross = []
    st1, _, _, _ = assert_credential(host2, rp_id="site-b.example", credential_id=cid)
    cross.append(("assert at site-b with site-a's credId", st1))
    st2, _, _, _ = assert_credential(host2, rp_id="site-b.example")
    cross.append(("assert at site-b with no allowList", st2))

    leaked = [n for n, s in cross if s == 0x00]
    out.append(
        Finding(
            id="DEVICE-CREDENTIAL-ISOLATION",
            module=MODULE,
            severity="critical" if leaked else "informational",
            title="A credential crosses RP boundaries"
            if leaked else "Credentials are isolated per RP ID",
            detail=(
                ("Leaked: " + "; ".join(leaked) + ".  A resident credential "
                 "registered at one RP must never satisfy an assertion at another.")
                if leaked else
                "\n".join(f"  {n}: 0x{s:02x}" for n, s in cross)
                + "\n\nBoth refused.  A credential registered at site-a.example does "
                "not satisfy an assertion at site-b.example, whether named by "
                "credential ID or discovered with an empty allowList.  This is the "
                "property that makes rpIdHash in authData meaningful rather than "
                "decorative."
            ),
            evidence={"probes": str(cross)},
            references=["CTAP 2.1 s7.2.2", "WebAuthn L2 s7.2"],
        )
    )

    # --- counter ----------------------------------------------------------
    auth3, host3 = bring_up("packed_self")
    st, r, _, _ = register(host3)
    cid3 = credential_id_from(r[2])
    start = counter_of(r[2])
    seq = []
    for _ in range(5):
        s, a, _, _ = assert_credential(host3, credential_id=cid3)
        seq.append(counter_of(a[2]) if s == 0x00 else None)
    monotonic = all(
        seq[i] > seq[i - 1] for i in range(1, len(seq)) if seq[i] is not None
    )
    out.append(
        Finding(
            id="DEVICE-SIGN-COUNTER",
            module=MODULE,
            severity="informational" if monotonic else "high",
            title="The signature counter advances"
            if monotonic else "The signature counter does not advance",
            detail=(
                f"registration {start}, then {seq}.  "
                + ("Strictly increasing across every assertion, which is what lets "
                   "an RP detect a cloned authenticator.  A frozen counter is the "
                   "cheapest tripwire for a device that reuses signatures."
                   if monotonic else
                   "Not strictly increasing.  A device that repeats a counter cannot "
                   "be distinguished from a clone by the RP.")
            ),
            evidence={"at_registration": start, "assertions": str(seq),
                      "strictly_increasing": monotonic},
            references=["WebAuthn L2 s6.1.1 signCount"],
        )
    )

    # --- exclude list -----------------------------------------------------
    auth4, host4 = bring_up("packed_self")
    st, r4, cd4, ch4 = register(host4)
    cid4 = credential_id_from(r4[2])
    cd4b = client_data("webauthn.create", os.urandom(32))
    st5, _ = host4.make_credential({
        1: __import__("hashlib").sha256(cd4b).digest(),
        2: {"id": RP_ID, "name": "Lab IdP"},
        3: {"id": os.urandom(16), "name": "alice", "displayName": "Alice"},
        4: [{"type": "public-key", "alg": -7}],
        6: [{"type": "public-key", "id": cid4}],
        7: {"rk": True, "up": True, "uv": True},
    })
    respected = st5 != 0x00
    out.append(
        Finding(
            id="DEVICE-EXCLUDE-LIST",
            module=MODULE,
            severity="informational" if respected else "medium",
            title="The exclude list blocks re-registration"
            if respected else "The exclude list is ignored",
            detail=(
                f"Registering with the existing credential in excludeList returned "
                f"0x{st5:02x}.  "
                + ("Refused, which is what stop a second credential from silently "
                   "coexisting with the first for the same account."
                   if respected else
                   "Accepted.  A second credential is created alongside the first, "
                   "so an RP that keys on (rpId, userId) ends up with two.")
            ),
            evidence={"status": f"0x{st5:02x}", "respected": respected},
            references=["CTAP 2.1 s7.1"],
        )
    )

    return out
