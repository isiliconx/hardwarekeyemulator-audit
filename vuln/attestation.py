"""
The attestation chain, and the one place it is malformed.

The device mints a real certificate: a local CA issues a leaf, the leaf signs
authData || clientDataHash, and the leaf carries id-fido-gen-ce-aaguid
(1.3.6.1.4.1.45724.1.1.4) so a verifier can bind the leaf to the aaguid field.
None of that is forgeable -- it terminates at a CA this process generated, and
that is the honest limit.

What is wrong is narrower and mechanical.  RFC 4043 / id-fido-gen-ce-aaguid
defines that extension's extnValue as OCTET STRING (SIZE (16)): a single DER
OCTET STRING whose 16-byte content IS the aaguid.  The device writes
_der_octet_string(aaguid) into an UnrecognizedExtension, and cryptography
already wraps extnValue in an OCTET STRING -- so the value a verifier reads is
`04 10 <aaguid>`, 18 bytes, double-wrapped.

Every consumer of that extension therefore reads a 17-byte aaguid beginning
0x04 0x10, or the 18-byte blob, and compares it against the 16-byte field.
The comparison fails.  Their own selftest asserts only that the extension is
*present*, which is why this passes at 83/0 and is still wrong.
"""

from __future__ import annotations

import os

from tooling.harness import (
    FIDO_AAGUID_OID,
    Finding,
    aaguid_field,
    bring_up,
    fido_extension_bytes,
)
from tooling.harness import leaf_of, register

MODULE = "attestation"


def run() -> list[Finding]:
    out: list[Finding] = []
    auth, host = bring_up("packed_x5c")
    status, resp, cd, ch = register(host)

    auth_data = resp[2]
    leaf = leaf_of(resp[3])
    field = aaguid_field(auth_data)
    raw = fido_extension_bytes(leaf)

    if raw is not None and len(raw) != 16:
        unwrapped = raw[2:] if raw[:2] == b"\x04\x10" else None
        out.append(
            Finding(
                id="FIDO-AAGUID-EXTENSION-DOUBLE-WRAPPED",
                module=MODULE,
                severity="high",
                title="id-fido-gen-ce-aaguid carries a nested OCTET STRING",
                detail=(
                    f"The leaf's extension value is {len(raw)} bytes and begins "
                    f"0x{raw[0]:02x}{raw[1]:02x}, which is a DER OCTET STRING header.  "
                    f"id-fido-gen-ce-aaguid defines extnValue as OCTET STRING "
                    f"(SIZE (16)) -- one wrapping, 16 bytes of content.\n\n"
                    f"field aaguid     {field.hex()} ({len(field)} bytes)\n"
                    f"extension value {raw.hex()} ({len(raw)} bytes)\n"
                    + (f"unwrapped       {unwrapped.hex()} ({len(unwrapped)} bytes)\n"
                       if unwrapped else "")
                    + "\nA verifier doing the obvious comparison -- "
                    "ext.value.value against the aaguid field -- gets a mismatch and "
                    "either rejects a legitimate-looking credential or, worse, has a "
                    "code path that gives up on the comparison.\n\n"
                    "The value is recoverable by unwrapping once, which is why the "
                    "device's own selftest passes: it asserts the extension is "
                    "present, not that it parses to the aaguid."
                ),
                evidence={
                    "oid": "1.3.6.1.4.1.45724.1.1.4",
                    "extension_value_len": len(raw),
                    "extension_value_hex": raw.hex(),
                    "field_aaguid_len": len(field),
                    "field_aaguid_hex": field.hex(),
                    "matches_after_single_unwrap": bool(unwrapped and unwrapped == field),
                    "matches_verbatim": raw == field,
                },
                remediation=(
                    "Pass the raw 16 bytes, not _der_octet_string(aaguid):\n"
                    "    x.UnrecognizedExtension(oid, aaguid)\n"
                    "cryptography wraps extnValue in the OCTET STRING itself, so the "
                    "DER helper inside it produces the second layer."
                ),
                references=[
                    "id-fido-gen-ce-aaguid",
                    "RFC 4043 id-ce 1.3.6.1.4.1.45724.1.1.4",
                    "WebAuthn L2 s8.2",
                ],
            )
        )

    # --- is the chain structurally sound, and is it honest about that? ----
    from cryptography import x509

    self_issued = leaf.issuer == leaf.subject
    try:
        root_hint = "self-issued (leaf is its own issuer)" if self_issued else                     f"issued by {leaf.issuer.rfc4514_string()}"
    except Exception:  # noqa: BLE001
        root_hint = "unknown"

    out.append(
        Finding(
            id="ATTESTATION-TERMINATES-AT-LOCAL-CA",
            module=MODULE,
            severity="informational",
            title="The chain verifies and terminates at a CA the process made",
            detail=(
                f"leaf  {leaf.subject.rfc4514_string()}\n"
                f"issuer {root_hint}\n\n"
                "The signature is real and the chain is well-formed.  It proves the "
                "device holds the leaf key and nothing about hardware origin, which "
                "is exactly what a self-issued software CA can establish.  An RP "
                "pinning FIDO MDS attestation roots rejects this on the chain alone; "
                "that rejection is the only reason this is not a bypass, and it is a "
                "property of the RP rather than of the device."
            ),
            evidence={
                "fmt": resp[1],
                "x5c_length": len(resp[3].get("x5c", [])),
                "leaf_self_issued": self_issued,
                "aaguid": field.hex(),
            },
            references=["WebAuthn L2 s8.2", "FIDO Metadata Service BLOB payload"],
        )
    )

    # --- does their own analyser notice the extension problem? ------------
    try:
        from analyze_attestation import inspect

        analysis = inspect({"fmt": resp[1], "authData": auth_data,
                            "attStmt": resp[3]}, auth_data,
                           __import__("hashlib").sha256(cd).digest())
        says_present = analysis.get("leaf_has_fido_extension")

        # Read the extension value off the leaf and judge it here, rather than
        # assuming it is malformed.  id-fido-gen-ce-aaguid is an OCTET STRING of
        # exactly 16 bytes; anything else is a value an RP must not trust, and
        # the interesting question is whether their analyser would say so.
        raw_value = None
        for ext in leaf.extensions:
            if ext.oid.dotted_string == FIDO_AAGUID_OID:
                raw_value = ext.value.value
                break
        conformant = raw_value is not None and len(raw_value) == 16
        analyser_complains = any(
            "aaguid" in str(f.get("title", "")).lower()
            or "extension" in str(f.get("title", "")).lower()
            for f in analysis.get("findings", [])
        )
        # The analyser is right only if it flags a bad value, or if there was
        # nothing bad to flag.
        analyser_correct = conformant or analyser_complains
        out.append(
            Finding(
                id=("ANALYSER-VALIDATES-THE-AAGUID-EXTENSION"
                    if analyser_correct
                    else "ANALYSER-MISSES-MALFORMED-EXTENSION"),
                module=MODULE,
                severity="informational" if analyser_correct else "medium",
                title=("the AAGUID extension is well-formed and the analyser agrees"
                       if conformant
                       else "Their analyser reports a malformed extension as present and fine"),
                detail=(
                    f"analyze_attestation.inspect() reports "
                    f"leaf_has_fido_extension={says_present}.  The leaf's "
                    f"extnValue is "
                    + (f"{len(raw_value)} bytes"
                       if raw_value is not None else "absent")
                    + ", and id-fido-gen-ce-aaguid must hold exactly 16 bytes, so "
                    + ("the value is conformant."
                       if conformant
                       else "the value is malformed.")
                    + "\n\n"
                    + ("The device wraps it once and the analyser reads it."
                       if conformant
                       else "The analyser checks for the extension's *presence* "
                            "and never validates the value's length, so it cannot "
                            "tell a conformant leaf from this one.")
                    + f"\n\nverdict: {analysis.get('verdict')}"
                ),
                evidence={
                    "leaf_has_fido_extension": says_present,
                    "extn_value_length": (
                        len(raw_value) if raw_value is not None else None),
                    "extn_value_hex": (
                        raw_value.hex() if raw_value is not None else None),
                    "aaguid_field_hex": field.hex(),
                    "value_is_conformant": conformant,
                    "analyser_flagged_it": analyser_complains,
                    "root_is_trusted_fido_ca": analysis.get("root_is_trusted_fido_ca"),
                    "rejectable_signals": sum(
                        1 for f in analysis.get("findings", [])
                        if f.get("rp_can_reject")),
                },
                remediation=(
                    None if analyser_correct
                    else "Parse extnValue and require exactly 16 bytes before "
                         "reporting the extension as present."
                ),
                references=["id-fido-gen-ce-aaguid"],
            )
        )
    except Exception as exc:  # noqa: BLE001
        out.append(
            Finding(
                id="ANALYSER-ERROR",
                module=MODULE,
                severity="low",
                title="Their analyser raised on this certificate",
                detail=f"{type(exc).__name__}: {exc}",
            )
        )

    return out
