"""
Their four enforcement shapes, driven with a forged signature.

policy_lab.classify() takes a pre-parsed attestation plus a `sig_ok` boolean and
returns four independent verdicts -- the four shapes real RPs ship.  This module
feeds it a real certificate with a signature that does not verify and records
which shapes still call the credential a hardware key.

This is the finding their own README identifies, and it is real.  It is also not
a defect in their *device*: it is a demonstration that presence-only attestation
gates do not work, which is what policy_lab.py exists to show.  The severity
here is the exposure, not a bug in the audited code.

The one thing worth checking further is whether D is the only shape that catches
it, and whether a shape could be written that catches it without the MDS.
"""

from __future__ import annotations

from tooling.harness import Finding, aaguid_field, bring_up, leaf_of, register

MODULE = "policy_shapes"


def run() -> list[Finding]:
    out: list[Finding] = []
    auth, host = bring_up("packed_x5c")
    status, resp, cd, ch = register(host)

    auth_data = resp[2]
    leaf = leaf_of(resp[3])
    parsed = {
        "flags": auth_data[32],
        "fmt": resp[1],
        "aaguid": aaguid_field(auth_data).hex(),
        "leaf_issuer": leaf.issuer.rfc4514_string(),
    }

    from policy_lab import classify

    honest = classify(parsed, True)
    forged = classify(parsed, False)

    accepted_forged = [
        name for name, v in forged.items() if v["counts_as_hardware_key"]
    ]
    rejected_forged = [
        name for name, v in forged.items() if not v["counts_as_hardware_key"]
    ]

    out.append(
        Finding(
            id="POLICY-THREE-OF-FOUR-SHAPES-ACCEPT-FORGED-SIG",
            module=MODULE,
            severity="high",
            title="A non-verifying attestation is still called a hardware key by three of four shapes",
            detail=(
                "Same credential, same browser, same flags; only the signature "
                "validity differs.\n\n"
                + "\n".join(
                    f"  {name:18s} sig_ok=True  -> "
                    f"{'HARDWARE' if honest[name]['counts_as_hardware_key'] else 'passkey '}"
                    for name in honest)
                + "\n"
                + "\n".join(
                    f"  {name:18s} sig_ok=False -> "
                    f"{'HARDWARE' if forged[name]['counts_as_hardware_key'] else 'passkey '}"
                    for name in forged)
                + f"\n\nWith sig_ok=False, {len(accepted_forged)} shape(s) still report "
                f"a hardware key: {', '.join(accepted_forged)}.  "
                f"Only {', '.join(rejected_forged)} rejects it.\n\n"
                "Shape C is the important one: it checks that an attStmt is present "
                "and never inspects the signature, which is what "
                "attestation: 'direct' becomes in a verifier written that way.  "
                "Requesting attestation and then only checking that a statement "
                "arrived makes the request decorative."
            ),
            evidence={
                "flags": f"0x{parsed['flags']:02x}",
                "fmt": parsed["fmt"],
                "aaguid": parsed["aaguid"],
                "accepted_with_forged_sig": accepted_forged,
                "rejected_with_forged_sig": rejected_forged,
                "C_reason": forged.get("C_ATTEST_PRESENT", {}).get("reason", ""),
                "D_reason": forged.get("D_MDS_TRUSTED", {}).get("reason", ""),
            },
            remediation=(
                "Treat 'attestation present' and 'attestation verified' as different "
                "requirements.  If an RP wants direct attestation it must verify the "
                "statement signature, and if it wants vendor identity it must pin an "
                "MDS root.  Presence alone is not evidence."
            ),
            references=[
                "WebAuthn L2 s8.2 attestation statement verification",
                "WebAuthn L3 s10 attestation conveyance policies",
            ],
        )
    )

    # --- is there a shape that catches it without the MDS? ----------------
    # Chain-only verification: does the signature verify under the leaf key?
    # That is checkable here and is the cheapest real gate.
    from cryptography import x509

    leaf_pub = leaf.public_key()
    sig = resp[3].get("sig")
    try:
        leaf_pub.verify(sig, auth_data + __import__("hashlib").sha256(cd).digest(),
                        __import__("cryptography.hazmat.primitives.asymmetric.ec",
                                   fromlist=["ECDSA"]).ECDSA(
                            __import__("cryptography.hazmat.primitives.hashes",
                                       fromlist=["SHA256"]).SHA256()))
        chain_only_honest = True
    except Exception:  # noqa: BLE001
        chain_only_honest = False

    out.append(
        Finding(
            id="POLICY-CHAIN-ONLY-GATE-IS-AVAILABLE",
            module=MODULE,
            severity="informational",
            title="A signature-verification gate catches this without the MDS",
            detail=(
                "D is the strongest shape, but it needs the FIDO MDS, which is a "
                "network dependency and a signing-root problem.  The cheapest gate "
                "that actually works is one ECDSA verification under the leaf key: "
                "it catches tampering and forged signatures, which is everything "
                "shapes A and C miss.\n\n"
                f"On this certificate that check is "
                f"{'satisfied' if chain_only_honest else 'not satisfied'}, confirming "
                "it is computable from material already in the response.  It still "
                "proves nothing about hardware origin -- that is what the MDS is for "
                "-- so the two are complementary, not alternatives."
            ),
            evidence={
                "signature_verifies_under_leaf": chain_only_honest,
                "x5c_present": bool(resp[3].get("x5c")),
            },
            references=["WebAuthn L2 s8.2"],
        )
    )

    # --- the syncability shape is the one this device controls ------------
    be = bool(parsed["flags"] & 0x08)
    out.append(
        Finding(
            id="POLICY-SYNCABILITY-IS-CLIENT-CONTROLLED",
            module=MODULE,
            severity="informational",
            title="Shape B reads a flag the authenticator chooses",
            detail=(
                f"BE(0x08) is {'set' if be else 'clear'}, so shape B "
                f"{'calls this a passkey' if be else 'calls this a hardware key'}.  "
                "The flag is written by the authenticator and carried in "
                "authenticatorData inside the signature, so it is authentic -- but "
                "nothing binds it to the device's nature.  A software authenticator "
                "that emits BE=clear is indistinguishable from a security key at "
                "this layer, which is exactly why shape B is the one most sites "
                "ship and the one that proves least.\n\n"
                "This is a Chromium sorting behaviour being mistaken for an "
                "authenticity signal."
            ),
            evidence={
                "BE_flag": be,
                "BS_flag": bool(parsed["flags"] & 0x10),
                "shape_B_verdict": honest["B_SYNCABILITY"]["reason"],
            },
            references=["WebAuthn L2 s6.1.1 authenticator data flags"],
        )
    )

    return out
