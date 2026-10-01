"""
Their RP verifier, attacked.

rp_verify.py is the part of this project that would actually be deployed, and it
holds up better than the device: a forged attestation signature is refused, a
signature moved onto a fresh challenge is refused, cross-origin is refused.

Two things are worth reporting anyway.  The identical replay is accepted, which
is correct for a stateless signature check and is a property of every WebAuthn
verifier -- but it is the one place their code makes no attempt at challenge
reuse, so an RP built on it inherits that gap silently.  And the verifier
records `attestation_verified` from policy rather than from the verification it
just performed, which is a reporting field that can lie.
"""

from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tooling.harness import Finding, ORIGIN, RP_ID, assert_credential, bring_up
from tooling.harness import counter_of, credential_id_from, register
from tooling.harness import webauthn_attestation

MODULE = "rp_verifier"

RELAXED = {"require_attestation": False}


def run() -> list[Finding]:
    out: list[Finding] = []
    from rp_verify import POLICY, RpError, verify_assertion, verify_registration

    # --- registration: does it refuse a forged attestation? ---------------
    auth, host = bring_up("packed_x5c")
    st, resp, cd, ch = register(host)
    clean = webauthn_attestation(resp)
    reg = verify_registration(RP_ID, cd, clean, ch, expected_origin=ORIGIN,
                              policy=RELAXED)

    attacker = ec.generate_private_key(ec.SECP256R1())
    forged = {"fmt": clean["fmt"], "authData": clean["authData"],
              "attStmt": dict(clean["attStmt"])}
    forged["attStmt"]["sig"] = attacker.sign(
        clean["authData"] + __import__("hashlib").sha256(cd).digest(),
        ec.ECDSA(hashes.SHA256()))

    try:
        verify_registration(RP_ID, cd, forged, ch, expected_origin=ORIGIN,
                            policy=RELAXED)
        forged_refused = False
        forged_reason = "accepted"
    except RpError as exc:
        forged_refused = True
        forged_reason = str(exc)

    out.append(
        Finding(
            id="RP-REFUSES-FORGED-ATTESTATION",
            module=MODULE,
            severity="informational" if forged_refused else "critical",
            title="A forged attestation signature is refused",
            detail=(
                f"{'Refused' if forged_refused else 'ACCEPTED'}: {forged_reason}.  "
                "The verifier loads x5c[0] and verifies against the leaf key, which "
                "is the rule WebAuthn L2 s8.2 states and the one implementations "
                "most often get wrong by verifying against the credential key."
            ),
            evidence={
                "clean_registration_accepted": True,
                "forged_refused": forged_refused,
                "reason": forged_reason,
                "signature_length_original": len(clean["attStmt"]["sig"]),
                "signature_length_forged": len(forged["attStmt"]["sig"]),
            },
            references=["WebAuthn L2 s8.2"],
        )
    )

    # --- does attestation_verified report the verification, or the policy? --
    # Two calls that differ only in require_attestation.  If the field tracks the
    # proof it reads True in both; if it tracks the policy it flips with the
    # setting, which would mean a verifier that just checked a signature reports
    # False because nobody asked it to.
    off_flag = reg["attestation_verified"]
    gated_flag = None
    gated_reason = None
    # require_attestation=True legitimately REFUSES this certificate, because
    # the chain terminates at a local CA the process created and nothing is
    # pinned.  A refusal says nothing about the field, so the second probe pins
    # that same local root instead: the statement is then verified and the gate
    # is satisfied, which is the case where the flag must still read True.
    root_der = None
    try:
        from cryptography import x509 as _x509

        chain = clean["attStmt"].get("x5c", [])
        if len(chain) > 1:
            root_der = _x509.load_der_x509_certificate(chain[-1])
            from cryptography.hazmat.primitives import hashes as _hashes

            fp = root_der.fingerprint(_hashes.SHA256()).hex()
            gated = verify_registration(
                RP_ID, cd, clean, ch, expected_origin=ORIGIN,
                policy={**RELAXED, "require_attestation": True,
                        "trusted_attestation_root_sha256": [fp]},
            )
            gated_flag = gated["attestation_verified"]
    except Exception as exc:  # noqa: BLE001
        gated_reason = f"{type(exc).__name__}: {exc}"

    tracks_proof = bool(off_flag) and bool(gated_flag)
    out.append(
        Finding(
            id=("RP-ATTESTATION-VERIFIED-REPORTS-THE-PROOF"
                if tracks_proof
                else "RP-ATTESTATION-VERIFIED-FLAG-FOLLOWS-POLICY"),
            module=MODULE,
            severity="informational" if tracks_proof else "medium",
            title=("attestation_verified reports the verification, not the policy"
                   if tracks_proof
                   else "attestation_verified reflects the policy, not the check"),
            detail=(
                f"Two calls over the same valid attestation, differing only in "
                f"require_attestation (off: {RELAXED['require_attestation']}, on: "
                f"True), return attestation_verified="
                f"{off_flag} and {gated_flag}."
                + (f"  The gated call raised {gated_reason}." if gated_reason else "")
                + "\n\n"
                + (
                    "The signature was verified in both calls, so the field "
                    "correctly describes what the function proved and is "
                    "independent of whether a policy gate was configured.  An "
                    "audit log reading this field gets the truth."
                    if tracks_proof
                    else "The field flips with the policy setting rather than with "
                         "the verification, so it reads False on a certificate "
                         "whose signature was verified a few lines earlier, and "
                         "would read True for any fmt other than none if a policy "
                         "value were misconfigured."
                )
            ),
            evidence={
                "attestation_verified_require_attestation_off": off_flag,
                "attestation_verified_require_attestation_on": gated_flag,
                "policy_require_attestation": RELAXED["require_attestation"],
                "fmt": reg["fmt"],
                "tracks_the_proof": tracks_proof,
                "signature_actually_verified": True,
            },
            remediation=(
                None if tracks_proof else
                "Return attestation_verified=True only when the statement "
                "signature verified in this call."
            ),
            references=["WebAuthn L2 s8.2"],
        )
    )

    # --- assertion replay --------------------------------------------------
    auth2, host2 = bring_up("packed_self")
    st, resp2, cd2, ch2 = register(host2)
    clean2 = webauthn_attestation(resp2)
    reg2 = verify_registration(RP_ID, cd2, clean2, ch2, expected_origin=ORIGIN,
                               policy=RELAXED)
    cid = reg2["credential_id"]
    der = reg2["public_key_der"]
    stored = reg2["sign_count"]

    chal = os.urandom(32)
    st3, ar, cd3, ch3 = assert_credential(host2, credential_id=cid, challenge=chal)
    captured = {1: {"id": cid, "type": "public-key"}, 2: ar[2], 3: ar[3]}

    results = {}
    for name, use_chal, use_cd, origin in (
        ("identical replay", ch3, cd3, ORIGIN),
        ("fresh challenge", os.urandom(32), None, ORIGIN),
        ("cross origin", os.urandom(32), None, "https://evil.example"),
    ):
        ch = use_chal or os.urandom(32)
        body = use_cd or __import__("tooling.harness", fromlist=["client_data"]).client_data(
            "webauthn.get", ch, origin)
        try:
            verify_assertion(RP_ID, body, captured, der, stored, ch,
                             expected_origin=origin, policy=RELAXED)
            results[name] = "ACCEPTED"
        except RpError as exc:
            results[name] = f"refused: {str(exc)[:60]}"

    accepted = [n for n, v in results.items() if v == "ACCEPTED"]
    out.append(
        Finding(
            id="RP-IDENTICAL-REPLAY-ACCEPTED",
            module=MODULE,
            severity="medium" if "identical replay" in accepted else "informational",
            title="A verbatim assertion replay is accepted"
            if "identical replay" in accepted
            else "Verbatim replay is refused",
            detail=(
                "\n".join(f"  {n:18s} {v}" for n, v in results.items())
                + "\n\nThe in-band replays are refused because the signature covers "
                "authData || clientDataHash: substituting the clientDataJSON changes "
                "the signed message.  A verbatim replay carries no such change, so "
                "nothing in the assertion distinguishes it.\n\n"
                "That is not a verifier bug -- it is what a stateless signature check "
                "is.  It becomes a login-reuse bug the moment an RP stores no state, "
                "and their verifier keeps none: no spent-challenge cache, and the "
                "counter check accepts an equal value.  A verifier built on this "
                "needs a challenge cache or strictly advancing per-credential "
                "counters on the RP side."
                if "identical replay" in accepted else
                "\n".join(f"  {n:18s} {v}" for n, v in results.items())
            ),
            evidence={
                "results": str(results),
                "captured_counter": counter_of(ar[2]),
                "stored_counter": stored,
                "challenge_cache": False,
            },
            remediation="Store spent challenges, or require the counter to strictly advance per credential.",
            references=["WebAuthn L2 s7.2"],
        )
    )

    return out
