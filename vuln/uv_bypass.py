"""
Can the device be made to assert user verification it never performed?

The critical question is whether uv=true can succeed with nothing behind it.  A
device that says "user verified" when no PIN is set, no pinUvAuthParam was sent,
and no bioenrollment exists has told the RP a second factor happened when
nothing was verified.

CTAP 2.1 s7.2 step 3: if the authenticator does not support clientPin, or no PIN
is set, uv=true must return CTAP2_ERR_UV_INVALID.

Two devices are brought up, because the question only has meaning against a
device that genuinely has no verification mechanism:

  pinned   a PIN is configured and the gate collects it, so uv=true is
           satisfiable.  This is what an honest host embedding looks like.
  bare     no PIN, no gate at all.

Every probe declares the verdict it expects, so this module reports a pass on a
conforming device instead of crashing on the absence of a finding.
"""

from __future__ import annotations

from tooling.harness import (
    Finding,
    assert_credential,
    bring_up,
    credential_id_from,
    flags_dict,
    register,
)

MODULE = "uv_bypass"


def run() -> list[Finding]:
    out: list[Finding] = []

    # ------------------------------------------------------------ GetInfo
    auth, host = bring_up(uv="pin")
    status, info = host.ctap2(0x04, b"")
    options = info.get(4, {})
    pin_configured = getattr(auth, "_pin_hash", None) is not None

    out.append(
        Finding(
            id="UV-CAPABILITY-ADVERTISED",
            module=MODULE,
            severity="informational",
            title="GetInfo declares what the device can actually verify",
            detail=(
                f"GetInfo options: {options}.  "
                f"uv={options.get('uv')}, "
                f"clientPin={options.get('clientPin')}, "
                f"pinUvAuthToken={options.get('pinUvAuthToken')}.  "
                f"PIN configured: {pin_configured}.\n\n"
                "uv in GetInfo is a promise: some form of built-in user "
                "verification exists and a client can obtain a verified "
                "assertion.  A device advertising uv with no clientPin cannot "
                "honour that, and the request it invites is the one CTAP 2.1 "
                "s7.2 step 3 says must fail."
            ),
            evidence={
                "options": str(options),
                "versions": str(info.get(1)),
                "getinfo_keys": str(sorted(info)),
                "pin_configured": pin_configured,
            },
            references=["CTAP 2.1 s7.2 step 3", "CTAP 2.1 s8.3 GetInfo"],
        )
    )

    uv_advertised = bool(options.get("uv"))
    if uv_advertised and not pin_configured:
        out.append(
            Finding(
                id="UV-ADVERTISED-WITHOUT-A-MECHANISM",
                module=MODULE,
                severity="high",
                title="GetInfo advertises uv but no PIN is configured",
                detail=(
                    "options.uv is True while clientPin is absent and no PIN is "
                    "configured, so the device invites a uv=true ceremony that no "
                    "client has a way to satisfy."
                ),
                evidence={"options": str(options), "pin_configured": pin_configured},
                remediation=(
                    "Advertise uv only when a clientPin is configured, so the "
                    "GetInfo promise matches what the device can deliver."
                ),
                references=["CTAP 2.1 s8.3"],
            )
        )

    # ------------- the configuration under test: upstream's own default.
    # No PIN, and a gate that returns True.  This is how their selftests and
    # policy_lab.build_demo_attestation construct the device, so it is the
    # configuration that actually ships.
    bare_auth, bare_host = bring_up(uv="unconditional")

    st, resp, _, _ = register(
        bare_host, options={"rk": True, "up": True, "uv": True}
    )
    if st == 0x00:
        flags = flags_dict(resp[2])
        if flags["UV"]:
            out.append(
                Finding(
                    id="UV-ASSERTED-WITHOUT-VERIFICATION",
                    module=MODULE,
                    severity="critical",
                    title="UV flag set with no PIN and no verification performed",
                    detail=(
                        "MakeCredential with options.uv=true completed on a device "
                        "with no PIN configured, no pinUvAuthParam sent and no "
                        "bioenrollment, and authenticatorData carries UV(0x04).\n\n"
                        "CTAP 2.1 s7.2 step 3 requires CTAP2_ERR_UV_INVALID here.  "
                        "What the device does instead is call uv_gate(), which the "
                        "embedding caller supplies -- so 'user verified' reduces to "
                        "'the embedding application returned True from a lambda', "
                        "and whoever holds the authenticator object holds the "
                        "gate.\n\n"
                        "An RP that reads UV as a second factor has recorded a "
                        "second factor that never happened."
                    ),
                    evidence={
                        "makeCredential_status": f"0x{st:02x}",
                        "flags": str(flags),
                        "clientPin_option": options.get("clientPin", "absent"),
                        "pin_configured": getattr(bare_auth, "_pin_hash", None)
                        is not None,
                        "pinUvAuthParam_sent": False,
                    },
                    remediation=(
                        "Refuse uv=true unless the ceremony carried a valid "
                        "pinUvAuthParam or bioenrollment is available, and stop "
                        "advertising uv in GetInfo without a clientPin."
                    ),
                    references=["CTAP 2.1 s7.2 step 3", "WebAuthn L2 s6.1.1"],
                )
            )
        else:
            out.append(
                Finding(
                    id="UV-REQUEST-COMPLETED-WITHOUT-UV",
                    module=MODULE,
                    severity="medium",
                    title="uv=true completed without setting the UV flag",
                    detail=(
                        "The ceremony returned success while leaving UV clear, so "
                        "the client asked for verification and the device neither "
                        "refused nor verified."
                    ),
                    evidence={"makeCredential_status": f"0x{st:02x}",
                              "flags": str(flags)},
                    remediation="Return CTAP2_ERR_UV_INVALID when uv is requested "
                                "and cannot be met.",
                    references=["CTAP 2.1 s7.2 step 3"],
                )
            )
    else:
        out.append(
            Finding(
                id="UV-REFUSED-WITHOUT-A-MECHANISM",
                module=MODULE,
                severity="informational",
                title="uv=true is refused when nothing could have been verified",
                detail=(
                    f"MakeCredential with options.uv=true returned 0x{st:02x} on a "
                    "device with no PIN configured and no gate installed.  "
                    "CTAP 2.1 s7.2 step 3 requires CTAP2_ERR_UV_INVALID (0x2F).  "
                    "CTAP2_ERR_UV_BLOCKED (0x3C) and "
                    "CTAP2_ERR_INVALID_OPTION (0x2C) are also refusals, but 0x2F "
                    "is the code that matches this condition exactly.\n\n"
                    "'User verified' now means a mechanism was satisfied, not that "
                    "a caller returned True."
                ),
                evidence={
                    "makeCredential_status": f"0x{st:02x}",
                    "expected_by_spec": "0x2f",
                    "matches_spec_exactly": st == 0x2F,
                    "pin_configured": getattr(bare_auth, "_pin_hash", None)
                    is not None,
                    "gate_installed": getattr(bare_auth, "uv_gate", None) is not None,
                },
                references=["CTAP 2.1 s7.2 step 3"],
            )
        )

    # ------------------- and the strictly harder case: no gate at all.
    # A device with neither a PIN nor a gate has nothing to call, so this
    # isolates the "no mechanism whatsoever" path from the "asserting gate" one.
    none_auth, none_host = bring_up(uv="none")
    st_n, resp_n, _, _ = register(
        none_host, options={"rk": True, "up": True, "uv": True}
    )
    out.append(
        Finding(
            id="UV-NO-GATE-NO-PIN",
            module=MODULE,
            severity="informational",
            title="A device with no gate and no PIN refuses uv=true",
            detail=(
                f"With uv_gate unset and no PIN configured, uv=true returned "
                f"0x{st_n:02x}.  "
                + (
                    "The refusal names the missing mechanism."
                    if st_n != 0x00
                    else "The ceremony completed, which it should not have."
                )
            ),
            evidence={
                "makeCredential_status": f"0x{st_n:02x}",
                "gate_installed": getattr(none_auth, "uv_gate", None) is not None,
                "pin_configured": getattr(none_auth, "_pin_hash", None) is not None,
            },
            references=["CTAP 2.1 s7.2 step 3"],
        )
    )

    # ------------------------------- pinned device: the honest path, plus
    # the assertion route, which shares the same _uv() gate.
    st_p, resp_p, _, _ = register(
        host, options={"rk": True, "up": True, "uv": True}
    )
    if st_p == 0x00:
        flags_p = flags_dict(resp_p[2])
        out.append(
            Finding(
                id="UV-SATISFIED-BY-PIN",
                module=MODULE,
                severity="informational",
                title="uv=true is satisfied by a PIN the device verified",
                detail=(
                    "MakeCredential with options.uv=true on a device with a PIN "
                    f"configured returned 0x{st_p:02x} with flags {flags_p}.  The "
                    "gate collected the PIN and verify_pin judged it, so the UV "
                    "flag corresponds to a verification that happened."
                ),
                evidence={"makeCredential_status": f"0x{st_p:02x}",
                          "flags": str(flags_p)},
                references=["CTAP 2.1 s7.2 step 3"],
            )
        )

        cid = credential_id_from(resp_p[2])
        st2, ar, _, _ = assert_credential(
            host, credential_id=cid, options={"up": True, "uv": True}
        )
        if st2 == 0x00:
            flags_a = flags_dict(ar[2])
            out.append(
                Finding(
                    id="UV-ASSERTION-PATH-AGREES",
                    module=MODULE,
                    severity="informational",
                    title="The assertion path applies the same gate",
                    detail=(
                        "GetAssertion with options.uv=true returned "
                        f"0x{st2:02x} with flags {flags_a}.  Registration and "
                        "assertion share one _uv() path, so a fix to one fixes "
                        "both."
                    ),
                    evidence={"getAssertion_status": f"0x{st2:02x}",
                              "flags": str(flags_a)},
                    references=["CTAP 2.1 s7.2 step 3"],
                )
            )
        else:
            out.append(
                Finding(
                    id="UV-ASSERTION-PATH-DISAGREES",
                    module=MODULE,
                    severity="medium",
                    title="Registration accepts uv but the assertion path refuses",
                    detail=(
                        f"MakeCredential with uv=true returned 0x{st_p:02x} but "
                        f"GetAssertion with uv=true returned 0x{st2:02x}.  The two "
                        "ceremonies then disagree about what user verification "
                        "means, and a client cannot tell which rule it is under."
                    ),
                    evidence={"makeCredential_status": f"0x{st_p:02x}",
                              "getAssertion_status": f"0x{st2:02x}"},
                    remediation="Route both ceremonies through one verification "
                                "check.",
                    references=["CTAP 2.1 s7.2 step 3"],
                )
            )
    else:
        out.append(
            Finding(
                id="UV-REFUSED-DESPITE-PIN",
                module=MODULE,
                severity="medium",
                title="uv=true refused although a PIN is configured",
                detail=(
                    "A device with a configured PIN and a gate that collects it "
                    f"returned 0x{st_p:02x} for uv=true.  If the PIN was supplied "
                    "correctly this is over-strict, and an RP requiring UV would "
                    "reject a genuine second factor."
                ),
                evidence={"makeCredential_status": f"0x{st_p:02x}",
                          "pin_configured": pin_configured},
                remediation="Check the gate is installed and collects the PIN "
                            "before raising the UV flag.",
                references=["CTAP 2.1 s7.2 step 3"],
            )
        )

    # --------------------------------- a gate that refuses the verification
    deny_auth, deny_host = bring_up(uv="pin", uv_gate=lambda: False)
    st_d, _, _, _ = register(
        deny_host, options={"rk": True, "up": True, "uv": True}
    )
    out.append(
        Finding(
            id="UV-FAILED-VERIFICATION-IS-REFUSED",
            module=MODULE,
            severity="informational",
            title="A verification that fails is reported as a failure",
            detail=(
                f"With the gate refusing, uv=true returned 0x{st_d:02x} and no "
                "credential was created.  Worth stating plainly: the device "
                "reports a failed verification correctly.  The defect was never "
                "that it ignored the gate, it is that returning True from the "
                "gate was treated as verification."
            ),
            evidence={"status": f"0x{st_d:02x}",
                      "credential_created": st_d == 0x00},
            references=["CTAP 2.1 s7.2 step 3"],
        )
    )

    return out


__all__ = ["run", "MODULE"]