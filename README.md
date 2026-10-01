# hardwarekeyemulator audit

An audit of [isiliconx/hardwarekeyemulator](https://github.com/isiliconx/hardwarekeyemulator)
at commit `0fac0f6` — a software CTAP2 authenticator with three transports and a
relying-party verifier. 4,966 lines in `src/`, 5,799 including `tests/`.

The project is well built and its own selftests pass. This audit finds five
defects it can fix, all of which their suite passes over because the tests assert
presence where they needed to assert correctness, plus two it deliberately leaves
open.

```
./build.sh                            venv, requirements, fetch the target, its selftests
./build.sh test                       the audit, the PoCs, upstream's suite on a patched copy, the differential
./build.sh remediate [checkout]       apply the remediation in place to a checkout
python3 -m tooling.run_all            the report
python3 exploit/uv_forge.py           PoC: UV with no verification
python3 exploit/aaguid_mismatch.py    PoC: the AAGUID extension
```

## Result, both trees

| tree | critical | high | medium | informational | module errors |
|---|---|---|---|---|---|
| pristine, as published | **1** | **3** | 3 | 13 | 0 |
| patched, after `exploit/*.py` | 0 | 1 | 1 | 17 | 0 |

`tests/test_differential.py`: **24 passed, 0 failed**. Upstream's own suite on the
patched tree: `selftest_hid` 36, `selftest_e2e` 21, `selftest_uhid` 35,
`pytest tests` 48 — zero failures.

## Findings

| severity | finding | status |
|---|---|---|
| critical | `UV-ASSERTED-WITHOUT-VERIFICATION` — the device sets UV(0x04) with no PIN, no `pinUvAuthParam`, and no verification of any kind | fixed |
| high | `FIDO-AAGUID-EXTENSION-DOUBLE-WRAPPED` — `id-fido-gen-ce-aaguid` carries 18 bytes of nested DER, not 16 | fixed |
| high | `GETINFO-UV-WITHOUT-A-UV-MECHANISM` — `uv` advertised with no `clientPin` | fixed |
| high | `POLICY-THREE-OF-FOUR-SHAPES-ACCEPT-FORGED-SIG` — three of four RP enforcement shapes call a non-verifying attestation a hardware key | OPEN-1 |
| medium | `RP-ATTESTATION-VERIFIED-FLAG-FOLLOWS-POLICY` — the field reflects policy, not the verification performed | fixed |
| medium | `ANALYSER-MISSES-MALFORMED-EXTENSION` — `analyze_attestation` reports the malformed value as a valid extension | fixed |
| medium | `GETINFO-MISSING-CTAP21-KEYS` — keys 6 and 0x0A absent while `FIDO_2_0` is declared | OPEN-2 |

Full detail, evidence and reasoning in [findings.md](findings.md).

`UV-ASSERTED-WITHOUT-VERIFICATION-ASSERTION` from the first pass was merged into
the critical: registration and assertion share one `_uv()` path, so it is one
defect with two entry points, and the detector now reports the agreement as a
separate informational.

## The defects

### 1. UV with no verification — critical, fixed

`Ctap2Authenticator._uv()` calls an injected `uv_gate` callable and nothing else.
It never examines a PIN, a `pinUvAuthParam`, or a bioenrollment, because none
exists:

```
GetInfo options        {'rk': True, 'up': True, 'uv': True}
clientPin advertised   absent
PIN configured         False

--- MakeCredential, options.uv = true, no PIN ---
  status    0x00
  flags     {'raw': '0x45', 'UP': True, 'UV': True}

--- GetAssertion, options.uv = true, no PIN ---
  status    0x00
  flags     {'raw': '0x05', 'UP': True, 'UV': True}
```

CTAP 2.1 s7.2 step 3 requires `CTAP2_ERR_UV_INVALID`. Whoever holds the
authenticator object holds the gate, so "user verified" reduces to "the embedding
application returned True from a lambda". An RP that reads UV as a second factor
has recorded a second factor that never happened.

**Fixed** by refusing `uv=true` unless a PIN is configured, and requiring the
gate to authorise a correctly supplied one. After the patch the same probe
returns `0x2f` with no PIN, succeeds with the right PIN, and returns `0x3c` with
the wrong one while decrementing the retry counter.

Note that this required changing their tests. `test_internal_uv_sets_flag_only_after_gate_succeeds`
asserted `uv_gate=lambda: True` yields the UV flag — it was asserting the defect.
It now configures a PIN, so it still exercises an internal-verification path, it
just does so through a mechanism that verifies something.

### 2. The AAGUID extension is double-wrapped — high, fixed

`id-fido-gen-ce-aaguid` is an OCTET STRING holding 16 raw bytes. The device
passed an already-wrapped value into `x509.UnrecognizedExtension`, which wraps
`extnValue` itself:

```
aaguid field     16 bytes  b93fd961f2e6462fb12282002247de21
ext.value.value  18 bytes  0410b93fd961f2e6462fb12282002247de21
                                        ^^^^ wrapped twice
```

Demonstrated with a real YubiKey 5 AAGUID, deliberately: it does not parse
either way. Their selftest asserts the extension is *present* and never that the
value is 16 bytes. Neither does `analyze_attestation.py`, the component whose
job is telling an RP what it can reject.

**Fixed** on both sides — the device wraps once, and `rp_verify.py` compares
against the bare bytes. Both had to move together: the old comparison only ever
matched the 18-byte form, so it would have rejected every *correct* leaf.

## Open findings

**OPEN-1** `POLICY-THREE-OF-FOUR-SHAPES-ACCEPT-FORGED-SIG` is a property of the
RP, not the authenticator, and `policy_lab.py` exists to show the difference. The
shapes are a teaching tool. Left as it is.

The practical note for anyone hardening an RP: shape D is not the only gate that
works. A single ECDSA verification under `x5c[0]`'s own key catches every case
shapes A and C miss, needs no network, and is computable from material already in
the response. Verified against their certificate. Stricter than shape D for a
locally-issued chain and needs no MDS fetch.

**OPEN-2** `GETINFO-MISSING-CTAP21-KEYS` — the device declares `FIDO_2_0` and
omits keys 6 and 0x0A. Defensible under 2.0, and upstream's suite asserts
`6 not in info`. An earlier version of the patch added them and broke four of
their tests; that change was reverted rather than the tests adjusted.

## Layout

```
config/target.yaml           scope, severity gate, rate and output config
recon/fetch.sh               clone or refresh the target
recon/patch_tree.sh          rebuild the patched copy from pristine, run their suite
discovery/surface.py         source, LOC, and surface inventory
vuln/uv_bypass.py            can the device assert UV it never performed
vuln/attestation.py          the attestation chain and the AAGUID extension
vuln/policy_shapes.py        the four RP enforcement shapes, with a forged signature
vuln/rp_verifier.py          their verifier: forged sig, the verified flag, replay
vuln/device_conformance.py   GetInfo, credential isolation, counter, exclude list
exploit/uv_forge.py          PoC: obtain a UV-flagged assertion with no PIN
exploit/aaguid_mismatch.py   PoC: the extension, with any AAGUID
exploit/apply_fix.py         the remediation: 5 hunks in src/
exploit/fix_tests.py         their selftests, rewritten to go through a PIN
exploit/fix_uv_sites.py      the 12 uv=true call sites that pass an asserting gate
tooling/harness.py           in-process CTAPHID loopback, ceremony helpers, Finding
tooling/run_all.py           run every module, write findings.json
tests/test_modules.py        every module runs, every PoC behaves as documented
tests/test_differential.py   baseline vs patched, in subprocesses
findings.md                  the findings, the evidence, the reasoning, the corrections
```

## How the pieces work

`tooling/harness.py` brings their authenticator up in-process over their own
`LoopbackTransport`, which frames real 64-byte CTAPHID reports — so every probe
here goes through the same framing a USB HID device would. `bring_up()` takes
the verification configuration explicitly, because the question only has meaning
against a specific one:

| mode | configuration | why |
|---|---|---|
| `uv="pin"` | PIN set, gate collects it | what an honest host embedding looks like |
| `uv="unconditional"` | no PIN, gate returns True | **upstream's own default** — the configuration under test |
| `uv="none"` | no PIN, no gate | isolates "no mechanism" from "asserting gate" |

That distinction matters: their `selftest_hid`, `selftest_e2e`,
`test_rp_security.py` and `policy_lab.build_demo_attestation` all construct the
device with `uv_gate=lambda: True` and no PIN. That is the configuration that
ships, so it is what the critical is measured against.

## Reproducing the differential

```
./build.sh test
```

fetches the target, audits the **pristine** tree, then `recon/patch_tree.sh`
deletes and re-copies the patched tree from pristine on every run — a patched
tree that accumulates edits makes a "the fix works" claim unfalsifiable —
applies all three patchers, runs upstream's suite there, and finally runs the
differential.

The differential runs each tree in a **subprocess**. An earlier version
re-imported the modules in-process, which left the first tree's `ctap2_core`
bound in `sys.modules`, so both sweeps measured the same tree and half the checks
passed vacuously. It also fails if the remediation closes something
`findings.md` says was left open, because a fix that does more than documented is
as much a defect as one that under-delivers.

## Scope

Everything runs against a local clone over a loopback transport. No third-party
service, no account, no API key, no physical token. `uhid_ctap.py` is unexercised
— `/dev/uhid` returns `ENODEV` on this host — and upstream's own selftest reports
that as INFO rather than pretending.