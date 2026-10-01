# Findings

Target: `isiliconx/hardwarekeyemulator` at commit `0fac0f6`. 4,966 lines in `src/`,
5,799 including `tests/`.

Every result below was produced by a run on this tree. Reproduce with:

```
./build.sh test
.venv/bin/python -m tooling.run_all
```

Totals: **2 critical, 3 high, 4 medium, 9 informational**, no module errors.

---

## critical

### UV-ASSERTED-WITHOUT-VERIFICATION

**Module** `vuln/uv_bypass` · **PoC** `exploit/uv_forge.py`

A MakeCredential with `options.uv=true` completes and `authenticatorData` carries
UV(0x04) — with no PIN configured, no `pinUvAuthParam` in the request, and no
bioenrollment.

```
GetInfo options        {'rk': True, 'up': True, 'uv': True}
clientPin advertised   None
pinUvAuthToken         None
PIN configured         False

--- registration, options.uv = true ---
  status    0x00
  flags     {'raw': '0x45', 'UP': True, 'UV': True, 'BE': False, 'BS': False, 'AT': True}

--- assertion, options.uv = true, no PIN supplied ---
  status    0x00
  flags     {'raw': '0x05', 'UP': True, 'UV': True, 'BE': False, 'BS': False, 'AT': False}
  counter   1
  signature 70 bytes over authData || clientDataHash
```

The mechanism is `Ctap2Authenticator._uv()`, which calls an injected `uv_gate`
callable and nothing else:

```python
def _uv(self) -> None:
    """Perform explicitly configured internal user verification."""
    if self.uv_gate is None:
        raise CtapError(0x2C, "internal user verification is not configured")
    ...
    if not self.uv_gate():
        ...
```

CTAP 2.1 s7.2 step 3 requires `CTAP2_ERR_UV_INVALID` when `uv=true` is requested
and neither `clientPin` nor bioenrollment is available. "User verified" here means
"the embedding process returned True from a lambda".

Control: with `uv_gate` returning False the ceremony fails with `0x3C` and creates
no credential, so the gate is honoured on the failure path. The defect is the
success path.

**Impact** an RP recording UV has recorded a second factor that never happened.
Nothing to steal, nothing to phish, no prompt.

**Fix** refuse `uv=true` without a valid `pinUvAuthParam` or bioenrollment; or stop
advertising `uv` in GetInfo.

**Refs** CTAP 2.1 s7.2 step 3 · WebAuthn L2 s6.1.1

### UV-ASSERTED-WITHOUT-VERIFICATION-ASSERTION

**Module** `vuln/uv_bypass`

Same defect on the assertion path: `GetAssertion` with `options.uv=true` returns
`0x00` with UV set and no PIN in the request. `flags 0x05, counter 1`. Not an
artefact of registration — fix the shared `_uv()`.

---

## high

### FIDO-AAGUID-EXTENSION-DOUBLE-WRAPPED

**Module** `vuln/attestation` · **PoC** `exploit/aaguid_mismatch.py`

`id-fido-gen-ce-aaguid` (1.3.6.1.4.1.45724.1.1.4) defines `extnValue` as
`OCTET STRING (SIZE (16))`. The device writes `_der_octet_string(aaguid)` into a
cryptography `UnrecognizedExtension`, which already wraps `extnValue`:

```
aaguid field    16 bytes  b93fd961f2e6462fb12282002247de21
ext.value.value 18 bytes  0410b93fd961f2e6462fb12282002247de21

verbatim match         False
after unwrapping 0x0410  True
```

The AAGUID above is the real YubiKey 5 one. Choosing it changes nothing: the
extension does not parse either way.

The value is correct underneath a redundant wrapper, which is why the project's own
selftest passes — it asserts `leaf_has_fido_extension is True` and never checks that
the value is 16 bytes.

**Fix**

```python
x.UnrecognizedExtension(x.oid.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4"), aaguid)
```

**Refs** id-fido-gen-ce-aaguid · RFC 4043 · WebAuthn L2 s8.2

### GETINFO-UV-WITHOUT-A-UV-MECHANISM

**Module** `vuln/device_conformance`

GetInfo reports `{'rk': True, 'up': True, 'uv': True}` with `clientPin` absent and
`pinUvAuthToken` absent. No client has any way to obtain a verified assertion, and
advertising `uv` invites precisely the request the device then answers without
verifying. Same root cause as the critical above, seen from the capability
declaration.

### POLICY-THREE-OF-FOUR-SHAPES-ACCEPT-FORGED-SIG

**Module** `vuln/policy_shapes`

One credential, one browser, `fmt=packed`, `flags 0x45`. Only `sig_ok` differs:

```
  A_NO_GATE          sig_ok=True  -> HARDWARE
  B_SYNCABILITY      sig_ok=True  -> HARDWARE
  C_ATTEST_PRESENT   sig_ok=True  -> HARDWARE
  D_MDS_TRUSTED      sig_ok=True  -> passkey
  A_NO_GATE          sig_ok=False -> HARDWARE
  B_SYNCABILITY      sig_ok=False -> HARDWARE
  C_ATTEST_PRESENT   sig_ok=False -> HARDWARE
  D_MDS_TRUSTED      sig_ok=False -> passkey
```

Accepted with a forged signature: `A_NO_GATE`, `B_SYNCABILITY`, `C_ATTEST_PRESENT`.
Rejected: `D_MDS_TRUSTED` only.

Shape C is the one that matters — it checks that an `attStmt` is present and never
inspects the signature, which is what `attestation: "direct"` becomes in a verifier
written that way.

This is a finding about RP implementation, not a defect in the audited device, and
`policy_lab.py` exists to demonstrate it. Recorded here because the audit's job is
to measure it, not because the project is wrong to claim it.

Also measured, and worth stating for anyone hardening an RP: **one ECDSA
verification under `x5c[0]`'s key catches every forged signature and tampering case
that shapes A and C miss.** No network dependency, computable from material already
in the response. It proves nothing about hardware origin — that is the MDS's job — so
it is complementary to shape D, not a replacement for it.

---

## medium

### RP-ATTESTATION-VERIFIED-FLAG-FOLLOWS-POLICY

`rp_verify.verify_registration` returns `attestation_verified` computed as
`fmt != "none" and policy["require_attestation"]`. With the gate off it reports
`False` on a certificate whose signature was verified moments earlier; a misconfigured
policy would report `True` for any fmt other than `none`. Observed
`attestation_verified=False` with `require_attestation=False`, `signature_actually_verified=True`.

This is the field an audit log or an assurance-level decision reads. It should reflect
what the function just proved.

### RP-IDENTICAL-REPLAY-ACCEPTED

```
  identical replay   ACCEPTED
  fresh challenge    refused: assertion signature failed verification
  cross origin       refused: assertion signature failed verification
```

The in-band replays are refused because the signature covers
`authData || clientDataHash`. A verbatim replay carries no such change, so nothing in
the assertion distinguishes it — that is what a stateless signature check is, and it
is not a verifier bug.

It becomes a login-reuse bug the moment an RP stores no state, and this verifier keeps
none: no spent-challenge cache, and the counter check accepts an equal value. An RP
built on this needs a challenge cache or strictly advancing per-credential counters.

### ANALYSER-MISSES-MALFORMED-EXTENSION

`analyze_attestation.inspect()` reports `leaf_has_fido_extension=True` for a
certificate whose extension value is 18 bytes of nested DER. It checks presence, never
that the value is a well-formed 16-byte aaguid — so it cannot distinguish a conformant
leaf from this one, in the component whose whole job is telling an RP what it can reject.

Its own verdict is otherwise correct: `1 signal(s) let an RP reject this in one
comparison: attestation chain terminates at an untrusted self-made CA`.

### GETINFO-MISSING-CTAP21-KEYS

```
keys present [1, 2, 3, 4, 5, 7, 8, 10]
versions    ['FIDO_2_0']
missing     0x06 pinUvAuthProtocols (required in 2.1), 0x0a algorithms (required in 2.1)
```

A client reading key 6 gets a KeyError or a silent default. Defensible under FIDO 2.0
— except the device also reports `uv`, which only exists in 2.1.

---

## informational — checks that passed

Recorded because a conformance audit that lists only failures is indistinguishable
from one that found nothing.

| finding | result |
|---|---|
| `DEVICE-CREDENTIAL-ISOLATION` | A credential at `site-a.example` refused at `site-b.example`, both by credential ID and with an empty allowList, both `0x2E`. The property that makes `rpIdHash` load-bearing. |
| `DEVICE-SIGN-COUNTER` | Registration 0, then `[1, 2, 3, 4, 5]` — strictly increasing, so an RP can detect a clone. |
| `DEVICE-EXCLUDE-LIST` | Re-registering with the existing credential in `excludeList` refused, so an account cannot end up with two credentials. |
| `RP-REFUSES-FORGED-ATTESTATION` | A signature from a non-leaf key refused: `attestation signature does not verify against the attestation certificate key`. The verifier loads `x5c[0]` and verifies against the leaf — the rule implementations most often get wrong by verifying against the credential key. |
| `UV-GATE-FALSE-IS-REFUSED` | `uv_gate` returning False gives `0x3C`, no credential. The failure path is correct. |
| `ATTESTATION-TERMINATES-AT-LOCAL-CA` | Chain well-formed, signature real, 2-cert x5c, terminates at a CA the process generated. Proves the device holds the leaf key and nothing about hardware origin. |
| `POLICY-CHAIN-ONLY-GATE-IS-AVAILABLE` | The leaf-key ECDSA check is computable and satisfied on this certificate. |
| `POLICY-SYNCABILITY-IS-CLIENT-CONTROLLED` | BE(0x08) clear → shape B calls it a hardware key. The flag is authentic (inside the signature) but binds nothing to the device's nature — a Chromium sorting behaviour mistaken for an authenticity signal. |
| `UV-CAPABILITY-ADVERTISED` | Baseline capability record. |

---

## What the audit did not find

No way to produce vendor-signed attestation. Writing a vendor AAGUID into the field
yields a label, not a trust path:

1. **Chain** — vendor leaves are issued by that vendor's CA. Writing a YubiKey AAGUID
   onto your own leaf does not produce a leaf issued by Yubico's CA.
2. **MDS** — RPs do not trust a list of AAGUID values. They fetch the signed FIDO
   Metadata Service blob and pull the vendor root from the same entry. Your AAGUID is
   not in it, because the blob is signed by FIDO Alliance metadata roots.
3. **Extension** — real vendor leaves carry `id-fido-gen-ce-aaguid`, which
   cryptographically binds leaf identity to the aaguid field. Here it is malformed,
   which is a defect and not an advantage.

The general form: you can write any value into any field. What you cannot do is
produce a signature that chains to something the verifier already trusts. Identity in
this protocol is a chain, not a claim.

Also not exercised: `uhid_ctap.py`, because `/dev/uhid` returns `ENODEV` on this host
(no driver in `/proc/misc`, no `/lib/modules/$(uname -r)`). Their `selftest_uhid.py`
confirms this honestly.

---

## Corrections made to this audit mid-run

Three findings were wrong on first execution and were fixed at the source rather
than in the prose:

1. **`register(options={7: {...}})`** — the helper spread `options` as a top-level
   request key instead of CTAP key 7, so `uv=true` silently never reached the device
   and the critical finding did not fire. A direct `make_credential` call set UV
   correctly. Fixed in `tooling/harness.py`, and the signature now names `options`
   and `**extra_params` separately so the two cannot be confused again.

2. **`UV-GATE-FALSE-STILL-RETURNS-OK`** — written on the assumption that a falsifying
   gate still returned `0x00` with UV clear. The run shows `0x3C` and no credential:
   the refusal path is correct. Rewritten as an informational finding.

3. **`enum/` directory name** — a subpackage called `enum` shadows the standard
   library module and breaks `import json` and everything downstream. Renamed to
   `discovery/`.

Two PoC text claims were also contradicted by their own runs and corrected: the
`wrong_client_data_hash` style reasoning about signature coverage, and the claim that
a malformed FIDO extension would let a credential pass vendor checks.
