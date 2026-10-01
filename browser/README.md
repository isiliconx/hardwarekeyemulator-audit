# Test your site with a virtual USB security key

Chrome 148 is driven over the DevTools protocol with a virtual authenticator that
reports `transport=usb` and `defaultBackupEligibility=False`. A WebAuthn
registration on your site therefore sees a hardware key, not a passkey.

Measured in a real `navigator.credentials.create()` ceremony:

```
flags       0x45    UP=SET  UV=SET  BE=clear  BS=clear  AT=SET
aaguid      01020304050607080102030405060708
transports  ['usb']
VERDICT  security key -- not backup eligible, not syncable
```

## Do this

```bash
cd /home/ubuntu/.hermes/web/hardwarekeyemulator-audit
./browser/start.sh
```

A Chrome window opens on `DISPLAY=:1` showing the FIDO2 Lab RP.

To test your own site, give the launcher the URL:

```bash
./browser/start.sh https://your.site
```

Then register from the page, and confirm what got registered:

```bash
python3 browser/drive.py --site https://your.site
```

`drive.py` re-attaches the key on its own DevTools session before measuring, so
it works standalone. It runs a fresh ceremony and prints the flags.

## Why a copy of your profile

`~/.config/google-chrome` is the one path on this host where Chrome will not
bind a DevTools port. Same binary, same flags, same display, same filesystem:

| profile path | DevTools port |
|---|---|
| `~/.config/probe-chrome` | binds |
| `~/probe-chrome` | binds |
| `/tmp/x1/x2/x3/prof` | binds |
| a full copy of your profile, in `/tmp` | binds |
| `~/.config/google-chrome` | **does not bind** |

Not the contents — a wiped empty directory there also fails. Not the singleton
files — clearing them changes nothing. The launcher uses
`/home/ubuntu/.hermes/cache/scratch/chrome-work`, a copy of your profile, and
your real profile is never written to. Close this browser and reopen Chrome as
usual to get your normal session back.

## RP ID rules

WebAuthn binds a credential to the RP ID. Your site must be served over HTTPS
and the RP ID must be your domain or a registrable suffix of it:

| you test | RP ID your site must send |
|---|---|
| `https://example.com` | `example.com` or `com` |
| `https://app.example.com` | `app.example.com`, `example.com` or `com` |

The launcher treats your origin as secure via
`--unsafely-treat-insecure-origin-as-secure`, so a self-signed or internal
certificate will load. Your real browser will still want a valid certificate.

## Verify it is a security key, not a passkey

Look at the two bits:

- `BE` (backup eligible, `0x08`) clear and `BS` (backup state, `0x10`) clear —
  not syncable, so the browser offers it as a security key.
- `BE` and `BS` set — syncable, offered as a passkey.

`drive.py` prints both and gives the verdict.

Two earlier readings in this repository said `BS` was set and reported a passkey.
Both were wrong: `attestationObject` is a CBOR map, not a text-prefixed blob, so
a fixed offset landed inside the COSE key and reported garbage. `measure.js`
decodes the map and refuses to print flags unless `authData[0:32]` equals
`SHA-256(rpId)`.

## The kernel HID route

`src/uhid_ctap.py` exposes the project's own `ctap2_core.py` as a real HID
device on the FIDO usage page, which any browser sees natively with no DevTools
involved. It needs the UHID driver:

```bash
sudo modprobe uhid
PYTHONPATH=src python3 src/uhid_ctap.py --rp-id your.site
```

Unavailable here: `/dev/uhid` returns `ENODEV`, `kernel.modules_disabled=1`,
and there is no `uhid.ko` for kernel 6.12.94. The CDP route above is the one
that works on this machine.

## Limits

The CDP authenticator is Chromium's own virtual device. It behaves as a USB
security key and the flags are correct, but it is not a kernel HID device. A
registration made against the lab RP is stored in the copied profile; it does not
carry back to your real one.
