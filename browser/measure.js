// Measure what the browser actually records, with the parse self-checked.
//
// attestationObject is a CBOR map, so the flags byte cannot be found at a fixed
// offset -- that was the bug in three earlier readings.  Decode the map, then
// refuse to report anything unless authData's first 32 bytes equal
// SHA-256(rpId).  A wrong parse must fail, not print a plausible table.
(async () => {
  const hex = (u8) => [...u8].map(x => x.toString(16).padStart(2, '0')).join('');

  function readCbor(b, p) {
    const ib = b[p++];
    const major = ib >> 5, ai = ib & 0x1f;
    let len;
    if (ai < 24) len = ai;
    else if (ai === 24) len = b[p++];
    else if (ai === 25) { len = (b[p] << 8) | b[p + 1]; p += 2; }
    else if (ai === 26) {
      len = (b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3];
      p += 4;
    } else throw new Error('unsupported additional info ' + ai);

    if (major === 0) {
      let v = ai;
      if (ai === 24) v = b[p - 1];
      else if (ai === 25) v = ((b[p - 2] << 8) | b[p - 1]);
      else if (ai === 26) v = ((b[p - 4] << 24) | (b[p - 3] << 16) |
                                (b[p - 2] << 8) | b[p - 1]);
      return [v, p];
    }
    if (major === 1) {
      let v = ai;
      if (ai === 24) v = b[p - 1];
      else if (ai === 25) v = ((b[p - 2] << 8) | b[p - 1]);
      else if (ai === 26) v = ((b[p - 4] << 24) | (b[p - 3] << 16) |
                                (b[p - 2] << 8) | b[p - 1]);
      return [-1 - v, p];
    }
    if (major === 2) return [b.slice(p, p + len), p + len];
    if (major === 3) return [new TextDecoder().decode(b.slice(p, p + len)), p + len];
    if (major === 4) {
      const o = [];
      for (let i = 0; i < len; i++) { const [v, q] = readCbor(b, p); o.push(v); p = q; }
      return [o, p];
    }
    if (major === 5) {
      const o = {};
      for (let i = 0; i < len; i++) {
        const [k, p1] = readCbor(b, p);
        const [v, p2] = readCbor(b, p1);
        o[k] = v; p = p2;
      }
      return [o, p];
    }
    throw new Error('unsupported major type ' + major);
  }

  if (!window.isSecureContext)
    return { ok: false, error: 'not a secure context: ' + location.href };
  if (!navigator.credentials)
    return { ok: false, error: 'navigator.credentials missing -- page did not load' };

  const enc = new TextEncoder();
  const shaHex = async (s) => hex(new Uint8Array(
    await crypto.subtle.digest('SHA-256', enc.encode(s))));
  const rpId = location.hostname;

  const c = new Uint8Array(32);
  crypto.getRandomValues(c);

  let p;
  try {
    p = await navigator.credentials.create({ publicKey: {
      challenge: c,
      rp: { id: rpId, name: document.title || rpId },
      user: { id: crypto.getRandomValues(new Uint8Array(16)),
              name: 'probe@' + rpId, displayName: 'Probe' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 },
                         { type: 'public-key', alg: -257 }],
      authenticatorSelection: { residentKey: 'preferred', requireResidentKey: true,
                                userVerification: 'preferred' },
      timeout: 25000, attestation: 'direct' } });
  } catch (e) { return { ok: false, error: String(e) }; }

  let obj, ad;
  try {
    const ab = new Uint8Array(p.response.attestationObject);
    [obj] = readCbor(ab, 0);
    ad = new Uint8Array(obj.authData);
  } catch (e) { return { ok: false, error: 'CBOR: ' + String(e) }; }

  const got = hex(ad.slice(0, 32));
  const want = await shaHex(rpId);
  if (got !== want)
    return { ok: false,
             error: 'PARSE INVALID: rpIdHash ' + got +
                     ' != sha256(' + rpId + ') ' + want,
             got: got, want: want };

  const f = ad[32];
  return {
    ok: true,
    site: location.origin,
    rpId: rpId,
    fmt: obj.fmt,
    adLen: ad.length,
    rpIdHashVerified: true,
    flags: '0x' + f.toString(16).padStart(2, '0'),
    UP: (f & 0x01) ? 'SET' : 'clear',
    UV: (f & 0x04) ? 'SET' : 'clear',
    BE: (f & 0x08) ? 'SET' : 'clear',
    BS: (f & 0x10) ? 'SET' : 'clear',
    AT: (f & 0x40) ? 'SET' : 'clear',
    aaguid: hex(ad.slice(37, 53)),
    signCount: (ad[33] << 24) | (ad[34] << 16) | (ad[35] << 8) | ad[36],
    attachment: p.authenticatorAttachment,
    transports: p.response.getTransports ? p.response.getTransports() : null,
    attStmtKeys: Object.keys(obj.attStmt || {})
  };
})()
