/**
 * Byte-level decoders for the playground.
 *
 * ─── Why annotate rather than pretty-print ────────────────────────────────
 * A JSON dump of a parsed structure tells you what a library decided the bytes
 * meant. It does not tell you where a field sits, how wide it is, or why it is
 * there — and those are exactly the things someone reading a spec for the first
 * time is trying to line up.
 *
 * So each decoder returns a map: offset, length, the raw hex, the value, and a
 * sentence about why the field exists. Rendered as a table it reads like the
 * diagram in the specification, with real bytes in it.
 *
 * The parsing itself is done by the shipped parsers — `parseAuthenticatorData`,
 * `decodeCbor` — rather than reimplemented here. A decoder that disagreed with
 * the verifier would be worse than no decoder, because it would show a visitor
 * something the library never actually saw.
 * ──────────────────────────────────────────────────────────────────────────
 */

import { decodeCbor, decodeCborPrefix, parseAuthenticatorData } from '@ninshorg/webauthn';

/** One labelled span of bytes. */
export interface Field {
  readonly offset: number;
  readonly length: number;
  readonly name: string;
  /** Raw bytes, hex, truncated when long. */
  readonly hex: string;
  /** What those bytes mean. */
  readonly value: string;
  /** Why the field is there at all. */
  readonly note: string;
  /** Nesting level, for indentation in the table. */
  readonly depth?: number;
  /**
   * Report the size without a byte range.
   *
   * Entries of a CBOR map have a size but no meaningful offset into anything
   * the reader can see, and printing `0 … 70` for each of them would invite
   * exactly the wrong reading.
   */
  readonly sizeOnly?: boolean;
}

export interface Decoded {
  readonly summary: string;
  readonly totalBytes: number;
  readonly fields: readonly Field[];
}

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

/** Hex, shortened in the middle so a long field stays readable in a table. */
function shortHex(bytes: Uint8Array, max = 24): string {
  if (bytes.length <= max) return hex(bytes);
  return `${hex(bytes.subarray(0, max / 2))}…${hex(bytes.subarray(bytes.length - 4))}`;
}

// ─── WebAuthn authenticator data ───────────────────────────────────────────

/** The eight flag bits, and what each one asserts. */
const FLAG_BITS: readonly { bit: number; name: string; note: string }[] = [
  { bit: 0, name: 'UP — user present', note: 'Someone touched the authenticator. Mandatory in both ceremonies; there is no option to disable it because the spec offers none.' },
  { bit: 1, name: 'RFU1', note: 'Reserved. Must be zero.' },
  { bit: 2, name: 'UV — user verified', note: 'A PIN or a biometric was checked *on the authenticator*. The biometric never leaves the device — this single bit is all the server learns about it.' },
  { bit: 3, name: 'BE — backup eligible', note: 'The credential may be synced to a cloud account. A multi-device passkey.' },
  { bit: 4, name: 'BS — backed up', note: 'It currently is. Setting this without BE is a contradiction the spec forbids, and Ninsho refuses it.' },
  { bit: 5, name: 'RFU2', note: 'Reserved. Must be zero.' },
  { bit: 6, name: 'AT — attested credential data', note: 'A new credential follows. Present at registration; an assertion carrying it is refused, since a sign-in must not smuggle in a credential.' },
  { bit: 7, name: 'ED — extension data', note: 'A CBOR extension map follows.' },
];

/** COSE key labels, so the key map reads as something other than integers. */
const COSE_LABELS: Record<string, string> = {
  '1': 'kty — key type (2 = EC2, 3 = RSA, 1 = OKP)',
  '3': 'alg — algorithm (-7 = ES256, -8 = EdDSA, -257 = RS256)',
  '-1': 'crv — curve (EC2/OKP) · n — modulus (RSA)',
  '-2': 'x — coordinate (EC2/OKP) · e — exponent (RSA)',
  '-3': 'y — coordinate (EC2)',
};

/**
 * Annotates authenticator data, WebAuthn §6.1.
 *
 * The layout is packed with no framing, which is what makes a byte map useful:
 * the only thing separating `signCount` from an AAGUID is knowing where one
 * ends.
 */
export function decodeAuthenticatorData(bytes: Uint8Array): Decoded {
  // Parsed by the shipped parser first, so anything this annotates is
  // something the verifier also accepted.
  const parsed = parseAuthenticatorData(bytes);
  const fields: Field[] = [];

  fields.push({
    offset: 0,
    length: 32,
    name: 'rpIdHash',
    hex: shortHex(bytes.subarray(0, 32)),
    value: 'SHA-256 of the relying party id',
    note: 'What stops a credential registered for one site being used at another. The authenticator hashes the RP ID it was invoked with, and the signature covers this hash.',
  });

  const flagByte = bytes[32] as number;
  fields.push({
    offset: 32,
    length: 1,
    name: 'flags',
    hex: flagByte.toString(16).padStart(2, '0'),
    value: `0b${flagByte.toString(2).padStart(8, '0')}`,
    note: 'Eight assertions in one byte. Each bit is broken out below.',
  });

  for (const flag of FLAG_BITS) {
    const set = (flagByte & (1 << flag.bit)) !== 0;
    fields.push({
      offset: 32,
      length: 0,
      name: `bit ${flag.bit} · ${flag.name}`,
      hex: set ? '1' : '0',
      value: set ? 'set' : 'clear',
      note: flag.note,
      depth: 1,
    });
  }

  fields.push({
    offset: 33,
    length: 4,
    name: 'signCount',
    hex: hex(bytes.subarray(33, 37)),
    value: String(parsed.signCount),
    note: 'Big-endian. A counter that fails to advance is the spec’s clone signal (§6.1.1) — Ninsho rejects it by default. Most passkeys report 0 forever, which is not a clone and is never rejected.',
  });

  const attested = parsed.attestedCredentialData;
  if (attested) {
    let offset = 37;

    fields.push({
      offset,
      length: 16,
      name: 'aaguid',
      hex: hex(attested.aaguid),
      value: 'authenticator model id',
      note: 'Identifies the hardware model. Self-asserted unless a trusted attestation chain vouches for it — which is why Ninsho reports aaguidVerified separately.',
    });
    offset += 16;

    fields.push({
      offset,
      length: 2,
      name: 'credentialIdLength',
      hex: hex(bytes.subarray(offset, offset + 2)),
      value: String(attested.credentialId.length),
      note: 'Big-endian, and an attacker-controlled number that drives a read. Checked against the spec’s 1023-byte ceiling *and* against what is actually present, before anything is allocated.',
    });
    offset += 2;

    fields.push({
      offset,
      length: attested.credentialId.length,
      name: 'credentialId',
      hex: shortHex(attested.credentialId),
      value: `${attested.credentialId.length} bytes`,
      note: 'The lookup key. Stored by the relying party and presented on every later sign-in.',
    });
    offset += attested.credentialId.length;

    const keyBytes = attested.credentialPublicKey;
    fields.push({
      offset,
      length: keyBytes.length,
      name: 'credentialPublicKey',
      hex: shortHex(keyBytes),
      value: `COSE key, ${keyBytes.length} bytes of CBOR`,
      note: 'No length prefix — the only way to find where it ends is to decode it, which is why decodeCborPrefix exists. Store these bytes verbatim; they are re-imported on every authentication.',
    });

    // Break the COSE map out, so the key stops being an opaque blob.
    try {
      const key = decodeCbor(keyBytes);
      if (key instanceof Map) {
        for (const [label, value] of key) {
          fields.push({
            offset,
            length: 0,
            name: `label ${String(label)}`,
            hex: value instanceof Uint8Array ? shortHex(value, 16) : '—',
            value:
              value instanceof Uint8Array
                ? `${value.length} bytes`
                : String(value as string | number),
            note: COSE_LABELS[String(label)] ?? 'Unrecognised label — ignored rather than refused, since real authenticators occasionally add one.',
            depth: 1,
          });
        }
      }
    } catch {
      // The parser above already accepted it, so this is unreachable in
      // practice; annotation is a convenience and must never fail the decode.
    }
  }

  return {
    summary: attested
      ? 'Registration — carries a new credential'
      : 'Authentication — an assertion, no credential',
    totalBytes: bytes.length,
    fields,
  };
}

// ─── Attestation object ────────────────────────────────────────────────────

/** Annotates the CBOR wrapper an attestation arrives in. */
export function decodeAttestationObject(bytes: Uint8Array): Decoded {
  const decoded = decodeCbor(bytes);
  if (!(decoded instanceof Map)) {
    throw new Error('attestationObject is not a CBOR map');
  }

  const fmt = decoded.get('fmt');
  const authData = decoded.get('authData');
  const attStmt = decoded.get('attStmt');

  const fields: Field[] = [
    {
      offset: 0,
      length: bytes.length,
      name: 'attestationObject',
      hex: shortHex(bytes, 16),
      value: `CBOR map, ${decoded.size} entries`,
      note: 'Definite-length CBOR only. Indefinite lengths and tags are refused — they are where CBOR parsers historically grow vulnerabilities, and CTAP2 canonical CBOR forbids them anyway.',
    },
    {
      offset: 0,
      length: 0,
      name: 'fmt',
      hex: '—',
      value: String(fmt),
      note: fmt === 'none'
        ? 'No attestation conveyed — the normal case for passkeys, and what the browser substitutes when the relying party asks for `none`.'
        : 'A statement format. Ninsho verifies every format WebAuthn defines — `packed`, `apple`, `tpm`, `fido-u2f`, `android-key` and `android-safetynet` — against roots you supply, and refuses a name it does not know rather than parsing it without checking.',
      depth: 1,
    },
    {
      offset: 0,
      length: 0,
      name: 'attStmt',
      hex: '—',
      value: attStmt instanceof Map ? `${attStmt.size} entries` : String(attStmt),
      note: 'The signature and certificate chain, when there is one. For `none` it must be empty — data hiding in a field nobody reads is data nobody is checking.',
      depth: 1,
    },
  ];

  if (authData instanceof Uint8Array) {
    fields.push({
      offset: 0,
      length: authData.length,
      name: 'authData',
      hex: shortHex(authData, 16),
      value: `${authData.length} bytes`,
      note: 'The packed structure decoded in full below.',
      depth: 1,
    });
  }

  return {
    summary: `Attestation object, format "${String(fmt)}"`,
    totalBytes: bytes.length,
    fields,
  };
}

// ─── PASETO v4.public ──────────────────────────────────────────────────────

/**
 * Annotates a PASETO token.
 *
 * The point worth showing is what PASETO does *not* have: no `alg` header, so
 * there is no algorithm to confuse. The version and purpose are in the string
 * itself, and `v4.public` means Ed25519 and nothing else.
 */
export function decodePaseto(token: string): Decoded {
  const parts = token.split('.');
  const fields: Field[] = [];

  fields.push({
    offset: 0,
    length: 0,
    name: 'version',
    hex: '—',
    value: parts[0] ?? '',
    note: 'Part of the token string, not a header a caller can rewrite. This is the structural answer to JWT’s algorithm-confusion family: there is no `alg` field to set to `none`.',
  });

  fields.push({
    offset: 0,
    length: 0,
    name: 'purpose',
    hex: '—',
    value: parts[1] ?? '',
    note: '`public` means signed and readable by anyone. Never put personal data in a payload — it is authenticated, not encrypted.',
  });

  const body = parts[2] ?? '';
  const raw = new Uint8Array(Buffer.from(body, 'base64url'));
  const payload = raw.subarray(0, Math.max(0, raw.length - 64));
  const signature = raw.subarray(Math.max(0, raw.length - 64));

  fields.push({
    offset: 0,
    length: payload.length,
    name: 'payload',
    hex: shortHex(payload, 16),
    value: (() => {
      try {
        return new TextDecoder().decode(payload);
      } catch {
        return `${payload.length} bytes`;
      }
    })(),
    note: 'The claims, as JSON. Ninsho puts `auth_time` here — when the user actually authenticated, which rotation does not reset, so a step-up check has something real to read.',
  });

  fields.push({
    offset: payload.length,
    length: signature.length,
    name: 'signature',
    hex: shortHex(signature, 16),
    value: `Ed25519, ${signature.length} bytes`,
    note: 'Computed over PAE(header, payload, footer, implicit) — a length-prefixed concatenation, so a byte moved from one field to another produces different input and fails. That is what stops footer-swapping.',
  });

  if (parts[3] !== undefined) {
    const footer = Buffer.from(parts[3], 'base64url').toString('utf8');
    fields.push({
      offset: 0,
      length: 0,
      name: 'footer',
      hex: '—',
      value: footer,
      note: 'Authenticated but readable without the key. Ninsho puts the key id here so a verifier can select a key *before* verifying — and a forged kid simply selects a key the signature then fails against.',
    });
  }

  return {
    summary: `PASETO ${parts[0]}.${parts[1]} — ${raw.length} bytes decoded`,
    totalBytes: token.length,
    fields,
  };
}

// ─── DPoP proof ────────────────────────────────────────────────────────────

/** Annotates a DPoP proof JWT, RFC 9449. */
export function decodeDpopProof(proof: string): Decoded {
  const [headerPart = '', payloadPart = '', signaturePart = ''] = proof.split('.');
  const parse = (part: string): Record<string, unknown> => {
    try {
      return JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as Record<string, unknown>;
    } catch {
      return {};
    }
  };

  const header = parse(headerPart);
  const payload = parse(payloadPart);
  const fields: Field[] = [];

  const describe: Record<string, string> = {
    typ: 'Must be `dpop+jwt`. A proof accepted without this check could be any JWT the client already had.',
    alg: 'Checked against an allowlist, never a denylist — `none` and the HMAC family are refused. A denylist is wrong the moment a new algorithm is registered.',
    jwk: 'The public key, embedded. Its RFC 7638 thumbprint must equal the `cnf.jkt` the token was bound to, which is what ties this proof to that token.',
    jti: 'Single-use identifier. Remembered server-side for as long as the proof would still be accepted, so a captured proof cannot be replayed.',
    htm: 'HTTP method. Binds the proof to this request, so one captured from a GET cannot authorise a DELETE.',
    htu: 'HTTP URI. Binds it to this endpoint.',
    iat: 'Issued at. Proofs outside a narrow window are refused.',
    ath: 'SHA-256 of the access token. Ties the proof to the specific credential presented alongside it.',
  };

  for (const [key, value] of Object.entries(header)) {
    fields.push({
      offset: 0,
      length: 0,
      name: `header.${key}`,
      hex: '—',
      value: typeof value === 'object' ? JSON.stringify(value) : String(value),
      note: describe[key] ?? 'Header parameter.',
    });
  }

  for (const [key, value] of Object.entries(payload)) {
    fields.push({
      offset: 0,
      length: 0,
      name: `claim.${key}`,
      hex: '—',
      value: typeof value === 'object' ? JSON.stringify(value) : String(value),
      note: describe[key] ?? 'Claim.',
    });
  }

  fields.push({
    offset: 0,
    length: 0,
    name: 'signature',
    hex: shortHex(new Uint8Array(Buffer.from(signaturePart, 'base64url')), 16),
    value: `${signaturePart.length} chars base64url`,
    note: 'Only one textual spelling is accepted. A non-canonical base64url encoding of the same signature is refused — sixteen spellings of one signature was a real bug here, found by mutation testing.',
  });

  return {
    summary: 'DPoP proof (RFC 9449) — a fresh signature per request',
    totalBytes: proof.length,
    fields,
  };
}

/** Re-exported so the server can locate a COSE key inside a larger buffer. */
export { decodeCborPrefix };

// ─── Attestation statements ────────────────────────────────────────────────

/**
 * What each field of an attestation statement carries, per format.
 *
 * Written out rather than generated, because the interesting part of a
 * statement is not its shape but what each field is *for* — and in particular
 * which field is the one holding the whole format together.
 */
const STATEMENT_NOTES: Record<string, Record<string, string>> = {
  packed: {
    alg: 'The COSE algorithm the signature uses. The verifier takes the digest from here, never from the signature or the certificate.',
    sig: 'Signed over `authData || SHA-256(clientDataJSON)` — the ceremony itself, directly.',
    x5c: 'The certificate chain, leaf first. Verified to a root you supply; without roots it is refused, because anyone can self-sign a CA and claim any AAGUID.',
  },
  apple: {
    x5c: 'The whole format. There is no signature field: Apple mints this certificate for one ceremony and puts SHA-256(authData || clientDataHash) in an extension, so the certificate itself is the binding.',
  },
  tpm: {
    ver: 'TPM 2.0 and nothing else.',
    alg: 'The COSE algorithm of the attestation key’s signature.',
    sig: 'Signed over `certInfo` — not over the ceremony. Everything tying this to your registration runs through the two structures below.',
    certInfo:
      'A TPMS_ATTEST. `extraData` holds SHA-256(authData || clientDataHash), which is the tie to this ceremony; `attested.name` holds nameAlg || digest(pubArea), which is the tie to a particular key.',
    pubArea:
      'A TPMT_PUBLIC describing the key the TPM certified. It has to *be* the credential key — check `certInfo` without checking this and a genuine TPM signature vouches for a key nobody attested to.',
    x5c: 'The attestation identity key certificate. §8.3.1 requires an empty subject and the tcg-kp-AIKCertificate usage, and it must not be a CA.',
  },
  'fido-u2f': {
    sig: 'Signed over `0x00 || rpIdHash || clientDataHash || credentialId || (0x04 || x || y)`. The leading zero is a reserved constant, not padding — it is what stops this being replayed as a U2F authentication response.',
    x5c: 'Exactly one certificate. §8.6 permits no more: accepting a list would mean accepting whichever leaf the client picked out of certificates it supplied itself.',
  },
  'android-safetynet': {
    ver: 'The Google Play Services version that produced the response. Not consulted by the verifier.',
    response: 'A JWS Google composed and signed — not the authenticator. Its `nonce` field carries SHA-256(authData || clientDataHash), which is the only thread back to this registration, and its `ctsProfileMatch` field says whether the device passed Android’s compatibility test suite. The JWS header names its own algorithm, so only RS256 is accepted: an allowlist of exactly one leaves nothing to negotiate.',
  },
  'android-key': {
    alg: 'The COSE algorithm of the credential key, which is also the attestation key here.',
    sig: 'Signed over `authData || SHA-256(clientDataJSON)`, as `packed` is — and, on its own, saying no more than a self-signed chain could.',
    x5c: 'Where the format actually lives. Keystore writes a key description into this certificate: the challenge fixed when the key was generated (which must be this ceremony’s client data hash), and an authorization list saying the key was generated in the keystore, is a signing key, and is not usable by every application on the device.',
  },
};

/** Annotates the entries of an `attStmt` map. */
export function describeAttestationStatement(format: string, statement: unknown): Field[] {
  if (!(statement instanceof Map)) return [];

  if (statement.size === 0) {
    return [
      {
        offset: 0,
        length: 0,
        name: '(empty)',
        hex: '—',
        value: 'no entries',
        note:
          format === 'none'
            ? 'Required to be empty for `none`. Data hiding in a field nobody reads is data nobody is checking.'
            : 'Nothing to verify. A format this package cannot check is refused rather than parsed and ignored.',
      },
    ];
  }

  const notes = STATEMENT_NOTES[format] ?? {};
  const fields: Field[] = [];

  for (const [key, value] of statement as Map<unknown, unknown>) {
    const name = String(key);
    let hex = '—';
    let described: string;

    if (value instanceof Uint8Array) {
      hex = shortHex(value, 16);
      described = `${value.length} bytes`;
    } else if (Array.isArray(value)) {
      const total = value.reduce(
        (sum: number, entry: unknown) => sum + (entry instanceof Uint8Array ? entry.length : 0),
        0,
      );
      const first = value[0];
      if (first instanceof Uint8Array) hex = shortHex(first, 16);
      described = `${value.length} certificate${value.length === 1 ? '' : 's'}, ${total} bytes`;
    } else {
      described = String(value);
    }

    let byteLength = 0;
    if (value instanceof Uint8Array) byteLength = value.length;
    else if (Array.isArray(value)) {
      byteLength = value.reduce(
        (sum: number, entry: unknown) => sum + (entry instanceof Uint8Array ? entry.length : 0),
        0,
      );
    }

    fields.push({
      offset: 0,
      length: byteLength,
      sizeOnly: true,
      name,
      hex,
      value: described,
      note: notes[name] ?? 'Not consulted by the verifier.',
    });
  }

  return fields;
}
