/**
 * SafetyNet attestation — WebAuthn §8.5.
 *
 * ─── What this format is, and why it is last ──────────────────────────────
 * Older Android devices answered a registration by asking Google's SafetyNet
 * Attestation API to vouch for them, and forwarding Google's reply verbatim.
 * That reply is a JWS: a signed JSON document whose `nonce` field carries
 * `SHA-256(authData || clientDataHash)` and whose `ctsProfileMatch` field says
 * whether the device passed Android's compatibility test suite.
 *
 * So the chain of trust runs through Google rather than through the device.
 * The signature is Google's, over a document Google composed, about a device
 * Google inspected — none of it produced by the authenticator, and none of it
 * naming the credential key. That makes it the weakest of the attestation
 * formats: it attests to a *device*, not to where a key lives.
 *
 * Google has since deprecated the API this rests on in favour of Play
 * Integrity, and current Android devices send `android-key`, which attests to
 * the key itself. This is implemented for the devices still sending it, and it
 * is not the format to prefer when a device offers a choice.
 *
 * ─── RS256 only, deliberately ─────────────────────────────────────────────
 * The JWS header names its own algorithm, which is the shape every
 * algorithm-confusion attack is built on. SafetyNet responses are signed by
 * Google's attestation service with RSA, and this accepts nothing else — an
 * allowlist of exactly one, so the header has nothing left to negotiate.
 * ──────────────────────────────────────────────────────────────────────────
 */

/** Raised for a SafetyNet response this parser will not accept. */
export class SafetyNetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SafetyNetError';
  }
}

/** The hostname Google's attestation certificate is issued to. */
export const SAFETYNET_HOSTNAME = 'attest.android.com';

/**
 * How stale a SafetyNet response may be.
 *
 * The response is minted for one registration, so it should be seconds old.
 * Ten minutes leaves room for a slow device and a skewed clock while still
 * refusing one captured from an earlier session — which is the only reason to
 * look at the timestamp at all.
 */
export const SAFETYNET_MAX_AGE_MS = 10 * 60 * 1000;

/** How far into the future a timestamp may sit before it reads as forged. */
const SAFETYNET_MAX_SKEW_MS = 60 * 1000;

/** The parts of a SafetyNet JWS a verifier needs. */
export interface SafetyNetResponse {
  /** DER certificates from the header's `x5c`, leaf first. */
  readonly certificates: readonly Uint8Array[];
  /** `header.payload`, ASCII — exactly the bytes the signature covers. */
  readonly signingInput: Uint8Array;
  readonly signature: Uint8Array;
  /** Base64 of `SHA-256(authData || clientDataHash)`, as Google received it. */
  readonly nonce: string;
  readonly timestampMs: number;
  /** Whether the device passed Android's compatibility test suite. */
  readonly ctsProfileMatch: boolean;
  readonly basicIntegrity: boolean;
}

/**
 * Decodes canonical base64url.
 *
 * Re-encoding and comparing is what makes it canonical: `atob`-style decoders
 * accept several spellings of the same bytes, and a verifier that does is a
 * verifier where one document has more than one signature-covered form.
 */
function b64uDecode(value: string, what: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new SafetyNetError(`${what} is not base64url`);
  }
  const bytes = new Uint8Array(Buffer.from(value, 'base64url'));
  if (Buffer.from(bytes).toString('base64url') !== value) {
    throw new SafetyNetError(`${what} is not canonically encoded`);
  }
  return bytes;
}

/** Decodes canonical, padded standard base64 — the spelling `x5c` uses. */
function b64Decode(value: string, what: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new SafetyNetError(`${what} is not base64`);
  }
  const bytes = new Uint8Array(Buffer.from(value, 'base64'));
  if (Buffer.from(bytes).toString('base64') !== value) {
    throw new SafetyNetError(`${what} is not canonically encoded`);
  }
  return bytes;
}

/**
 * Parses JSON without letting a key called `__proto__` reach an object.
 *
 * The document is attacker-supplied and its fields are read by name, so a
 * property arriving through the prototype chain would be a field the verifier
 * never checked but still read.
 */
function parseJson(bytes: Uint8Array, what: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes), (key, entry) =>
      key === '__proto__' ? undefined : (entry as unknown),
    );
  } catch {
    throw new SafetyNetError(`${what} is not valid JSON`);
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new SafetyNetError(`${what} is not a JSON object`);
  }
  return value as Record<string, unknown>;
}

/**
 * Parses the JWS Google returned.
 *
 * Everything is located and type-checked before anything is trusted, and the
 * signing input is taken from the original text rather than re-serialised —
 * a signature covers bytes, and re-encoding JSON is a reliable way to produce
 * different ones.
 */
export function parseSafetyNetResponse(response: Uint8Array): SafetyNetResponse {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(response);
  } catch {
    throw new SafetyNetError('the SafetyNet response is not UTF-8');
  }

  const parts = text.split('.');
  if (parts.length !== 3) {
    throw new SafetyNetError(`a JWS has three segments, not ${parts.length}`);
  }
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];

  const header = parseJson(b64uDecode(headerPart, 'the JWS header'), 'the JWS header');
  if (header['alg'] !== 'RS256') {
    // The one algorithm Google's attestation service signs with. An allowlist
    // of exactly one leaves the header nothing to negotiate.
    throw new SafetyNetError(`unsupported SafetyNet algorithm: ${String(header['alg'])}`);
  }

  const x5c = header['x5c'];
  if (!Array.isArray(x5c) || x5c.length === 0) {
    throw new SafetyNetError('the JWS header carries no x5c chain');
  }
  if (x5c.length > 8) {
    throw new SafetyNetError(`the JWS header carries ${x5c.length} certificates`);
  }
  const certificates = x5c.map((entry, index) => {
    if (typeof entry !== 'string') {
      throw new SafetyNetError(`x5c entry ${index} is not a string`);
    }
    return b64Decode(entry, `x5c entry ${index}`);
  });

  const payload = parseJson(b64uDecode(payloadPart, 'the JWS payload'), 'the JWS payload');

  const nonce = payload['nonce'];
  if (typeof nonce !== 'string' || nonce.length === 0) {
    throw new SafetyNetError('the SafetyNet response carries no nonce');
  }

  const timestampMs = payload['timestampMs'];
  if (typeof timestampMs !== 'number' || !Number.isFinite(timestampMs)) {
    throw new SafetyNetError('the SafetyNet response carries no timestamp');
  }

  // Both are booleans in every response Google produces. A string `"true"` is
  // not a truthy value here, it is a different document.
  const ctsProfileMatch = payload['ctsProfileMatch'];
  const basicIntegrity = payload['basicIntegrity'];
  if (typeof ctsProfileMatch !== 'boolean' || typeof basicIntegrity !== 'boolean') {
    throw new SafetyNetError('the SafetyNet integrity verdicts are not booleans');
  }

  return {
    certificates,
    signingInput: new TextEncoder().encode(`${headerPart}.${payloadPart}`),
    signature: b64uDecode(signaturePart, 'the JWS signature'),
    nonce,
    timestampMs,
    ctsProfileMatch,
    basicIntegrity,
  };
}

/**
 * Checks the verdicts and the freshness a SafetyNet response carries.
 *
 * `ctsProfileMatch` is the one that means something: it is false on a rooted or
 * unlocked device, which is exactly the device an attacker controls.
 * `basicIntegrity` can be true there, so accepting on `basicIntegrity` alone
 * would accept the case the check exists for.
 */
export function verifySafetyNetVerdicts(response: SafetyNetResponse, now: number): void {
  if (!response.ctsProfileMatch) {
    throw new SafetyNetError('the device did not pass the compatibility test suite');
  }

  const age = now - response.timestampMs;
  if (age > SAFETYNET_MAX_AGE_MS) {
    throw new SafetyNetError(`the SafetyNet response is ${Math.round(age / 1000)}s old`);
  }
  if (age < -SAFETYNET_MAX_SKEW_MS) {
    throw new SafetyNetError('the SafetyNet response is timestamped in the future');
  }
}
