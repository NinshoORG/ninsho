import { createHash, createPublicKey, type KeyObject } from 'node:crypto';

/**
 * JSON Web Key handling for DPoP proofs.
 *
 * ─── Scope ────────────────────────────────────────────────────────────────
 * Only what RFC 9449 needs: parsing a public key out of a proof header,
 * computing its RFC 7638 thumbprint, and importing it for signature
 * verification. Ninsho does not otherwise use JOSE, and this is deliberately
 * not the beginning of a general JWK library.
 * ──────────────────────────────────────────────────────────────────────────
 */

/** The signature algorithms accepted in a DPoP proof header. */
export type DpopAlgorithm = 'ES256' | 'EdDSA';

/**
 * Every algorithm Ninsho will accept in a DPoP proof.
 *
 * ─── This allowlist is the security boundary ──────────────────────────────
 * A DPoP proof is a JWT, which means the entire algorithm-confusion family
 * applies — the class of attack PASETO was chosen to avoid for Ninsho's own
 * tokens. Three things must be structurally impossible here:
 *
 *   - `alg: none`. An unsigned proof asserting possession of a key.
 *   - Symmetric algorithms. If `HS256` were accepted, an attacker could take
 *     the public key from the header and use it as the HMAC secret — the
 *     classic confusion, and it works because the "public" key is right there
 *     in the token.
 *   - Anything not on this list, including algorithms added to JOSE later.
 *
 * An allowlist rather than a denylist, because a denylist is wrong the moment
 * a new algorithm is registered.
 *
 * ES256 is first because P-256 is universally available in browser WebCrypto;
 * Ed25519 support is newer and not yet everywhere.
 * ──────────────────────────────────────────────────────────────────────────
 */
export const ALLOWED_DPOP_ALGORITHMS: readonly DpopAlgorithm[] = ['ES256', 'EdDSA'];

/** A public JWK, narrowed to the two key types DPoP proofs may use. */
export type Jwk =
  | { readonly kty: 'EC'; readonly crv: 'P-256'; readonly x: string; readonly y: string }
  | { readonly kty: 'OKP'; readonly crv: 'Ed25519'; readonly x: string };

/** Raised for any malformed or unacceptable key. Carries no client-facing text. */
export class JwkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JwkError';
  }
}

/** base64url with no padding, as JOSE requires. */
const B64URL = /^[A-Za-z0-9_-]+$/;

function requireB64Url(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0 || !B64URL.test(value)) {
    throw new JwkError(`jwk.${field} must be non-empty base64url`);
  }
  return value;
}

/**
 * Validates an untrusted value as a public JWK.
 *
 * SECURITY: rejects any key containing a private component. A proof header
 * carrying `d` is either a client leaking its own private key or an attacker
 * probing for a server that will accept one; neither should be processed, and
 * silently ignoring the field would mean a leaked key still authenticated.
 */
export function parseJwk(value: unknown): Jwk {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new JwkError('jwk must be an object');
  }
  const jwk = value as Record<string, unknown>;

  for (const privateMember of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k']) {
    if (privateMember in jwk) {
      throw new JwkError(`jwk must be a public key; found private member "${privateMember}"`);
    }
  }

  // `use` and `key_ops`, when present, must not contradict verification.
  if ('use' in jwk && jwk['use'] !== 'sig') {
    throw new JwkError('jwk.use must be "sig" when present');
  }
  if ('key_ops' in jwk) {
    const ops = jwk['key_ops'];
    if (!Array.isArray(ops) || !ops.includes('verify')) {
      throw new JwkError('jwk.key_ops must include "verify" when present');
    }
  }

  if (jwk['kty'] === 'EC') {
    if (jwk['crv'] !== 'P-256') {
      throw new JwkError(`unsupported EC curve: ${String(jwk['crv'])}`);
    }
    return {
      kty: 'EC',
      crv: 'P-256',
      x: requireB64Url(jwk['x'], 'x'),
      y: requireB64Url(jwk['y'], 'y'),
    };
  }

  if (jwk['kty'] === 'OKP') {
    if (jwk['crv'] !== 'Ed25519') {
      throw new JwkError(`unsupported OKP curve: ${String(jwk['crv'])}`);
    }
    return { kty: 'OKP', crv: 'Ed25519', x: requireB64Url(jwk['x'], 'x') };
  }

  throw new JwkError(`unsupported key type: ${String(jwk['kty'])}`);
}

/** The algorithm a given key type must be used with. */
export function algorithmForJwk(jwk: Jwk): DpopAlgorithm {
  return jwk.kty === 'EC' ? 'ES256' : 'EdDSA';
}

/**
 * RFC 7638 JWK thumbprint, base64url-encoded SHA-256.
 *
 * ─── Why the canonical form matters ───────────────────────────────────────
 * The thumbprint is what binds a token to a key: it goes into the `cnf.jkt`
 * claim at issuance and is recomputed from each proof. If two encodings of the
 * same key produced different thumbprints, a client would be locked out of its
 * own session by a whitespace difference. If two *different* keys could produce
 * the same thumbprint, the binding would be worthless.
 *
 * RFC 7638 avoids both by fixing the input exactly: only the required members,
 * in lexicographic order, as compact JSON with no whitespace. Constructing the
 * object literally here rather than serializing the parsed JWK is deliberate —
 * it means an unexpected extra member cannot alter the hash.
 */
export function jwkThumbprint(jwk: Jwk): string {
  const canonical =
    jwk.kty === 'EC'
      ? `{"crv":"${jwk.crv}","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`
      : `{"crv":"${jwk.crv}","kty":"OKP","x":"${jwk.x}"}`;

  return createHash('sha256').update(canonical, 'utf8').digest('base64url');
}

/**
 * RFC 7638 thumbprint for an arbitrary key type.
 *
 * Ninsho verifies only EC and OKP proofs, but the canonicalisation rule is
 * general, and the specification's own worked example uses RSA. Keeping this
 * path available is what lets that example serve as a test vector.
 */
export function thumbprintOfRequiredMembers(members: Readonly<Record<string, string>>): string {
  const keys = Object.keys(members).sort();
  const canonical = `{${keys.map((k) => `"${k}":"${members[k] as string}"`).join(',')}}`;
  return createHash('sha256').update(canonical, 'utf8').digest('base64url');
}

/**
 * ASN.1 DER prefixes.
 *
 * Node imports keys from DER or PEM; JOSE exchanges raw coordinates. Rather
 * than push that conversion onto callers, the fixed prefixes are applied here.
 */
const SPKI_P256_PREFIX = Buffer.from(
  '3059301306072a8648ce3d020106082a8648ce3d030107034200',
  'hex',
);
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

const P256_COORDINATE_BYTES = 32;
const ED25519_KEY_BYTES = 32;

/**
 * Imports a JWK as a Node key for signature verification.
 *
 * @throws {JwkError} If the coordinates are the wrong length, or the point is
 *   otherwise not a valid key. Node performs the curve validation; a point not
 *   on the curve is rejected there rather than being verified against.
 */
export function importPublicKey(jwk: Jwk): KeyObject {
  try {
    if (jwk.kty === 'EC') {
      const x = Buffer.from(jwk.x, 'base64url');
      const y = Buffer.from(jwk.y, 'base64url');
      if (x.length !== P256_COORDINATE_BYTES || y.length !== P256_COORDINATE_BYTES) {
        throw new JwkError('P-256 coordinates must be 32 bytes each');
      }
      // 0x04 marks an uncompressed point.
      const der = Buffer.concat([SPKI_P256_PREFIX, Buffer.from([0x04]), x, y]);
      return createPublicKey({ key: der, format: 'der', type: 'spki' });
    }

    const x = Buffer.from(jwk.x, 'base64url');
    if (x.length !== ED25519_KEY_BYTES) {
      throw new JwkError('Ed25519 public key must be 32 bytes');
    }
    const der = Buffer.concat([SPKI_ED25519_PREFIX, x]);
    return createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch (error) {
    if (error instanceof JwkError) throw error;
    throw new JwkError(
      `jwk could not be imported: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
