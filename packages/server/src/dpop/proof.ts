import { createHash, verify as cryptoVerify } from 'node:crypto';
import {
  ALLOWED_DPOP_ALGORITHMS,
  algorithmForJwk,
  importPublicKey,
  jwkThumbprint,
  parseJwk,
  type DpopAlgorithm,
  type Jwk,
} from './jwk.js';

/**
 * DPoP proof verification — RFC 9449 §4.3.
 *
 * ─── What a proof is, and what it proves ──────────────────────────────────
 * A DPoP proof is a short-lived JWT that a client signs with a key it holds
 * privately, covering the HTTP method and URI of the request it accompanies —
 * and, when an access token is presented, a hash of that token.
 *
 * Verifying it establishes that whoever sent this request holds the private
 * key whose thumbprint the access token was bound to. A stolen bearer token is
 * then useless on its own: replaying it requires a proof, and producing a proof
 * requires the key, which never leaves the client.
 *
 * That is the property `SECURITY.md` previously listed as unmitigated.
 * ──────────────────────────────────────────────────────────────────────────
 *
 * ─── The uncomfortable part ───────────────────────────────────────────────
 * A proof is a JWT, so every JWT attack applies — including the algorithm
 * confusion that Ninsho avoids for its own tokens by using PASETO. There is no
 * choice about the format: RFC 9449 fixes it, and the client library on the
 * other end is a browser.
 *
 * So the JWT parsing here is written defensively and deliberately narrow: a
 * fixed `typ`, an algorithm allowlist, a required embedded key, and no path
 * that consults the token for anything before its signature is verified.
 * ──────────────────────────────────────────────────────────────────────────
 */

/** Raised for any proof that fails verification. Never exposed to a client. */
export class DpopProofError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DpopProofError';
  }
}

/** What a verified proof establishes. */
export interface VerifiedProof {
  /** RFC 7638 thumbprint of the proof key. This is what a token binds to. */
  readonly jkt: string;
  /** Unique identifier, for single-use enforcement. */
  readonly jti: string;
  /** Issuance time, epoch ms. */
  readonly issuedAtMs: number;
  readonly algorithm: DpopAlgorithm;
}

export interface VerifyProofOptions {
  /** HTTP method of the request the proof accompanies. */
  readonly method: string;
  /**
   * The request URI, without query or fragment (RFC 9449 §4.3 step 9).
   * The caller is responsible for reconstructing this from the *server's* view
   * of the request, never from a client-supplied header.
   */
  readonly url: string;
  /** The access token being presented, if any. Binds the proof to it via `ath`. */
  readonly accessToken?: string;
  /** How old a proof may be. Default 60s. */
  readonly maxAgeSeconds: number;
  /** Allowance for clock skew in either direction. */
  readonly clockToleranceSeconds: number;
}

/** JOSE requires unpadded base64url; anything else is not a valid JWT segment. */
const B64URL_SEGMENT = /^[A-Za-z0-9_-]+$/;

/**
 * Decodes a JWT segment, rejecting any non-canonical encoding.
 *
 * ─── Why the character-set check alone is not enough ──────────────────────
 * Node's base64url decoder is lenient. Where a segment's length does not fall
 * on a 3-byte boundary, its final character carries only a few meaningful
 * bits, and the rest are padding the decoder simply ignores — so several
 * distinct strings decode to identical bytes.
 *
 * For a 64-byte ECDSA signature that is not hypothetical: the last character
 * encodes two meaningful bits, leaving sixteen spellings of every valid
 * signature. Each one verifies, because the bytes are the same.
 *
 * That gives one proof many textual forms, which breaks anything that treats
 * the proof string as an identity — logging, deduplication, an operator
 * comparing two requests by eye. Re-encoding and comparing forces exactly one
 * accepted spelling per value, which is the same rule the PASETO parser
 * applies; this decoder was inconsistent with it until a mutation test found
 * the gap.
 * ──────────────────────────────────────────────────────────────────────────
 */
function decodeCanonical(segment: string, what: string): Buffer {
  if (!B64URL_SEGMENT.test(segment)) {
    throw new DpopProofError(`${what} is not valid base64url`);
  }
  const decoded = Buffer.from(segment, 'base64url');
  if (decoded.toString('base64url') !== segment) {
    throw new DpopProofError(`${what} is not canonical base64url`);
  }
  return decoded;
}

function decodeSegment(segment: string, what: string): Record<string, unknown> {
  const decoded = decodeCanonical(segment, what);

  let parsed: unknown;
  try {
    parsed = JSON.parse(decoded.toString('utf8'));
  } catch {
    throw new DpopProofError(`${what} is not valid JSON`);
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new DpopProofError(`${what} is not a JSON object`);
  }
  return parsed as Record<string, unknown>;
}

/**
 * Normalises a URI for the `htu` comparison.
 *
 * RFC 9449 §4.3 step 9 compares the proof's `htu` against the request URI with
 * query and fragment removed. Normalising both sides through the URL parser
 * means a trailing-slash or default-port difference does not reject a
 * legitimate client, while any difference in scheme, host or path still does.
 */
function normaliseHtu(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new DpopProofError('htu is not an absolute URI');
  }
  url.search = '';
  url.hash = '';
  return url.toString();
}

/** base64url SHA-256 of the access token, for the `ath` claim (RFC 9449 §4.3 step 11). */
export function accessTokenHash(accessToken: string): string {
  return createHash('sha256').update(accessToken, 'ascii').digest('base64url');
}

/**
 * Verifies a DPoP proof.
 *
 * The order below follows RFC 9449 §4.3 and is load-bearing: nothing the token
 * asserts is acted on before the signature over it has been verified. The one
 * value read early is the embedded `jwk`, which is unavoidable — it *is* the
 * verification key — and it is used for nothing except verifying the signature
 * that then proves it was the intended one.
 *
 * @throws {DpopProofError} On any failure. The reason is diagnostic only.
 */
export function verifyDpopProof(proof: string, options: VerifyProofOptions): VerifiedProof {
  if (typeof proof !== 'string' || proof.length === 0) {
    throw new DpopProofError('proof is empty or not a string');
  }
  // A generous ceiling, well above any legitimate proof, so a multi-megabyte
  // header cannot be used to make the server do parsing work.
  if (proof.length > 8192) {
    throw new DpopProofError('proof is implausibly large');
  }

  const parts = proof.split('.');
  if (parts.length !== 3) {
    throw new DpopProofError('proof is not a three-part compact JWS');
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];

  // ── Header ──────────────────────────────────────────────────────────────
  const header = decodeSegment(encodedHeader, 'proof header');

  // `typ` is what stops a token minted for some other purpose being replayed
  // as a proof. RFC 9449 §4.3 step 3.
  if (header['typ'] !== 'dpop+jwt') {
    throw new DpopProofError(`typ must be "dpop+jwt", got ${String(header['typ'])}`);
  }

  const alg = header['alg'];
  if (typeof alg !== 'string' || !ALLOWED_DPOP_ALGORITHMS.includes(alg as DpopAlgorithm)) {
    // Covers `none`, every symmetric algorithm, and anything JOSE adds later.
    throw new DpopProofError(`unacceptable alg: ${String(alg)}`);
  }

  if (!('jwk' in header)) {
    throw new DpopProofError('proof header must carry the public key as jwk');
  }

  // Key validation failures are surfaced as proof failures. A caller of this
  // function is asking one question — is this proof acceptable — and should
  // not have to catch two error types to hear "no". The underlying reason is
  // preserved in the message for diagnosis.
  let jwk: Jwk;
  try {
    jwk = parseJwk(header['jwk']);
  } catch (error) {
    throw new DpopProofError(
      `proof key is unacceptable: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  // The algorithm must match the key type. Without this an attacker could
  // present an Ed25519 key while claiming ES256, and any leniency in the
  // verifier about which primitive to run becomes exploitable.
  if (algorithmForJwk(jwk) !== alg) {
    throw new DpopProofError(`alg ${alg} does not match key type ${jwk.kty}`);
  }

  // ── Signature, before anything in the payload is trusted ────────────────
  let publicKey;
  try {
    publicKey = importPublicKey(jwk);
  } catch (error) {
    throw new DpopProofError(
      `proof key could not be imported: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const signingInput = Buffer.from(`${encodedHeader}.${encodedPayload}`, 'ascii');

  // The signature segment is where non-canonical encodings actually bite: a
  // 64-byte signature leaves spare bits in its final character.
  const signature = decodeCanonical(encodedSignature, 'signature');

  const signatureValid =
    alg === 'ES256'
      ? // JOSE uses the fixed-width r‖s form, not the DER encoding Node
        // defaults to for ECDSA.
        cryptoVerify('sha256', signingInput, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature)
      : cryptoVerify(null, signingInput, publicKey, signature);

  if (!signatureValid) {
    throw new DpopProofError('proof signature is invalid');
  }

  // ── Claims — now running on authenticated bytes ─────────────────────────
  const payload = decodeSegment(encodedPayload, 'proof payload');

  const jti = payload['jti'];
  if (typeof jti !== 'string' || jti.length === 0 || jti.length > 256) {
    throw new DpopProofError('jti must be a non-empty string of reasonable length');
  }

  if (payload['htm'] !== options.method.toUpperCase()) {
    // Without this, a proof captured from a GET could authorise a DELETE.
    throw new DpopProofError(
      `htm mismatch: proof is for ${String(payload['htm'])}, request is ${options.method}`,
    );
  }

  const htu = payload['htu'];
  if (typeof htu !== 'string') {
    throw new DpopProofError('htu must be a string');
  }
  if (normaliseHtu(htu) !== normaliseHtu(options.url)) {
    // Without this, a proof captured by one endpoint could be replayed against
    // another — including by a resource server that is not fully trusted.
    throw new DpopProofError('htu does not match the request URI');
  }

  const iat = payload['iat'];
  if (typeof iat !== 'number' || !Number.isFinite(iat)) {
    throw new DpopProofError('iat must be a number');
  }
  const issuedAtMs = iat * 1000;
  const now = Date.now();
  const toleranceMs = options.clockToleranceSeconds * 1000;

  if (issuedAtMs > now + toleranceMs) {
    throw new DpopProofError('proof was issued in the future');
  }
  if (issuedAtMs < now - options.maxAgeSeconds * 1000 - toleranceMs) {
    // Bounds how long a captured proof stays useful, and bounds how much
    // replay state the server has to retain.
    throw new DpopProofError('proof is too old');
  }

  // ── ath: binds the proof to the specific access token ───────────────────
  if (options.accessToken !== undefined) {
    const ath = payload['ath'];
    if (typeof ath !== 'string' || ath.length === 0) {
      throw new DpopProofError('ath is required when an access token is presented');
    }
    // A plain === is adequate: both sides are SHA-256 digests of values the
    // attacker already holds, so there is no secret for a timing difference to
    // leak. Nothing is gained by making it constant-time, and implying
    // otherwise would misrepresent where the security actually comes from.
    if (ath !== accessTokenHash(options.accessToken)) {
      throw new DpopProofError('ath does not match the presented access token');
    }
  }

  return {
    jkt: jwkThumbprint(jwk),
    jti,
    issuedAtMs,
    algorithm: alg as DpopAlgorithm,
  };
}
