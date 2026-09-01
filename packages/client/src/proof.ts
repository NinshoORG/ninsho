import { sha256Base64Url } from './encoding.js';
import { assembleJws, signProof, type DpopKey } from './keys.js';

/**
 * DPoP proof construction — the client half of RFC 9449.
 */

export interface ProofRequest {
  /** HTTP method of the request this proof will accompany. */
  readonly method: string;
  /** Absolute request URI. Query and fragment are stripped, as the spec requires. */
  readonly url: string;
  /** The access token being presented, if any. Adds the `ath` binding. */
  readonly accessToken?: string;
}

/** base64url SHA-256 of the access token — the `ath` claim, RFC 9449 §4.3. */
export async function accessTokenHash(accessToken: string): Promise<string> {
  return sha256Base64Url(accessToken);
}

/**
 * Creates a proof for exactly one request.
 *
 * ─── One proof per request, and why ───────────────────────────────────────
 * The proof commits to the method and URI, and carries a fresh `jti` the
 * server remembers until the proof expires. Reusing one is refused.
 *
 * That is not an inconvenience to work around — it is what makes a captured
 * proof worthless. Anything that observes traffic (a logging proxy, an
 * extension, a compromised CDN) sees a proof that is already spent by the time
 * it could be replayed.
 * ──────────────────────────────────────────────────────────────────────────
 */
export async function createProof(key: DpopKey, request: ProofRequest): Promise<string> {
  const url = new URL(request.url);
  url.search = '';
  url.hash = '';

  const header = {
    typ: 'dpop+jwt',
    alg: 'ES256',
    jwk: key.publicJwk,
  };

  const payload: Record<string, unknown> = {
    jti: crypto.randomUUID(),
    htm: request.method.toUpperCase(),
    htu: url.toString(),
    iat: Math.floor(Date.now() / 1000),
    ...(request.accessToken !== undefined && {
      ath: await accessTokenHash(request.accessToken),
    }),
  };

  const signingInput = assembleJws(header, payload);
  return `${signingInput}.${await signProof(key.privateKey, signingInput)}`;
}
