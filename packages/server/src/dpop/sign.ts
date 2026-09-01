import { generateKeyPairSync, randomUUID, sign as cryptoSign, type KeyObject } from 'node:crypto';
import { accessTokenHash } from './proof.js';
import { jwkThumbprint, type DpopAlgorithm, type Jwk } from './jwk.js';

/**
 * Client-side DPoP proof generation.
 *
 * ─── Why a server package ships a client helper ───────────────────────────
 * Because otherwise nobody can test their integration. A developer enabling
 * DPoP needs to be able to write a test that sends a real proof, and asking
 * them to hand-assemble a JWS to do it guarantees either a broken test or a
 * broken understanding of what the server checks.
 *
 * It is also what a Node service-to-service client needs. Browser clients
 * should generate their key with WebCrypto and set `extractable: false`, so the
 * private key cannot be read by script even if the page is compromised — which
 * is the property that makes DPoP worth having there. This helper cannot offer
 * that, and is not a substitute for it.
 *
 * SECURITY: this handles private key material. It exists for clients and
 * tests. Nothing on the server's verification path imports it.
 * ──────────────────────────────────────────────────────────────────────────
 */

/** A DPoP key pair, ready to sign proofs. */
export interface DpopKeyPair {
  readonly algorithm: DpopAlgorithm;
  readonly publicJwk: Jwk;
  readonly privateKey: KeyObject;
  /** RFC 7638 thumbprint — what an access token binds to. */
  readonly jkt: string;
}

/**
 * Generates a DPoP key pair.
 *
 * @param algorithm Defaults to ES256, because P-256 is universally available
 *   in browser WebCrypto while Ed25519 support is newer.
 */
export function generateDpopKeyPair(algorithm: DpopAlgorithm = 'ES256'): DpopKeyPair {
  if (algorithm === 'ES256') {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };

    const publicJwk: Jwk = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
    return { algorithm, publicJwk, privateKey, jkt: jwkThumbprint(publicJwk) };
  }

  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string };

  const publicJwk: Jwk = { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
  return { algorithm, publicJwk, privateKey, jkt: jwkThumbprint(publicJwk) };
}

export interface CreateProofOptions {
  /** HTTP method of the request this proof accompanies. */
  readonly method: string;
  /** Request URI. Query and fragment are stripped, as RFC 9449 requires. */
  readonly url: string;
  /** The access token being presented, if any. Adds the `ath` binding. */
  readonly accessToken?: string;
  /** Override the identifier. Defaults to a fresh UUID; reuse it only to test replay handling. */
  readonly jti?: string;
  /** Override issuance time, epoch ms. For testing clock skew. */
  readonly issuedAtMs?: number;
}

function b64urlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

/**
 * Creates a DPoP proof for one request.
 *
 * A proof is single-use and bound to the method and URI, so one must be created
 * per request — reusing it will be rejected by the server's replay guard.
 */
export function createDpopProof(keyPair: DpopKeyPair, options: CreateProofOptions): string {
  const url = new URL(options.url);
  url.search = '';
  url.hash = '';

  const header = {
    typ: 'dpop+jwt',
    alg: keyPair.algorithm,
    jwk: keyPair.publicJwk,
  };

  const payload: Record<string, unknown> = {
    jti: options.jti ?? randomUUID(),
    htm: options.method.toUpperCase(),
    htu: url.toString(),
    iat: Math.floor((options.issuedAtMs ?? Date.now()) / 1000),
    ...(options.accessToken !== undefined && { ath: accessTokenHash(options.accessToken) }),
  };

  const signingInput = `${b64urlJson(header)}.${b64urlJson(payload)}`;

  // JOSE requires the fixed-width r‖s form for ECDSA, not Node's default DER.
  const signature =
    keyPair.algorithm === 'ES256'
      ? cryptoSign(
          'sha256',
          Buffer.from(signingInput, 'ascii'),
          { key: keyPair.privateKey, dsaEncoding: 'ieee-p1363' },
        )
      : cryptoSign(null, Buffer.from(signingInput, 'ascii'), keyPair.privateKey);

  return `${signingInput}.${signature.toString('base64url')}`;
}
