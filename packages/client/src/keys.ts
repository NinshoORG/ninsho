import { encodeJson, sha256Base64Url, toBase64Url } from './encoding.js';

/**
 * DPoP key material in the browser.
 *
 * ─── The one property that makes browser DPoP worth having ────────────────
 * The key is generated with `extractable: false`. The private half cannot be
 * read by any script, including script an attacker injects through an XSS —
 * `crypto.subtle.exportKey` on it throws, and there is no other route to the
 * bytes.
 *
 * That is the whole point. A bearer token is a string, so an XSS that can read
 * it can copy it anywhere and use it forever. A DPoP-bound token is useless
 * without proofs, proofs require the key, and the key cannot leave the browser.
 * An attacker is reduced to signing proofs *while they still have execution* —
 * which is a far more expensive position to hold, and one that ends when the
 * page closes.
 *
 * It does not make XSS harmless. It makes stolen credentials non-portable,
 * which is a different and much better failure mode.
 * ──────────────────────────────────────────────────────────────────────────
 */

/** The public half of a DPoP key, in the JWK form a proof header carries. */
export interface PublicJwk {
  readonly kty: 'EC';
  readonly crv: 'P-256';
  readonly x: string;
  readonly y: string;
}

/** A DPoP key pair. The private half is a handle, never bytes. */
export interface DpopKey {
  /** Non-extractable. Can sign; cannot be read. */
  readonly privateKey: CryptoKey;
  readonly publicKey: CryptoKey;
  readonly publicJwk: PublicJwk;
  /** RFC 7638 thumbprint — what the server binds a token to. */
  readonly thumbprint: string;
}

/**
 * ECDSA P-256, which is `ES256` in JOSE.
 *
 * Chosen over Ed25519 because P-256 is available in every browser's WebCrypto,
 * while Ed25519 support is recent and still uneven. The server accepts both;
 * the client picks the one that works everywhere.
 */
const ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const SIGN_PARAMS = { name: 'ECDSA', hash: 'SHA-256' } as const;

/**
 * Generates a fresh DPoP key pair.
 *
 * `extractable: false` is not a parameter. Making it configurable would invite
 * someone to set it true for debugging and leave it that way, which would
 * silently remove the property the whole mechanism rests on.
 */
export async function generateDpopKey(): Promise<DpopKey> {
  const pair = await crypto.subtle.generateKey(ALGORITHM, false, ['sign', 'verify']);
  return describeKey(pair.privateKey, pair.publicKey);
}

/** Builds the public JWK and thumbprint for an existing key pair. */
export async function describeKey(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
): Promise<DpopKey> {
  const exported = (await crypto.subtle.exportKey('jwk', publicKey)) as {
    x?: string;
    y?: string;
  };

  if (typeof exported.x !== 'string' || typeof exported.y !== 'string') {
    throw new Error('ninsho: exported public key is missing its coordinates');
  }

  const publicJwk: PublicJwk = { kty: 'EC', crv: 'P-256', x: exported.x, y: exported.y };
  return {
    privateKey,
    publicKey,
    publicJwk,
    thumbprint: await jwkThumbprint(publicJwk),
  };
}

/**
 * RFC 7638 thumbprint of a public JWK.
 *
 * The canonical form is fixed by the specification: only the required members,
 * in lexicographic order, as compact JSON with no whitespace. It is built
 * literally here rather than by serializing an object, so an unexpected extra
 * member cannot change the result — and so this and the server's
 * implementation cannot drift into disagreeing about a key's identity.
 */
export async function jwkThumbprint(jwk: PublicJwk): Promise<string> {
  return sha256Base64Url(`{"crv":"${jwk.crv}","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`);
}

/**
 * Signs the DPoP signing input.
 *
 * WebCrypto returns ECDSA signatures as raw `r‖s`, which is exactly the form
 * JOSE requires — no DER unwrapping, unlike Node's default.
 */
export async function signProof(key: CryptoKey, signingInput: string): Promise<string> {
  const signature = await crypto.subtle.sign(
    SIGN_PARAMS,
    key,
    new TextEncoder().encode(signingInput),
  );
  return toBase64Url(new Uint8Array(signature));
}

/** Assembles a compact JWS from its parts. */
export function assembleJws(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): string {
  return `${encodeJson(header)}.${encodeJson(payload)}`;
}
