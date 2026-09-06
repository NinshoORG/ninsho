/**
 * base64url and JSON encoding, written against Web APIs only.
 *
 * Node's `Buffer` is not available in a browser, and pulling in a polyfill for
 * three small functions would be a dependency in the signing path of an
 * authentication client. These use `TextEncoder` and `btoa`/`atob`, which exist
 * in every browser and in Node 18+.
 */

/** Encodes bytes as unpadded base64url, the only form JOSE accepts. */
export function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  // Chunked so a large input cannot blow the argument limit of `apply`.
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decodes unpadded base64url back to bytes.
 *
 * Validated before `atob` sees it, for two reasons. `atob` throws a
 * `DOMException`, which is not the controlled error the rest of this project
 * raises and is awkward to catch by type; and this function is exported and
 * used to decode request bodies — `examples/express-api` reads WebAuthn
 * responses through it — so its input is attacker-supplied on that path.
 *
 * Padding characters are refused rather than tolerated. This is base64*url*,
 * where the unpadded form is the only one JOSE and WebAuthn produce, and
 * accepting a second spelling of the same bytes is how two implementations end
 * up disagreeing about what a value was.
 */
export function fromBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error('ninsho: value is not unpadded base64url');
  }
  // A length of 1 more than a multiple of 4 encodes no whole byte and cannot
  // be padded into anything valid.
  if (value.length % 4 === 1) {
    throw new Error('ninsho: value is not unpadded base64url');
  }

  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, '='));

  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** UTF-8 encodes a string, then base64url. */
export function encodeJson(value: unknown): string {
  return toBase64Url(new TextEncoder().encode(JSON.stringify(value)));
}

/** base64url SHA-256 of a string — the `ath` claim and the JWK thumbprint. */
export async function sha256Base64Url(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return toBase64Url(new Uint8Array(digest));
}
