/**
 * @ninshorg/client — browser client for Ninsho.
 *
 * Manages a DPoP session: a non-extractable key that no script can read, a
 * fresh proof on every request, an access token held only in memory, and
 * automatic single-flight refresh.
 *
 * Zero dependencies. Uses only Web APIs — WebCrypto, IndexedDB and fetch —
 * so it runs in a browser and in Node 20+ without a polyfill.
 *
 * @example
 * ```ts
 * import { NinshoClient, IndexedDbKeyStore } from '@ninshorg/client';
 *
 * const auth = new NinshoClient({
 *   baseUrl: 'https://api.example.com',
 *   keyStore: new IndexedDbKeyStore(),   // survives reload
 * });
 *
 * await auth.signIn('/auth/login', { email, password });
 *
 * // Proof, Authorization header, and refresh-on-401 are all handled.
 * const orders = await auth.fetch('/orders').then((r) => r.json());
 *
 * await auth.signOut();
 * ```
 */

export { NinshoClient } from './client.js';
export type { NinshoClientOptions } from './client.js';

export { generateDpopKey, describeKey, jwkThumbprint } from './keys.js';
export type { DpopKey, PublicJwk } from './keys.js';

export { createProof, accessTokenHash } from './proof.js';
export type { ProofRequest } from './proof.js';

export { IndexedDbKeyStore, MemoryKeyStore } from './storage.js';
export type { DpopKeyStore } from './storage.js';

export { toBase64Url, fromBase64Url } from './encoding.js';
