import { Ninsho, RedisStore, type HttpRequest } from '@ninshorg/server';
import type { Request } from 'express';
import type { DemoUser } from './mock-data.js';

/**
 * COMPARISON C: NINSHO DPoP (DEMONSTRATING PROOF-OF-POSSESSION)
 *
 * This implementation showcases proof-of-possession (RFC 9449) and
 * browser session lifecycle:
 * - A cryptographic key pair is generated inside the browser via WebCrypto.
 * - The private key is marked `extractable: false` and saved in `IndexedDB`.
 *   Scripts cannot export the raw private key bytes.
 * - The access token is held ONLY IN MEMORY (never in `localStorage`).
 * - Every request carries a fresh signature (`DPoP` header) covering HTTP method,
 *   target URL, single-use `jti`, and the access token hash (`ath`).
 * - A stolen access token (from a network log, proxy, or server leak) is
 *   COMPLETELY USELESS without the private key.
 * - Refresh credentials live in an `HttpOnly`, `SameSite=Lax` cookie.
 * - Opt-in `sessionSync` uses `BroadcastChannel` to notify other browser tabs
 *   on confirmed logout, clearing their in-memory access tokens without
 *   ever transferring credentials across tabs.
 */

export interface DpopService {
  readonly auth: Ninsho;
  readonly store: RedisStore;
  close(): Promise<void>;
}

export function createDpopService(redisUrl: string): DpopService {
  const store = new RedisStore(redisUrl, {
    redisOptions: { keyPrefix: 'secureshop:dpop:' },
  });

  const auth = new Ninsho({
    store,
    binding: 'dpop',
    accessTokenTtl: 300,
    dpopProofMaxAgeSeconds: 60,
    onStoreError: 'closed',
  });

  return {
    auth,
    store,
    async close() {
      await auth.close();
    },
  };
}

/** Adapts an Express Request to Ninsho's structural HttpRequest. */
export function toNinshoRequest(req: Request): HttpRequest {
  const protocol = req.headers['x-forwarded-proto']?.toString().split(',')[0]?.trim() || req.protocol || 'http';
  return {
    method: req.method,
    originalUrl: req.originalUrl || req.url,
    protocol,
    headers: req.headers as Record<string, string | string[] | undefined>,
    rawHeaders: req.rawHeaders,
    body: req.body,
  };
}
