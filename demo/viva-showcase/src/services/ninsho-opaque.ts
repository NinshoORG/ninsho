import { Ninsho, RedisStore, type NinshoStore } from '@ninshorg/server';
import type { DemoUser } from './mock-data.js';

/**
 * COMPARISON B: NINSHO OPAQUE SESSIONS & CENTRALIZED REVOCATION
 *
 * This implementation showcases Ninsho's default opaque strategy:
 * - Access tokens are 256-bit CSPRNG cryptographically random strings.
 * - State lives entirely inside the injected Redis store (`RedisStore`).
 * - No signing keys, no algorithm choice, no signature validation overhead.
 * - Raw tokens are never stored (keyed by SHA-256 hash).
 *
 * DUAL-INSTANCE ARCHITECTURE:
 * To prove cross-instance revocation, two independent Ninsho engine instances
 * (`instanceA` and `instanceB`) are created with separate Redis connections
 * sharing the same namespace (`secureshop:opaque:`).
 *
 * 🛡️ DEMONSTRATED BEHAVIOR:
 * 1. User logs in through Instance A.
 * 2. Token verifies through Instance A (HTTP 200) AND Instance B (HTTP 200).
 * 3. User logs out through Instance A, calling `revokeSession(sessionId)`.
 * 4. Replaying the copied token through Instance A returns HTTP 401.
 * 5. Replaying the copied token through Instance B ALSO returns HTTP 401 immediately.
 */

export interface OpaqueInstances {
  readonly instanceA: Ninsho;
  readonly instanceB: Ninsho;
  readonly storeA: RedisStore;
  readonly storeB: RedisStore;
  close(): Promise<void>;
}

export function createOpaqueInstances(redisUrl: string): OpaqueInstances {
  const storeA = new RedisStore(redisUrl, {
    redisOptions: { keyPrefix: 'secureshop:opaque:' },
  });
  const storeB = new RedisStore(redisUrl, {
    redisOptions: { keyPrefix: 'secureshop:opaque:' },
  });

  const instanceA = new Ninsho({
    store: storeA,
    strategy: 'opaque',
    accessTokenTtl: 300,
    onStoreError: 'closed',
  });

  const instanceB = new Ninsho({
    store: storeB,
    strategy: 'opaque',
    accessTokenTtl: 300,
    onStoreError: 'closed',
  });

  return {
    instanceA,
    instanceB,
    storeA,
    storeB,
    async close() {
      await Promise.all([instanceA.close(), instanceB.close()]);
    },
  };
}

export async function loginOpaque(
  instance: Ninsho,
  user: DemoUser,
): Promise<{
  accessToken: string;
  refreshToken: string;
  sessionId: string;
  expiresInSeconds: number;
}> {
  const pair = await instance.createSession({
    userId: user.id,
    roles: [user.role],
    scopes: [],
  });

  return {
    accessToken: pair.accessToken,
    refreshToken: pair.refreshToken,
    sessionId: pair.sessionId,
    expiresInSeconds: 300,
  };
}
