import { describe, it, expect, afterAll } from 'vitest';
import { execSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  TokenInvalidError,
  TokenRevokedError,
  StoreUnavailableError,
  generateId,
  type Principal,
} from '@ninshorg/core';
import { RedisStore } from '../store/redis.js';
import { OpaqueEngine } from '../engine/opaque.js';
import { PasetoEngine } from '../engine/paseto.js';
import { SessionManager } from '../session/manager.js';
import { MemoryAuditSink } from '../audit.js';
import { KeyRing, generateKeyPair } from '../keys/keyring.js';

/**
 * Redis persistence, restart and recovery verification.
 *
 * ─── What this suite establishes ──────────────────────────────────────────
 *
 * 1. A GRACEFUL Redis restart with RDB persistence preserves active sessions
 *    and revocation state for both opaque and PASETO strategies.
 *
 * 2. The default fail-closed behaviour (onStoreError: 'closed') refuses
 *    requests during temporary Redis unavailability rather than admitting
 *    them without server-side verification.
 *
 * 3. Complete data loss under the opaque strategy is fail-closed: all
 *    sessions become invalid because the server-side records that give them
 *    meaning are gone.
 *
 * 4. Complete data loss under the PASETO strategy loses the revocation
 *    denylist but not the tokens themselves, because PASETO tokens carry
 *    their claims in a cryptographic signature the server can verify locally.
 *    A PREVIOUSLY REVOKED token therefore becomes usable again until its
 *    natural expiry — a documented, unresolved limitation. The test asserts
 *    this dangerous outcome rather than hiding it.
 *
 * 5. Snapshot rollback (restoring an older RDB) discards revocations that
 *    occurred after the snapshot, with the same per-strategy consequences.
 *
 * ─── What this suite does NOT establish ───────────────────────────────────
 *
 * - It does not test abrupt process death (kill -9, power loss). The test
 *   uses `redis-cli SHUTDOWN SAVE`, which is a graceful shutdown that
 *   triggers a final RDB save. AOF durability, fsync policies, and
 *   kernel-level write ordering are not exercised.
 *
 * - It does not prove anything about Redis cluster, Sentinel failover,
 *   or replication lag.
 *
 * - It does not test AOF persistence specifically. RDB provides
 *   point-in-time snapshots; AOF would provide write-ahead durability.
 *   The distinction matters for the gap between the last snapshot and
 *   a crash.
 *
 * ─── Prerequisites ────────────────────────────────────────────────────────
 *
 * Docker must be available and its daemon running. Each scenario starts a
 * disposable `redis:7-alpine` container on a unique port with a temporary
 * data directory. The containers and directories are cleaned up in finally
 * blocks regardless of test outcome.
 *
 * The suite is skipped when Docker is unavailable (detected by probing the
 * `docker info` command). This is deliberate: a flaky test that sometimes
 * starts Docker and sometimes does not is worse than no test.
 * ──────────────────────────────────────────────────────────────────────────
 */

// ─── Docker availability probe ────────────────────────────────────────────

let dockerAvailable = false;
try {
  execSync('docker info', { stdio: 'pipe', timeout: 10_000 });
  dockerAvailable = true;
} catch {
  // Docker daemon not running or docker not installed.
}

const KEY_PAIR = generateKeyPair('test-persistence');
const ISSUER = 'https://persistence-test.ninsho.local';
const AUDIENCE = 'persistence-test-api';

// Track all resources for cleanup.
const openStores: RedisStore[] = [];
const containers: string[] = [];
const tmpDirs: string[] = [];

/** Allocate a port by binding to 0 and immediately releasing. */
async function findFreePort(): Promise<number> {
  const net = await import('node:net');
  const srv = net.createServer();
  await new Promise<void>((resolve, reject) => {
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      srv.off('error', reject);
      resolve();
    });
  });
  const addr = srv.address();
  if (addr === null || typeof addr === 'string') {
    throw new Error('Failed to get server address');
  }
  const port = addr.port;
  await new Promise<void>((resolve) => srv.close(() => resolve()));
  return port;
}

/**
 * Starts a disposable Redis instance in Docker with RDB persistence.
 *
 * @returns port, container name, and data directory path.
 */
function startRedis(
  port: number,
  dataDir: string,
  containerName: string,
): void {
  // --save 1 1: snapshot after 1 second if at least 1 key changed.
  // This is aggressive — production would never use this — but it ensures
  // writes reach the RDB file within the test's timeframe.
  execSync(
    `docker run -d --rm ` +
    `--name ${containerName} ` +
    `-p 127.0.0.1:${port}:6379 ` +
    `-v "${dataDir.replace(/\\/g, '/')}":/data ` +
    `redis:7-alpine ` +
    `redis-server --save 1 1 --dir /data --dbfilename dump.rdb`,
    { stdio: 'pipe', timeout: 30_000 },
  );
  containers.push(containerName);
}

/** Stop a Redis container. Uses SHUTDOWN SAVE for graceful RDB flush. */
function stopRedisGracefully(containerName: string): void {
  try {
    execSync(
      `docker exec ${containerName} redis-cli SHUTDOWN SAVE`,
      { stdio: 'pipe', timeout: 15_000 },
    );
  } catch {
    // SHUTDOWN causes the exec to fail since the server exits. Expected.
  }
  // Wait for container to actually stop.
  try {
    execSync(`docker wait ${containerName}`, { stdio: 'pipe', timeout: 15_000 });
  } catch {
    // Container already removed (--rm flag).
  }
  const idx = containers.indexOf(containerName);
  if (idx !== -1) containers.splice(idx, 1);
}

/** Force-stop a container without persistence flush. */
function stopRedisAbruptly(containerName: string): void {
  try {
    execSync(`docker kill ${containerName}`, { stdio: 'pipe', timeout: 10_000 });
  } catch {
    // Already stopped.
  }
  try {
    execSync(`docker wait ${containerName}`, { stdio: 'pipe', timeout: 10_000 });
  } catch {
    // Already removed.
  }
  const idx = containers.indexOf(containerName);
  if (idx !== -1) containers.splice(idx, 1);
}

/** Restart Redis from the same data directory. */
function restartRedis(
  port: number,
  dataDir: string,
  containerName: string,
): void {
  startRedis(port, dataDir, containerName);
}

/** Wait for Redis to become ready. */
async function waitForRedis(url: string, timeoutMs = 15_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const store = new RedisStore(url, {
      redisOptions: { maxRetriesPerRequest: 1, retryStrategy: () => null },
    });
    try {
      const ok = await store.ping();
      if (ok) {
        await store.close();
        return;
      }
    } catch {
      // Not ready yet.
    }
    await store.close();
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`Redis at ${url} did not become ready within ${timeoutMs}ms`);
}

function principal(): Principal {
  return { userId: `user_${generateId()}`, roles: ['user'], scopes: [] };
}

interface OpaqueHarness {
  store: RedisStore;
  engine: OpaqueEngine;
  sessions: SessionManager;
  audit: MemoryAuditSink;
}

function buildOpaque(url: string): OpaqueHarness {
  const store = new RedisStore(url);
  openStores.push(store);
  const engine = new OpaqueEngine(store, { accessTokenTtl: 300, clockToleranceSeconds: 5 });
  const audit = new MemoryAuditSink();
  const sessions = new SessionManager(store, engine, {
    refreshTokenTtl: 3600,
    refreshGraceSeconds: 30,
    clockToleranceSeconds: 5,
    audit,
  });
  return { store, engine, sessions, audit };
}

interface PasetoHarness {
  store: RedisStore;
  engine: PasetoEngine;
  sessions: SessionManager;
  audit: MemoryAuditSink;
  keys: KeyRing;
}

function buildPaseto(url: string): PasetoHarness {
  const store = new RedisStore(url);
  openStores.push(store);
  const keys = new KeyRing({ active: KEY_PAIR });
  const engine = new PasetoEngine(store, keys, {
    accessTokenTtl: 300,
    clockToleranceSeconds: 5,
    issuer: ISSUER,
    audience: AUDIENCE,
  });
  const audit = new MemoryAuditSink();
  const sessions = new SessionManager(store, engine, {
    refreshTokenTtl: 3600,
    refreshGraceSeconds: 30,
    clockToleranceSeconds: 5,
    audit,
  });
  return { store, engine, sessions, audit, keys };
}

/** Create a temporary directory for Redis data. */
function makeTmpDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'ninsho-redis-test-'));
  tmpDirs.push(dir);
  return dir;
}

function cleanup(): void {
  // Close all open stores.
  for (const s of openStores.splice(0)) {
    s.close().catch(() => {});
  }
  // Stop all containers.
  for (const name of containers.splice(0)) {
    try {
      execSync(`docker rm -f ${name}`, { stdio: 'pipe', timeout: 10_000 });
    } catch {
      // Best effort.
    }
  }
  // Remove tmp dirs.
  for (const dir of tmpDirs.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // Best effort on Windows.
    }
  }
}

afterAll(() => {
  cleanup();
});

// ─── Tests ────────────────────────────────────────────────────────────────

describe.runIf(dockerAvailable)(
  'Redis persistence and recovery (Docker-managed instances)',
  () => {
    // ── Scenario 1: Graceful restart with RDB persistence ─────────────
    describe('graceful restart with RDB persistence', () => {
      it('preserves active opaque sessions and their revocation state across a graceful restart', async () => {
        // This test uses redis-cli SHUTDOWN SAVE, which is a graceful
        // shutdown that triggers a final RDB save before exiting. It
        // establishes that sessions survive a planned maintenance restart,
        // NOT that they survive an abrupt process failure or power loss.
        const dataDir = makeTmpDir();
        const port = await findFreePort();
        const containerName = `ninsho-persist-opaque-${generateId().slice(0, 8)}`;
        const url = `redis://127.0.0.1:${port}`;

        try {
          startRedis(port, dataDir, containerName);
          await waitForRedis(url);

          // Build harness and create sessions.
          let h = buildOpaque(url);
          const user = principal();

          const activeSession = await h.sessions.create(user);
          const toRevoke = await h.sessions.create(user);

          // Verify both work before restart.
          await expect(h.engine.verify(activeSession.accessToken)).resolves.toBeDefined();
          await expect(h.engine.verify(toRevoke.accessToken)).resolves.toBeDefined();

          // Revoke one session.
          const revokedCtx = await h.engine.verify(toRevoke.accessToken);
          await h.sessions.revoke(revokedCtx.sessionId, 'logout');

          // Verify revoked session is now rejected.
          await expect(h.engine.verify(toRevoke.accessToken)).rejects.toThrow();

          // Wait for RDB persistence (save configured as "1 second if 1+ key changed").
          await new Promise((r) => setTimeout(r, 2500));

          // Close existing connections before stopping Redis.
          await h.store.close();
          openStores.splice(openStores.indexOf(h.store), 1);

          // Graceful restart.
          stopRedisGracefully(containerName);
          restartRedis(port, dataDir, containerName);
          await waitForRedis(url);

          // Reconnect with a fresh store and engine.
          h = buildOpaque(url);

          // Active session must still verify after restart.
          const restored = await h.engine.verify(activeSession.accessToken);
          expect(restored.userId).toBe(user.userId);

          // Revoked session must still be rejected after restart.
          await expect(h.engine.verify(toRevoke.accessToken)).rejects.toThrow();

          // Refresh rotation must still work for the active session.
          await expect(h.sessions.refresh(activeSession.refreshToken)).resolves.toBeDefined();
        } finally {
          cleanup();
        }
      }, 60_000);

      it('preserves PASETO sessions and revocation denylist entries across a graceful restart', async () => {
        const dataDir = makeTmpDir();
        const port = await findFreePort();
        const containerName = `ninsho-persist-paseto-${generateId().slice(0, 8)}`;
        const url = `redis://127.0.0.1:${port}`;

        try {
          startRedis(port, dataDir, containerName);
          await waitForRedis(url);

          let h = buildPaseto(url);
          const user = principal();

          const activeSession = await h.sessions.create(user);
          const toRevoke = await h.sessions.create(user);

          // Verify both work.
          await expect(h.engine.verify(activeSession.accessToken)).resolves.toBeDefined();
          await expect(h.engine.verify(toRevoke.accessToken)).resolves.toBeDefined();

          // Revoke one and verify the denylist blocks it.
          const revokedCtx = await h.engine.verify(toRevoke.accessToken);
          await h.engine.revoke(revokedCtx.tokenId);

          await expect(h.engine.verify(toRevoke.accessToken)).rejects.toBeInstanceOf(
            TokenRevokedError,
          );

          // Wait for RDB persistence.
          await new Promise((r) => setTimeout(r, 2500));

          await h.store.close();
          openStores.splice(openStores.indexOf(h.store), 1);

          // Graceful restart.
          stopRedisGracefully(containerName);
          restartRedis(port, dataDir, containerName);
          await waitForRedis(url);

          h = buildPaseto(url);

          // Active session must still verify.
          const restored = await h.engine.verify(activeSession.accessToken);
          expect(restored.userId).toBe(user.userId);

          // Revoked token must still be rejected — the denylist survived.
          await expect(h.engine.verify(toRevoke.accessToken)).rejects.toBeInstanceOf(
            TokenRevokedError,
          );
        } finally {
          cleanup();
        }
      }, 60_000);
    });

    // ── Scenario 2: Temporary Redis unavailability ────────────────────
    //
    // Existing coverage in store-invariants.test.ts › "fail-closed when
    // Redis is unreachable" already verifies:
    //   - Rate limiter fails closed with StoreUnavailableError
    //   - DPoP replay guard fails closed
    //   - ping() returns false rather than throwing
    //
    // This test adds the missing regression: that the *engine itself* —
    // not just components built on it — fails closed during an outage
    // and recovers when Redis returns.
    describe('temporary Redis unavailability and recovery', () => {
      it('opaque engine fails closed during outage and recovers when Redis returns', async () => {
        const dataDir = makeTmpDir();
        const port = await findFreePort();
        const containerName = `ninsho-outage-opaque-${generateId().slice(0, 8)}`;
        const url = `redis://127.0.0.1:${port}`;

        try {
          startRedis(port, dataDir, containerName);
          await waitForRedis(url);

          const h = buildOpaque(url);
          const user = principal();
          const session = await h.sessions.create(user);

          // Verify works while Redis is up.
          await expect(h.engine.verify(session.accessToken)).resolves.toBeDefined();

          // Wait for RDB persistence then stop Redis.
          await new Promise((r) => setTimeout(r, 2500));
          stopRedisGracefully(containerName);

          // Engine must fail closed — the store is the token's meaning,
          // and without it the caller cannot be identified at all.
          // Allow a brief settle for the ioredis reconnection to detect the loss.
          await new Promise((r) => setTimeout(r, 500));
          await expect(h.engine.verify(session.accessToken)).rejects.toThrow();

          // Restart Redis with same data.
          restartRedis(port, dataDir, containerName);
          await waitForRedis(url);

          // Must need a fresh store because the old ioredis client's
          // enableOfflineQueue: false means commands during outage rejected.
          // But ioredis with retry *should* reconnect. Let's give it time.
          await new Promise((r) => setTimeout(r, 2000));

          // Build a fresh connection to verify recovery.
          const h2 = buildOpaque(url);
          const restored = await h2.engine.verify(session.accessToken);
          expect(restored.userId).toBe(user.userId);
        } finally {
          cleanup();
        }
      }, 60_000);

      it('PASETO engine fails closed during outage when onStoreError is closed', async () => {
        // PASETO can verify the signature locally, but the default
        // fail-closed policy means the revocation check must also pass.
        // A store outage during the revocation check must result in
        // StoreUnavailableError, not silent admission.
        const dataDir = makeTmpDir();
        const port = await findFreePort();
        const containerName = `ninsho-outage-paseto-${generateId().slice(0, 8)}`;
        const url = `redis://127.0.0.1:${port}`;

        try {
          startRedis(port, dataDir, containerName);
          await waitForRedis(url);

          const h = buildPaseto(url);
          const user = principal();
          const session = await h.sessions.create(user);

          await expect(h.engine.verify(session.accessToken)).resolves.toBeDefined();

          await new Promise((r) => setTimeout(r, 2500));
          stopRedisGracefully(containerName);
          await new Promise((r) => setTimeout(r, 500));

          // The signature verifies locally, but the revocation check
          // hits the store. Under fail-closed it must throw
          // StoreUnavailableError rather than admitting the request.
          await expect(h.engine.verify(session.accessToken)).rejects.toBeInstanceOf(
            StoreUnavailableError,
          );

          // Restart and verify recovery with a fresh connection.
          restartRedis(port, dataDir, containerName);
          await waitForRedis(url);

          const h2 = buildPaseto(url);
          const restored = await h2.engine.verify(session.accessToken);
          expect(restored.userId).toBe(user.userId);
        } finally {
          cleanup();
        }
      }, 60_000);
    });

    // ── Scenario 3: Complete data loss ────────────────────────────────
    describe('complete data loss (Redis restarted without persistence data)', () => {
      it('opaque: all sessions fail closed — the store IS the token, and without it nothing verifies', async () => {
        // Under the opaque strategy, every access token is an opaque
        // random string whose meaning lives entirely in the store. If
        // the store is wiped, every token becomes "never existed" and
        // verification fails with TokenInvalidError. This is the
        // correct, fail-closed outcome.
        const dataDir = makeTmpDir();
        const port = await findFreePort();
        const containerName = `ninsho-dataloss-opaque-${generateId().slice(0, 8)}`;
        const url = `redis://127.0.0.1:${port}`;

        try {
          startRedis(port, dataDir, containerName);
          await waitForRedis(url);

          let h = buildOpaque(url);
          const user = principal();
          const session = await h.sessions.create(user);

          await expect(h.engine.verify(session.accessToken)).resolves.toBeDefined();

          await h.store.close();
          openStores.splice(openStores.indexOf(h.store), 1);
          stopRedisAbruptly(containerName);

          // Restart with a FRESH data directory — all data is gone.
          const freshDir = makeTmpDir();
          restartRedis(port, freshDir, containerName);
          await waitForRedis(url);

          h = buildOpaque(url);

          // Every opaque token must now fail: the store has no record.
          // This is fail-closed — the correct security outcome.
          await expect(h.engine.verify(session.accessToken)).rejects.toBeInstanceOf(
            TokenInvalidError,
          );

          // Refresh must also fail.
          await expect(h.sessions.refresh(session.refreshToken)).rejects.toThrow();
        } finally {
          cleanup();
        }
      }, 60_000);

      it('PASETO: previously revoked tokens become usable again — a documented, unresolved limitation', async () => {
        // SECURITY DOCUMENTATION TEST.
        //
        // Under the PASETO strategy, access tokens are cryptographically
        // signed and carry their own claims and expiry. The store holds
        // only the revocation denylist. If the store is wiped:
        //
        //   - Unrevoked tokens continue to verify because the signature
        //     and claims are self-contained.
        //   - PREVIOUSLY REVOKED tokens also verify, because the denylist
        //     entries that blocked them are gone.
        //
        // This test ASSERTS THE DANGEROUS OUTCOME rather than hiding it.
        // It is not a passing security claim; it is a documented fact
        // about the PASETO strategy's failure mode.
        //
        // Mitigation: use strategy: 'opaque' when complete data loss
        // must fail closed, or ensure continuous Redis persistence (AOF
        // with fsync=always or fsync=everysec) so denylist entries
        // survive restarts.
        const dataDir = makeTmpDir();
        const port = await findFreePort();
        const containerName = `ninsho-dataloss-paseto-${generateId().slice(0, 8)}`;
        const url = `redis://127.0.0.1:${port}`;

        try {
          startRedis(port, dataDir, containerName);
          await waitForRedis(url);

          let h = buildPaseto(url);
          const user = principal();
          const activeSession = await h.sessions.create(user);
          const revokedSession = await h.sessions.create(user);

          // Revoke one token.
          const revokedCtx = await h.engine.verify(revokedSession.accessToken);
          await h.engine.revoke(revokedCtx.tokenId);

          // Confirm it is rejected before data loss.
          await expect(h.engine.verify(revokedSession.accessToken)).rejects.toBeInstanceOf(
            TokenRevokedError,
          );
          // And the active one still works.
          await expect(h.engine.verify(activeSession.accessToken)).resolves.toBeDefined();

          await h.store.close();
          openStores.splice(openStores.indexOf(h.store), 1);
          stopRedisAbruptly(containerName);

          // Restart with a FRESH data directory — denylist is gone.
          const freshDir = makeTmpDir();
          restartRedis(port, freshDir, containerName);
          await waitForRedis(url);

          h = buildPaseto(url);

          // The active token still works — signature and claims are
          // self-contained and the denylist lookup finds no entry.
          const restored = await h.engine.verify(activeSession.accessToken);
          expect(restored.userId).toBe(user.userId);

          // THE DANGEROUS OUTCOME: the previously revoked token ALSO
          // verifies, because its denylist entry was lost.
          // This is the PASETO revocation-loss limitation.
          const dangerouslyRestored = await h.engine.verify(revokedSession.accessToken);
          expect(dangerouslyRestored.userId).toBe(user.userId);
          expect(dangerouslyRestored.tokenId).toBe(revokedCtx.tokenId);
        } finally {
          cleanup();
        }
      }, 60_000);
    });

    // ── Scenario 5: Snapshot rollback ─────────────────────────────────
    describe('snapshot rollback', () => {
      it('restoring an older RDB snapshot discards revocations that occurred after it, resurrecting PASETO tokens', async () => {
        // Snapshot rollback is the operational equivalent of partial data
        // loss: restoring from a backup means discarding everything that
        // happened after the backup was taken. For PASETO, this includes
        // revocation denylist entries.
        const dataDir = makeTmpDir();
        const port = await findFreePort();
        const containerName = `ninsho-rollback-${generateId().slice(0, 8)}`;
        const url = `redis://127.0.0.1:${port}`;

        try {
          startRedis(port, dataDir, containerName);
          await waitForRedis(url);

          let h = buildPaseto(url);
          const user = principal();

          // Phase 1: create sessions, wait for RDB snapshot.
          const sessionA = await h.sessions.create(user);
          const sessionB = await h.sessions.create(user);

          await expect(h.engine.verify(sessionA.accessToken)).resolves.toBeDefined();
          await expect(h.engine.verify(sessionB.accessToken)).resolves.toBeDefined();

          // Wait for the aggressive 1-second save policy to trigger.
          await new Promise((r) => setTimeout(r, 2500));

          // Trigger a manual BGSAVE to ensure we have a snapshot.
          execSync(`docker exec ${containerName} redis-cli BGSAVE`, {
            stdio: 'pipe',
            timeout: 5000,
          });
          await new Promise((r) => setTimeout(r, 1500));

          // Copy the snapshot as our "backup".
          const backupDir = makeTmpDir();
          execSync(
            `docker cp ${containerName}:/data/dump.rdb "${backupDir.replace(/\\/g, '/')}/dump.rdb"`,
            { stdio: 'pipe', timeout: 10_000 },
          );

          // Phase 2: revoke session B AFTER the snapshot.
          const ctxB = await h.engine.verify(sessionB.accessToken);
          await h.engine.revoke(ctxB.tokenId);
          await expect(h.engine.verify(sessionB.accessToken)).rejects.toBeInstanceOf(
            TokenRevokedError,
          );

          // Phase 3: "restore" from the older snapshot.
          await h.store.close();
          openStores.splice(openStores.indexOf(h.store), 1);
          stopRedisAbruptly(containerName);

          // Restart with the backup data (pre-revocation snapshot).
          restartRedis(port, backupDir, containerName);
          await waitForRedis(url);

          h = buildPaseto(url);

          // Session A should still work.
          await expect(h.engine.verify(sessionA.accessToken)).resolves.toBeDefined();

          // Session B's revocation was AFTER the snapshot — the denylist
          // entry does not exist in the restored data. The token
          // verifies again. This is the snapshot-rollback limitation.
          const rolledBack = await h.engine.verify(sessionB.accessToken);
          expect(rolledBack.userId).toBe(user.userId);
        } finally {
          cleanup();
        }
      }, 90_000);
    });
  },
);

// ─── Skip message when Docker is not available ────────────────────────────

if (!dockerAvailable) {
  describe('Redis persistence and recovery (Docker-managed instances)', () => {
    it.skip('Docker daemon is not running — persistence tests require Docker to manage isolated Redis instances', () => {
      // This test suite requires Docker to start and stop disposable Redis
      // instances with controlled persistence settings. It is designed to
      // be run in CI (where Docker is available) or locally with Docker
      // Desktop running.
      //
      // To run locally:
      //   1. Start Docker Desktop
      //   2. npm run test --workspace @ninshorg/server -- -t "Redis persistence"
    });
  });
}
