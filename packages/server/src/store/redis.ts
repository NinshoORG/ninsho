import { Redis, type RedisOptions } from 'ioredis';
import type { NinshoStore } from './types.js';

/** Options for {@link RedisStore}. */
export interface RedisStoreOptions {
  /**
   * Called on ioredis `error` events — failed connection attempts and
   * transport errors. Individual command promises still reject regardless.
   *
   * A handler is always attached (a no-op by default) because an unhandled
   * `error` event on an EventEmitter crashes the Node process. An
   * authentication library must not be able to take a host down because Redis
   * blipped.
   */
  onError?: (error: Error) => void;

  /**
   * Extra ioredis options, merged over the defaults below.
   * `enableOfflineQueue` is forced to `false` and cannot be overridden.
   */
  redisOptions?: Omit<RedisOptions, 'enableOfflineQueue'>;
}

/** How long to wait for the first connection before failing. */
const INITIAL_CONNECT_TIMEOUT_MS = 10_000;

/**
 * Redis-backed store. The production implementation.
 *
 * Requires **Redis 6.2 or later** for `GETDEL`, which is what makes `take()`
 * atomic. Without atomicity there, two concurrent requests presenting the same
 * single-use credential could both succeed — precisely the race that
 * refresh-token rotation must not lose.
 *
 * ─── Failure posture ──────────────────────────────────────────────────────
 * `enableOfflineQueue` is forced off, so once the initial connection has been
 * made, commands issued during an outage reject immediately rather than
 * queueing until a timeout. Rejections propagate to the engine, which applies
 * the configured failure mode — `closed` by default.
 *
 * This matters because the alternative is worse than it looks: a queued
 * command that resolves thirty seconds later has already had its HTTP request
 * time out, and a revocation check that never returns is indistinguishable, to
 * a bad implementation, from one that returned "not revoked".
 * ──────────────────────────────────────────────────────────────────────────
 */
export class RedisStore implements NinshoStore {
  readonly #client: Redis;
  /** Resolves when the first connection succeeds; rejects if it never does. */
  readonly #ready: Promise<void>;
  #closed = false;

  constructor(url: string, options: RedisStoreOptions = {}) {
    const redisOptions: RedisOptions = {
      maxRetriesPerRequest: 2,
      retryStrategy: (attempt) => (attempt > 5 ? null : Math.min(attempt * 200, 3000)),
      ...options.redisOptions,
      // Not overridable: fail fast rather than queue during an outage.
      enableOfflineQueue: false,
    };

    this.#client = new Redis(url, redisOptions);
    this.#client.on('error', options.onError ?? (() => {}));
    this.#ready = this.#awaitInitialConnection();
    // Attach a rejection handler immediately so a failed initial connection
    // never surfaces as an unhandled rejection when no command is in flight.
    // Callers awaiting a command still receive the rejection.
    this.#ready.catch(() => {});
  }

  /**
   * Commands issued before the first `ready` event would fail against an
   * empty offline queue, so the first command awaits this instead. Once
   * resolved it stays resolved, which preserves fail-fast behaviour for later
   * outages — this gate is about startup, not about masking downtime.
   */
  #awaitInitialConnection(): Promise<void> {
    if (this.#client.status === 'ready') return Promise.resolve();

    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error('Ninsho: timed out waiting for the initial Redis connection'));
      }, INITIAL_CONNECT_TIMEOUT_MS);

      const onReady = (): void => {
        cleanup();
        resolve();
      };
      // 'end' fires once ioredis stops retrying — the initial connection has
      // definitively failed rather than merely being slow.
      const onEnd = (): void => {
        cleanup();
        reject(new Error('Ninsho: initial Redis connection failed — Redis is unreachable'));
      };
      const cleanup = (): void => {
        clearTimeout(timer);
        this.#client.off('ready', onReady);
        this.#client.off('end', onEnd);
      };

      this.#client.once('ready', onReady);
      this.#client.once('end', onEnd);
    });
  }

  async #withClient<T>(run: (client: Redis) => Promise<T>): Promise<T> {
    if (this.#closed) throw new Error('RedisStore has been closed');
    await this.#ready;
    return run(this.#client);
  }

  async get(key: string): Promise<string | null> {
    return this.#withClient((c) => c.get(key));
  }

  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    await this.#withClient(async (c) => {
      if (ttlSeconds === undefined) {
        await c.set(key, value);
        return;
      }
      // A non-positive TTL means already expired. Redis rejects `EX 0`, and
      // storing without expiry would leak the key forever — delete instead.
      if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
        await c.del(key);
        return;
      }
      await c.set(key, value, 'EX', Math.ceil(ttlSeconds));
    });
  }

  async setIfAbsent(key: string, value: string, ttlSeconds?: number): Promise<boolean> {
    return this.#withClient(async (c) => {
      if (ttlSeconds === undefined) {
        return (await c.set(key, value, 'NX')) === 'OK';
      }
      if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) return false;
      // SET NX EX is a single atomic command — never SETNX followed by EXPIRE,
      // which can leave a key with no expiry if the process dies between them.
      return (await c.set(key, value, 'EX', Math.ceil(ttlSeconds), 'NX')) === 'OK';
    });
  }

  async take(key: string): Promise<string | null> {
    // GETDEL is atomic; a GET followed by DEL is not, and would let two
    // concurrent callers both observe the value before either deleted it.
    return this.#withClient((c) => c.getdel(key));
  }

  async increment(key: string, ttlSeconds: number): Promise<number> {
    return this.#withClient(async (c) => {
      if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) return 0;

      // INCR and EXPIRE travel in one pipeline. They are not atomic with
      // respect to each other, but the failure mode is benign: the window
      // boundary lives in the key name, so a refreshed TTL cannot extend a
      // window — it only delays cleanup. INCR itself is atomic, which is the
      // property the limiter actually depends on.
      const result = await c
        .multi()
        .incr(key)
        .expire(key, Math.ceil(ttlSeconds))
        .exec();

      const count = result?.[0]?.[1];
      return typeof count === 'number' ? count : 0;
    });
  }

  async delete(...keys: string[]): Promise<void> {
    if (keys.length === 0) return;
    await this.#withClient((c) => c.del(...keys));
  }

  async exists(key: string): Promise<boolean> {
    return this.#withClient(async (c) => (await c.exists(key)) === 1);
  }

  async sAdd(key: string, member: string, ttlSeconds?: number): Promise<void> {
    await this.#withClient(async (c) => {
      if (ttlSeconds !== undefined && (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0)) {
        return;
      }
      if (ttlSeconds === undefined) {
        await c.sadd(key, member);
        return;
      }
      // Pipelined so both land in one round trip. They are not atomic with
      // respect to each other, but the failure mode is benign: a set that
      // briefly lacks an expiry, corrected by the next sAdd. The inverse
      // ordering — EXPIRE before SADD — would be wrong, since EXPIRE on a
      // missing key is a no-op and the set would then never expire.
      await c
        .multi()
        .sadd(key, member)
        .expire(key, Math.ceil(ttlSeconds))
        .exec();
    });
  }

  async sRemove(key: string, ...members: string[]): Promise<void> {
    if (members.length === 0) return;
    await this.#withClient((c) => c.srem(key, ...members));
  }

  async sMembers(key: string): Promise<readonly string[]> {
    return this.#withClient((c) => c.smembers(key));
  }

  async ping(): Promise<boolean> {
    try {
      return await this.#withClient(async (c) => (await c.ping()) === 'PONG');
    } catch {
      // Deliberately swallowed: this is a liveness probe, and a health check
      // that throws is harder to use than one that reports false.
      return false;
    }
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    this.#client.disconnect();
  }
}
