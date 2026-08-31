import { RateLimitError, StoreUnavailableError, type AuditSink, type FailureMode } from '@ninsho/core';
import type { NinshoStore } from '../store/types.js';
import { KEYS } from '../keys.js';

/** One bucket's verdict. */
export interface BucketVerdict {
  readonly allowed: boolean;
  /** Requests still available in this window, floored at 0. */
  readonly remaining: number;
  /** Seconds until the window has moved far enough to allow another request. */
  readonly retryAfter: number;
}

export interface LimiterOptions {
  readonly store: NinshoStore;
  readonly onStoreError: FailureMode;
  readonly audit: AuditSink;
}

/**
 * Sliding-window counter.
 *
 * ─── Why not a fixed window, and why not a log ────────────────────────────
 * A fixed window permits a burst of 2× the limit across a boundary: spend the
 * whole allowance in the last second of one window, then the whole allowance
 * again in the first second of the next. For a login endpoint that doubling is
 * exactly the moment an attacker aims for.
 *
 * A sliding-window *log* — the predecessor's approach, one sorted-set entry per
 * request — is precise, but stores an entry per request. Under the flood it
 * exists to stop, that memory growth is itself the attack.
 *
 * A sliding-window *counter* keeps two integers per bucket and interpolates
 * between them by how far into the current window the request arrived. Bounded
 * memory, no boundary doubling, and accurate to within a few percent.
 * ──────────────────────────────────────────────────────────────────────────
 */
export class RateLimiter {
  readonly #store: NinshoStore;
  readonly #onStoreError: FailureMode;
  readonly #audit: AuditSink;

  constructor(options: LimiterOptions) {
    this.#store = options.store;
    this.#onStoreError = options.onStoreError;
    this.#audit = options.audit;
  }

  /**
   * Records a request against a bucket and reports whether it is allowed.
   *
   * @param bucket   Opaque bucket identity, e.g. `login:ip:1.2.3.4`.
   * @param limit    Requests permitted per window.
   * @param windowMs Window length in milliseconds.
   *
   * @throws {StoreUnavailableError} When the store is unreachable and
   *   `onStoreError` is `'closed'`.
   */
  async consume(bucket: string, limit: number, windowMs: number): Promise<BucketVerdict> {
    const now = Date.now();
    const windowIndex = Math.floor(now / windowMs);
    const elapsedFraction = (now % windowMs) / windowMs;

    // The window boundary lives in the key name, so a refreshed TTL cannot
    // extend a window. Two windows are retained so the previous one can be
    // weighted; a third window's lifetime gives ample slack for clock skew.
    const ttlSeconds = Math.ceil((windowMs * 3) / 1000);

    const currentKey = KEYS.rateLimit(bucket, windowIndex);
    const previousKey = KEYS.rateLimit(bucket, windowIndex - 1);

    let current: number;
    let previousRaw: string | null;
    try {
      current = await this.#store.increment(currentKey, ttlSeconds);
      previousRaw = await this.#store.get(previousKey);
    } catch (error) {
      return this.#handleStoreFailure(error, limit);
    }

    const previous = previousRaw === null ? 0 : Number.parseInt(previousRaw, 10);
    const weightedPrevious = Number.isFinite(previous)
      ? previous * (1 - elapsedFraction)
      : 0;

    const estimated = weightedPrevious + current;
    const allowed = estimated <= limit;

    return {
      allowed,
      remaining: Math.max(0, Math.floor(limit - estimated)),
      // How long until enough of the previous window ages out. Rounded up so a
      // client that obeys Retry-After is never told to return too early.
      retryAfter: allowed ? 0 : Math.max(1, Math.ceil((windowMs - (now % windowMs)) / 1000)),
    };
  }

  /**
   * Applies the configured failure mode to a store outage.
   *
   * ─── Why fail-closed is the default here too ──────────────────────────────
   * The predecessor's limiter failed open unconditionally and offered no way to
   * change it, so a Redis blip silently removed brute-force protection from the
   * login endpoint.
   *
   * Fail-closed sounds severe — nobody can log in — but the marginal cost is
   * usually zero: the same store backs sessions, so under the default `opaque`
   * strategy an outage has already stopped authentication. Refusing here adds
   * no new downtime, and it means the limiter cannot quietly stop working.
   * ──────────────────────────────────────────────────────────────────────────
   */
  #handleStoreFailure(error: unknown, limit: number): BucketVerdict {
    this.#audit.emit({
      type: 'store.unavailable',
      at: new Date().toISOString(),
      reason:
        this.#onStoreError === 'open'
          ? 'rate_limit_skipped'
          : 'rate_limit_refused',
    });

    if (this.#onStoreError === 'open') {
      return { allowed: true, remaining: limit, retryAfter: 0 };
    }

    throw new StoreUnavailableError(
      `store unreachable during rate limit check: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  /**
   * Consumes several buckets and returns the most restrictive verdict.
   *
   * Every bucket is consumed even when an earlier one has already refused, so
   * counters stay consistent — an attacker must not be able to keep their
   * per-account counter low by ensuring their per-IP counter trips first.
   */
  async consumeAll(
    buckets: ReadonlyArray<{ bucket: string; limit: number; windowMs: number }>,
  ): Promise<BucketVerdict> {
    const verdicts = await Promise.all(
      buckets.map(({ bucket, limit, windowMs }) => this.consume(bucket, limit, windowMs)),
    );

    const refused = verdicts.filter((v) => !v.allowed);
    if (refused.length === 0) {
      return {
        allowed: true,
        remaining: Math.min(...verdicts.map((v) => v.remaining)),
        retryAfter: 0,
      };
    }

    return {
      allowed: false,
      remaining: 0,
      retryAfter: Math.max(...refused.map((v) => v.retryAfter)),
    };
  }

  /** Throws {@link RateLimitError} if any bucket refuses. */
  async enforce(
    buckets: ReadonlyArray<{ bucket: string; limit: number; windowMs: number }>,
  ): Promise<BucketVerdict> {
    const verdict = await this.consumeAll(buckets);
    if (!verdict.allowed) {
      throw new RateLimitError(verdict.retryAfter, `buckets exceeded`);
    }
    return verdict;
  }
}
