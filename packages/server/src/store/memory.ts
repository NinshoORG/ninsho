import { ConfigurationError } from '@ninshorg/core';
import type { NinshoStore } from './types.js';

/**
 * In-process store for tests, local development, and single-instance
 * prototypes.
 *
 * ─── Why this is safe where the predecessor's mock was not ────────────────
 * Two differences, both deliberate.
 *
 * 1. It must be named. There is no environment variable that substitutes this
 *    for a real store. Using it is a visible line of application code that
 *    shows up in review and in `git blame`.
 *
 * 2. It refuses to construct under `NODE_ENV=production`, with no opt-out.
 *
 * The second point deserves a note, because Ninsho otherwise holds that no
 * environment variable may weaken security. Reading `NODE_ENV` here only ever
 * makes the library stricter — the check can add a failure, never remove one.
 * Defeating it means unsetting `NODE_ENV`, which is a deliberate act, and the
 * store is still named explicitly in code either way.
 *
 * There is no `allowInProduction` flag. A deployment that genuinely wants
 * in-memory sessions in production can implement `NinshoStore` itself, which
 * is explicit, auditable, and obviously not a test double.
 * ──────────────────────────────────────────────────────────────────────────
 *
 * State is per-process and lost on restart, so a multi-instance deployment
 * would see each instance disagree about which sessions exist and which
 * tokens are revoked.
 */
export class MemoryStore implements NinshoStore {
  /** Values with their absolute expiry in epoch ms; `null` means no expiry. */
  readonly #values = new Map<string, { value: string; expiresAt: number | null }>();
  readonly #sets = new Map<string, { members: Set<string>; expiresAt: number | null }>();
  #closed = false;

  constructor() {
    if (process.env['NODE_ENV'] === 'production') {
      throw new ConfigurationError(
        'MemoryStore cannot be used in production. Session state would be ' +
          'per-process and lost on restart, so revocation and rate limiting ' +
          'would not work. Use RedisStore, or supply your own NinshoStore.',
      );
    }
  }

  /**
   * Expiry is evaluated lazily on access rather than by a timer.
   *
   * A `setInterval` sweep would keep the Node process alive after the
   * application had finished, which is a genuinely annoying bug to inherit
   * from a library. Lazy eviction means memory is reclaimed on next touch;
   * `sweep()` is available for tests that assert on size.
   */
  #live<T extends { expiresAt: number | null }>(
    map: Map<string, T>,
    key: string,
  ): T | undefined {
    const entry = map.get(key);
    if (entry === undefined) return undefined;
    if (entry.expiresAt !== null && Date.now() >= entry.expiresAt) {
      map.delete(key);
      return undefined;
    }
    return entry;
  }

  /**
   * Converts a TTL to an absolute expiry.
   * Returns `'expired'` for non-positive TTLs so callers delete rather than
   * store — a TTL of 0 or less means the entry is already dead, and storing
   * it without expiry is how a revocation list grows without bound.
   */
  #expiryFor(ttlSeconds: number | undefined): number | null | 'expired' {
    if (ttlSeconds === undefined) return null;
    if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) return 'expired';
    return Date.now() + ttlSeconds * 1000;
  }

  #assertOpen(): void {
    if (this.#closed) {
      throw new Error('MemoryStore has been closed');
    }
  }

  async get(key: string): Promise<string | null> {
    this.#assertOpen();
    return this.#live(this.#values, key)?.value ?? null;
  }

  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    this.#assertOpen();
    const expiresAt = this.#expiryFor(ttlSeconds);
    if (expiresAt === 'expired') {
      this.#values.delete(key);
      return;
    }
    this.#values.set(key, { value, expiresAt });
  }

  async setIfAbsent(key: string, value: string, ttlSeconds?: number): Promise<boolean> {
    this.#assertOpen();
    // Single-threaded execution makes check-then-act atomic here: no await
    // separates the read from the write, so no other task can interleave.
    if (this.#live(this.#values, key) !== undefined) return false;
    const expiresAt = this.#expiryFor(ttlSeconds);
    if (expiresAt === 'expired') return false;
    this.#values.set(key, { value, expiresAt });
    return true;
  }

  async take(key: string): Promise<string | null> {
    this.#assertOpen();
    const entry = this.#live(this.#values, key);
    if (entry === undefined) return null;
    this.#values.delete(key);
    return entry.value;
  }

  async increment(key: string, ttlSeconds: number): Promise<number> {
    this.#assertOpen();
    const expiresAt = this.#expiryFor(ttlSeconds);
    if (expiresAt === 'expired') return 0;

    // No await between read and write, so this is atomic on a single-threaded
    // event loop — the same reasoning as setIfAbsent above.
    const current = this.#live(this.#values, key);
    const next = current === undefined ? 1 : Number.parseInt(current.value, 10) + 1;
    const value = Number.isFinite(next) ? next : 1;

    this.#values.set(key, { value: String(value), expiresAt });
    return value;
  }

  async delete(...keys: string[]): Promise<void> {
    this.#assertOpen();
    for (const key of keys) {
      this.#values.delete(key);
      this.#sets.delete(key);
    }
  }

  async exists(key: string): Promise<boolean> {
    this.#assertOpen();
    return this.#live(this.#values, key) !== undefined;
  }

  async sAdd(key: string, member: string, ttlSeconds?: number): Promise<void> {
    this.#assertOpen();
    const expiresAt = this.#expiryFor(ttlSeconds);
    if (expiresAt === 'expired') return;

    const existing = this.#live(this.#sets, key);
    if (existing === undefined) {
      this.#sets.set(key, { members: new Set([member]), expiresAt });
      return;
    }
    existing.members.add(member);
    // Refresh the set's expiry so an active set does not vanish under its
    // members. Redis EXPIRE has the same effect.
    existing.expiresAt = expiresAt;
  }

  async sRemove(key: string, ...members: string[]): Promise<void> {
    this.#assertOpen();
    if (members.length === 0) return;
    const entry = this.#live(this.#sets, key);
    if (entry === undefined) return;
    for (const member of members) entry.members.delete(member);
    // Match Redis: a set with no members does not exist.
    if (entry.members.size === 0) this.#sets.delete(key);
  }

  async sMembers(key: string): Promise<readonly string[]> {
    this.#assertOpen();
    const entry = this.#live(this.#sets, key);
    return entry === undefined ? [] : [...entry.members];
  }

  async ping(): Promise<boolean> {
    return !this.#closed;
  }

  async close(): Promise<void> {
    this.#closed = true;
    this.#values.clear();
    this.#sets.clear();
  }

  // ── Test affordances ──────────────────────────────────────────────────────
  // Not part of NinshoStore. Present so tests can assert on eviction without
  // reaching into private state.

  /** Drops every expired entry. Returns how many were removed. */
  sweep(): number {
    let removed = 0;
    for (const key of [...this.#values.keys()]) {
      if (this.#live(this.#values, key) === undefined) removed += 1;
    }
    for (const key of [...this.#sets.keys()]) {
      if (this.#live(this.#sets, key) === undefined) removed += 1;
    }
    return removed;
  }

  /** Live entry count, after sweeping. */
  size(): number {
    this.sweep();
    return this.#values.size + this.#sets.size;
  }
}
