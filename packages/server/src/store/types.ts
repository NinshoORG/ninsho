/**
 * The storage seam.
 *
 * ─── Why this interface exists ────────────────────────────────────────────
 * The predecessor hard-coded its Redis client and then, inside the client's
 * constructor, branched on `process.env.USE_REDIS_MOCK` to substitute an
 * in-memory test double. That double was bundled into the published artifact,
 * so a single environment variable in production replaced every security
 * guarantee — revocation, session state, rate limiting — with a per-process
 * fake, while the API kept returning 200.
 *
 * Ninsho has no such branch and cannot grow one: the store arrives through the
 * constructor, so selecting an implementation is a visible act in application
 * code rather than an ambient environment decision. CI fails the build if a
 * test double or an env kill-switch appears in `dist/`.
 * ──────────────────────────────────────────────────────────────────────────
 *
 * The interface is deliberately narrow. Every method maps to a primitive
 * operation that any reasonable key-value store can provide, and the two
 * atomic operations (`setIfAbsent`, `take`) are the only concurrency
 * primitives the engine needs — which keeps refresh-token rotation
 * implementable without a Redis-specific escape hatch such as raw Lua.
 *
 * Implementations must:
 *   - treat all keys as opaque strings
 *   - honour TTLs in whole seconds, expiring entries no later than requested
 *   - throw on transport failure rather than returning a falsy value, so the
 *     configured failure mode decides what happens rather than the engine
 *     silently reading a miss as "not revoked"
 */
export interface NinshoStore {
  /** Returns the stored value, or `null` if absent or expired. */
  get(key: string): Promise<string | null>;

  /**
   * Stores a value, overwriting any existing one.
   * @param ttlSeconds - Whole seconds until expiry. Omit for no expiry.
   *   Values <= 0 are treated as already expired and the key is removed,
   *   never stored without expiry — a negative TTL silently becoming
   *   "permanent" is how revocation entries leak forever.
   */
  set(key: string, value: string, ttlSeconds?: number): Promise<void>;

  /**
   * Stores a value only if the key is absent. Atomic.
   * @returns `true` if this call stored the value, `false` if it already existed.
   */
  setIfAbsent(key: string, value: string, ttlSeconds?: number): Promise<boolean>;

  /**
   * Atomically reads and deletes a key.
   * @returns The value if it existed, otherwise `null`.
   *
   * The atomicity matters: it is what makes single-use credential consumption
   * race-free, so two concurrent requests presenting the same one-time value
   * cannot both succeed.
   */
  take(key: string): Promise<string | null>;

  /**
   * Atomically increments the integer at `key`, creating it at 0 first.
   * @returns The value after incrementing. The first call returns 1.
   *
   * The TTL is refreshed on every call, which is safe here *because callers
   * put the window boundary in the key name* rather than relying on expiry to
   * end a window. The TTL is garbage collection, not policy — a counter whose
   * window is defined by its key cannot be extended by touching it.
   *
   * Must be atomic: two concurrent callers must never receive the same value,
   * or a rate limit becomes a suggestion under exactly the concurrent load it
   * exists to control.
   */
  increment(key: string, ttlSeconds: number): Promise<number>;

  /** Removes keys. Absent keys are ignored. No-op when given no keys. */
  delete(...keys: string[]): Promise<void>;

  /** Whether a key is present and unexpired. */
  exists(key: string): Promise<boolean>;

  /**
   * Adds a member to the set at `key`.
   * @param ttlSeconds - Expiry for the whole set. Applied on every add so an
   *   active set does not expire underneath its members.
   */
  sAdd(key: string, member: string, ttlSeconds?: number): Promise<void>;

  /** Removes members from the set at `key`. No-op when given no members. */
  sRemove(key: string, ...members: string[]): Promise<void>;

  /** All members of the set at `key`. Empty array when absent. Order is not guaranteed. */
  sMembers(key: string): Promise<readonly string[]>;

  /** Liveness probe. Returns `false` rather than throwing when unreachable. */
  ping(): Promise<boolean>;

  /** Releases connections. Safe to call more than once. */
  close(): Promise<void>;
}
