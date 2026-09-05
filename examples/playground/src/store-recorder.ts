import type { NinshoStore } from '@ninsho/server';

/**
 * A store that records every operation performed through it.
 *
 * ─── Why the playground needs this ────────────────────────────────────────
 * The interesting claims Ninsho makes are about what reaches the store: that a
 * raw token never does, that rotation consumes atomically, that a revocation
 * writes a tombstone before it enumerates. Those are invisible from the
 * outside — you get a token back either way.
 *
 * So this wraps a real store and keeps a log. The playground shows the log,
 * which turns "the raw token is never stored" from a claim in a README into
 * something a visitor can read off the screen and check for themselves.
 *
 * It is a demonstration aid and lives in an example. It is emphatically not
 * something to run in production: it retains every value that passes through
 * it, which for a session store means retaining credentials in memory.
 * ──────────────────────────────────────────────────────────────────────────
 */

export interface StoreOperation {
  readonly seq: number;
  readonly at: number;
  readonly op: string;
  readonly key: string;
  /** The stored or returned value, when the operation has one. */
  readonly value?: string | null;
  readonly ttlSeconds?: number;
  /** For `take` and `setIfAbsent`, whether this caller won. */
  readonly outcome?: string;
}

export class RecordingStore implements NinshoStore {
  readonly #inner: NinshoStore;
  #log: StoreOperation[] = [];
  #seq = 0;
  /** Every key ever touched, so the keyspace view can probe for live ones. */
  readonly #seen = new Set<string>();

  constructor(inner: NinshoStore) {
    this.#inner = inner;
  }

  /** Everything that has happened since the last `clearLog()`. */
  get log(): readonly StoreOperation[] {
    return this.#log;
  }

  clearLog(): void {
    this.#log = [];
  }

  /**
   * The keys currently holding a value.
   *
   * Rebuilt by probing every key this recorder has ever touched, rather than
   * by reading the store's internals — so an entry that has expired drops out
   * on its own, and the view stays honest about what is actually live.
   *
   * The probes are deliberately not recorded; logging the inspector's own
   * reads would drown the operations a visitor came to look at.
   */
  async keyspace(): Promise<{ key: string; value: string }[]> {
    const live: { key: string; value: string }[] = [];

    for (const key of this.#seen) {
      const value = await this.#inner.get(key);
      if (value !== null) {
        live.push({ key, value });
        continue;
      }
      // Sets do not answer `get`, so a key that looks empty may still be one.
      const members = await this.#inner.sMembers(key);
      if (members.length > 0) live.push({ key, value: `set: [${members.join(', ')}]` });
    }

    return live.sort((a, b) => a.key.localeCompare(b.key));
  }

  #record(entry: Omit<StoreOperation, 'seq' | 'at'>): void {
    this.#seen.add(entry.key);
    this.#seq += 1;
    this.#log.push({ seq: this.#seq, at: Date.now(), ...entry });
    // Bounded so a long-running playground cannot grow without limit.
    if (this.#log.length > 500) this.#log.shift();
  }

  async get(key: string): Promise<string | null> {
    const value = await this.#inner.get(key);
    this.#record({ op: 'get', key, value, outcome: value === null ? 'miss' : 'hit' });
    return value;
  }

  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    await this.#inner.set(key, value, ttlSeconds);
    this.#record({ op: 'set', key, value, ...(ttlSeconds !== undefined && { ttlSeconds }) });
  }

  async setIfAbsent(key: string, value: string, ttlSeconds?: number): Promise<boolean> {
    const stored = await this.#inner.setIfAbsent(key, value, ttlSeconds);
    this.#record({
      op: 'setIfAbsent',
      key,
      value,
      ...(ttlSeconds !== undefined && { ttlSeconds }),
      outcome: stored ? 'stored' : 'already existed',
    });
    return stored;
  }

  async take(key: string): Promise<string | null> {
    const value = await this.#inner.take(key);
    // The atomic one. Two concurrent callers cannot both see a value here, and
    // that is what makes rotation and single-use links race-free.
    this.#record({ op: 'take (atomic)', key, value, outcome: value === null ? 'lost the race or absent' : 'won' });
    return value;
  }

  async increment(key: string, ttlSeconds: number): Promise<number> {
    const value = await this.#inner.increment(key, ttlSeconds);
    this.#record({ op: 'increment (atomic)', key, value: String(value), ttlSeconds });
    return value;
  }

  async delete(...keys: string[]): Promise<void> {
    await this.#inner.delete(...keys);
    for (const key of keys) this.#record({ op: 'delete', key });
  }

  async exists(key: string): Promise<boolean> {
    const present = await this.#inner.exists(key);
    this.#record({ op: 'exists', key, outcome: String(present) });
    return present;
  }

  async sAdd(key: string, member: string, ttlSeconds?: number): Promise<void> {
    await this.#inner.sAdd(key, member, ttlSeconds);
    this.#record({ op: 'sAdd', key, value: member, ...(ttlSeconds !== undefined && { ttlSeconds }) });
  }

  async sRemove(key: string, ...members: string[]): Promise<void> {
    await this.#inner.sRemove(key, ...members);
    this.#record({ op: 'sRemove', key, value: members.join(', ') });
  }

  async sMembers(key: string): Promise<readonly string[]> {
    const members = await this.#inner.sMembers(key);
    this.#record({ op: 'sMembers', key, value: `${members.length} member(s)` });
    return members;
  }

  async ping(): Promise<boolean> {
    return this.#inner.ping();
  }

  async close(): Promise<void> {
    return this.#inner.close();
  }
}
