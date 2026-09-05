/**
 * Per-visitor isolation.
 *
 * ─── Why the playground needs it ──────────────────────────────────────────
 * The first version kept one world for everyone. That is fine on a laptop and
 * wrong the moment two people open the page: one visitor's "create session"
 * would appear in another's store trace, and the replay demonstration would
 * revoke a session someone else was midway through.
 *
 * Worse, it would misrepresent the library. A visitor seeing keys they did not
 * create would reasonably conclude that Ninsho leaks state between callers,
 * when what leaked was the demo's own shared variable.
 *
 * So each visitor gets their own store, their own audit sink, and their own
 * Ninsho. A cookie identifies them; it is an opaque random id and carries
 * nothing else.
 *
 * ─── The bounds ───────────────────────────────────────────────────────────
 * Anyone can open the page, so the number of worlds is capped and idle ones
 * are evicted. Without that, a public deployment is a memory leak with a URL —
 * which would be an unfortunate thing for a security demo to be.
 * ──────────────────────────────────────────────────────────────────────────
 */

import { randomUUID } from 'node:crypto';
import type { Request, Response } from 'express';

/** How many visitors may hold state at once. */
const MAX_WORLDS = 200;

/** How long an untouched world survives. */
const IDLE_MS = 30 * 60 * 1000;

const COOKIE = 'ninsho_playground';

/** Anything the playground keeps for one visitor. */
export interface Disposable {
  close(): Promise<void>;
}

export interface VisitorRegistryOptions<T extends Disposable> {
  readonly create: () => T;
  readonly maxWorlds?: number;
  readonly idleMs?: number;
}

interface Entry<T> {
  value: T;
  touchedAt: number;
}

/**
 * Keeps one world per visitor, bounded and swept.
 *
 * Written generically over what a world *is* so the registry can be tested
 * against a trivial stand-in rather than only through the HTTP surface.
 */
export class VisitorRegistry<T extends Disposable> {
  readonly #entries = new Map<string, Entry<T>>();
  readonly #create: () => T;
  readonly #max: number;
  readonly #idleMs: number;

  constructor(options: VisitorRegistryOptions<T>) {
    this.#create = options.create;
    this.#max = options.maxWorlds ?? MAX_WORLDS;
    this.#idleMs = options.idleMs ?? IDLE_MS;
  }

  get size(): number {
    return this.#entries.size;
  }

  /**
   * Reads the visitor's id from the request, minting one when absent.
   *
   * The cookie is `httpOnly` and `sameSite: 'lax'` — it identifies a
   * playground world and nothing else, but there is no reason for a script to
   * read it, and a demo that models the careless option would be teaching the
   * wrong habit.
   */
  identify(req: Request, res: Response): string {
    const existing = readCookie(req, COOKIE);
    if (existing !== undefined && /^[A-Za-z0-9-]{8,64}$/.test(existing)) return existing;

    const id = randomUUID();
    res.cookie(COOKIE, id, {
      httpOnly: true,
      sameSite: 'lax',
      secure: req.protocol === 'https',
      maxAge: IDLE_MS,
      path: '/',
    });
    return id;
  }

  /** The visitor's world, created on first use. */
  async get(id: string): Promise<T> {
    await this.#sweep();

    const entry = this.#entries.get(id);
    if (entry !== undefined) {
      entry.touchedAt = Date.now();
      return entry.value;
    }

    // Evict the least recently used rather than refusing: a visitor who
    // arrives to a "come back later" page has learned nothing about Ninsho.
    if (this.#entries.size >= this.#max) {
      const oldest = [...this.#entries.entries()].sort(
        (a, b) => a[1].touchedAt - b[1].touchedAt,
      )[0];
      if (oldest !== undefined) {
        await oldest[1].value.close();
        this.#entries.delete(oldest[0]);
      }
    }

    const value = this.#create();
    this.#entries.set(id, { value, touchedAt: Date.now() });
    return value;
  }

  /** Discards a visitor's world, so the next request starts clean. */
  async reset(id: string): Promise<void> {
    const entry = this.#entries.get(id);
    if (entry === undefined) return;
    await entry.value.close();
    this.#entries.delete(id);
  }

  /** Releases everything. Used when shutting down, and by the tests. */
  async clear(): Promise<void> {
    for (const entry of this.#entries.values()) await entry.value.close();
    this.#entries.clear();
  }

  /** Drops worlds nobody has touched recently. */
  async #sweep(): Promise<void> {
    const cutoff = Date.now() - this.#idleMs;
    for (const [id, entry] of this.#entries) {
      if (entry.touchedAt < cutoff) {
        await entry.value.close();
        this.#entries.delete(id);
      }
    }
  }
}

/**
 * Minimal cookie reading, so the playground needs no cookie-parser.
 *
 * Use a real parser in an application; this exists to keep the dependency list
 * to Express alone, matching `examples/express-api`.
 */
export function readCookie(req: Request, name: string): string | undefined {
  const header = req.headers.cookie;
  if (typeof header !== 'string') return undefined;

  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    if (part.slice(0, index).trim() === name) {
      return decodeURIComponent(part.slice(index + 1).trim());
    }
  }
  return undefined;
}
