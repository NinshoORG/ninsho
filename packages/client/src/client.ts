import { generateDpopKey, type DpopKey } from './keys.js';
import { createProof } from './proof.js';
import { MemoryKeyStore, type DpopKeyStore } from './storage.js';

/**
 * The browser client.
 *
 * ─── What it takes off the application's hands ────────────────────────────
 * Managing a DPoP session by hand means: generate a non-extractable key,
 * persist it somewhere that can hold one, mint a fresh proof for every
 * request with the right method and URI and token hash, notice a 401, refresh
 * without stampeding, retry the original request, and never once put the
 * access token somewhere a script can read it.
 *
 * Getting any of those wrong is silent. This does all of them.
 * ──────────────────────────────────────────────────────────────────────────
 */

export interface NinshoClientOptions {
  /** Base URL of the API. Relative request paths resolve against it. */
  readonly baseUrl: string;
  /**
   * Where the DPoP key is persisted. Defaults to in-memory, which is correct
   * for tests and non-browser clients; a browser should pass an
   * `IndexedDbKeyStore` so the session survives a reload.
   */
  readonly keyStore?: DpopKeyStore;
  /**
   * Path the client posts to when an access token has expired.
   * Default `/auth/refresh`.
   */
  readonly refreshPath?: string;
  /** Injected for tests. Defaults to the global `fetch`. */
  readonly fetch?: typeof globalThis.fetch;
}

/** What a refresh endpoint is expected to return. */
interface RefreshResponse {
  readonly accessToken?: unknown;
}

export class NinshoClient {
  readonly #baseUrl: string;
  readonly #keyStore: DpopKeyStore;
  readonly #refreshPath: string;
  readonly #fetch: typeof globalThis.fetch;

  /**
   * The access token, held **in memory only**.
   *
   * Never `localStorage` or `sessionStorage`: anything a script can read, an
   * XSS can read. Losing it on reload is the intended trade — the refresh
   * token lives in an httpOnly cookie the browser replays on its own, so a
   * reload costs one refresh round trip rather than a sign-in.
   */
  #accessToken: string | null = null;

  /** Cached so a key is generated once, not per request. */
  #key: DpopKey | null = null;

  /**
   * The in-flight refresh, if any.
   *
   * Without this, a page that fires six requests when a token expires gets six
   * 401s and starts six refreshes. Under rotation that is worse than wasteful:
   * five of them present a token another has already rotated, and the server —
   * correctly — reads that as theft and ends the session. Single-flight is what
   * keeps a normal page load from looking like an attack.
   */
  #refreshInFlight: Promise<boolean> | null = null;

  /**
   * The in-flight key initialisation, if any.
   *
   * The same stampede as `#refreshInFlight`, and worse in its consequences.
   * Several requests firing before a key exists would each see none, each
   * generate one, and each write it — last one wins. Requests already in
   * flight would then be signing proofs with keys the store no longer holds,
   * and a session bound to a discarded key is simply broken, with nothing in
   * the logs to explain it.
   */
  #keyInFlight: Promise<DpopKey> | null = null;

  constructor(options: NinshoClientOptions) {
    this.#baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.#keyStore = options.keyStore ?? new MemoryKeyStore();
    this.#refreshPath = options.refreshPath ?? '/auth/refresh';
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /**
   * Returns the DPoP key, creating and persisting one on first use.
   *
   * The same key is reused for the life of the session, which is what lets a
   * token stay bound across refreshes.
   */
  async getKey(): Promise<DpopKey> {
    if (this.#key !== null) return this.#key;
    if (this.#keyInFlight !== null) return this.#keyInFlight;

    const initialise = (async (): Promise<DpopKey> => {
      try {
        const stored = await this.#keyStore.load();
        if (stored !== null) {
          this.#key = stored;
          return stored;
        }

        const fresh = await generateDpopKey();
        await this.#keyStore.save(fresh);
        this.#key = fresh;
        return fresh;
      } finally {
        this.#keyInFlight = null;
      }
    })();

    this.#keyInFlight = initialise;
    return initialise;
  }

  /** The RFC 7638 thumbprint the server binds sessions to. */
  async getThumbprint(): Promise<string> {
    return (await this.getKey()).thumbprint;
  }

  /** The current access token, if a session is established. */
  get accessToken(): string | null {
    return this.#accessToken;
  }

  /** Records the access token returned by a sign-in or refresh. */
  setAccessToken(token: string | null): void {
    this.#accessToken = token;
  }

  /** Whether a session appears to be established. */
  get isAuthenticated(): boolean {
    return this.#accessToken !== null;
  }

  /** Resolves a path against the base URL. Absolute URLs pass through. */
  #resolve(path: string): string {
    return /^https?:\/\//i.test(path) ? path : `${this.#baseUrl}${path.startsWith('/') ? '' : '/'}${path}`;
  }

  /**
   * Performs a request with a fresh DPoP proof, refreshing once on a 401.
   *
   * `credentials: 'include'` is set so the browser sends the httpOnly refresh
   * cookie. It is what makes the refresh below work without the application
   * ever handling the refresh token itself.
   */
  async fetch(path: string, init: RequestInit = {}): Promise<Response> {
    const response = await this.#send(path, init);

    // A 401 on a request that carried a token usually means the token expired.
    // Refresh once and retry; a second 401 is a real refusal, not a stale token.
    if (response.status !== 401 || this.#accessToken === null) {
      return response;
    }

    const refreshed = await this.#refreshOnce();
    if (!refreshed) return response;

    return this.#send(path, init);
  }

  /** One attempt, with a proof minted for exactly this method and URI. */
  async #send(path: string, init: RequestInit): Promise<Response> {
    const url = this.#resolve(path);
    const method = (init.method ?? 'GET').toUpperCase();

    const key = await this.getKey();
    const proof = await createProof(key, {
      method,
      url,
      ...(this.#accessToken !== null && { accessToken: this.#accessToken }),
    });

    const headers = new Headers(init.headers);
    headers.set('DPoP', proof);
    if (this.#accessToken !== null) {
      // RFC 9449 §7.1: a DPoP-bound token is presented with the DPoP scheme.
      headers.set('Authorization', `DPoP ${this.#accessToken}`);
    }

    return this.#fetch(url, { ...init, method, headers, credentials: 'include' });
  }

  /**
   * Refreshes the access token, collapsing concurrent callers into one attempt.
   *
   * Every caller awaits the same promise, so six simultaneous 401s produce one
   * refresh — see the note on `#refreshInFlight` for why that matters more than
   * efficiency.
   */
  async #refreshOnce(): Promise<boolean> {
    if (this.#refreshInFlight !== null) return this.#refreshInFlight;

    const attempt = (async (): Promise<boolean> => {
      try {
        const url = this.#resolve(this.#refreshPath);
        const key = await this.getKey();

        // No `ath`: the expired token is not what is being presented here. The
        // refresh token travels in the cookie.
        const proof = await createProof(key, { method: 'POST', url });

        const response = await this.#fetch(url, {
          method: 'POST',
          headers: { DPoP: proof },
          credentials: 'include',
        });

        if (!response.ok) {
          // The session is over — expired, revoked, or reuse was detected.
          // Clearing the token stops every later request from retrying against
          // a session that no longer exists.
          this.#accessToken = null;
          return false;
        }

        const body = (await response.json()) as RefreshResponse;
        if (typeof body.accessToken !== 'string' || body.accessToken.length === 0) {
          this.#accessToken = null;
          return false;
        }

        this.#accessToken = body.accessToken;
        return true;
      } catch {
        // A network failure is not a signal that the session ended, so the
        // token is left alone for the next attempt.
        return false;
      } finally {
        this.#refreshInFlight = null;
      }
    })();

    this.#refreshInFlight = attempt;
    return attempt;
  }

  /** Refreshes on demand. Rarely needed — `fetch` does it automatically. */
  async refresh(): Promise<boolean> {
    return this.#refreshOnce();
  }

  /**
   * Signs in, binding the new session to this client's key.
   *
   * The proof sent here carries no `ath` — no token exists yet. The server
   * reads the key's thumbprint from it and binds the session to that key, so
   * every later request must come from this browser.
   */
  async signIn(path: string, body: unknown): Promise<Response> {
    const response = await this.#send(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (response.ok) {
      const cloned = response.clone();
      try {
        const parsed = (await cloned.json()) as RefreshResponse;
        if (typeof parsed.accessToken === 'string') {
          this.#accessToken = parsed.accessToken;
        }
      } catch {
        // A sign-in that returns no JSON body is the application's business.
      }
    }
    return response;
  }

  /**
   * Signs out: tells the server, forgets the token, and discards the key.
   *
   * Discarding the key matters. Leaving it behind would mean the next person to
   * use the browser inherits a key that a still-live session elsewhere is bound
   * to — and a shared machine is exactly where sign-out has to be thorough.
   */
  async signOut(path = '/auth/logout'): Promise<Response | null> {
    let response: Response | null = null;
    try {
      if (this.#accessToken !== null) {
        response = await this.#send(path, { method: 'POST' });
      }
    } catch {
      // Local state is cleared regardless: a network failure must not leave a
      // browser believing it is still signed in.
    } finally {
      this.#accessToken = null;
      this.#key = null;
      this.#keyInFlight = null;
      await this.#keyStore.clear();
    }
    return response;
  }
}
