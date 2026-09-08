import { StoreUnavailableError, type FailureMode } from '@ninshorg/core';
import type { NinshoStore } from '../store/types.js';
import { KEYS } from '../keys.js';

/**
 * Single-use enforcement for DPoP proof identifiers — RFC 9449 §11.1.
 *
 * ─── Why the signature is not enough ──────────────────────────────────────
 * A valid proof stays valid for its whole acceptance window. Anyone who can
 * observe one — a logging proxy, a compromised intermediary, a browser
 * extension — can replay it verbatim within that window, together with the
 * access token it accompanied, and the signature check will pass every time.
 *
 * Remembering each `jti` until its proof would have expired closes that: a
 * proof works exactly once. This is what makes DPoP resistant to replay rather
 * than merely to token theft in isolation.
 * ──────────────────────────────────────────────────────────────────────────
 */
export class DpopReplayGuard {
  readonly #store: NinshoStore;
  readonly #onStoreError: FailureMode;
  readonly #retentionSeconds: number;

  /**
   * @param retentionSeconds How long a `jti` is remembered. Must be at least
   *   the proof acceptance window plus clock tolerance; a shorter retention
   *   would forget a proof that is still acceptable, reopening the replay.
   */
  constructor(store: NinshoStore, onStoreError: FailureMode, retentionSeconds: number) {
    this.#store = store;
    this.#onStoreError = onStoreError;
    this.#retentionSeconds = retentionSeconds;
  }

  /**
   * Records a proof identifier and reports whether it was previously unseen.
   *
   * `setIfAbsent` is atomic, so of two requests replaying the same proof
   * simultaneously exactly one can win. A get-then-set would let both through,
   * which is precisely the race an attacker replaying a captured proof would
   * try to hit.
   *
   * @returns `true` if this is the first use.
   * @throws {StoreUnavailableError} When the store is unreachable and the
   *   failure mode is `closed`.
   */
  async claim(jkt: string, jti: string): Promise<boolean> {
    // Namespaced by key thumbprint as well as `jti`, so one client cannot
    // burn another's identifiers by guessing them.
    const key = KEYS.dpopProof(jkt, jti);

    try {
      return await this.#store.setIfAbsent(key, '1', this.#retentionSeconds);
    } catch (error) {
      if (this.#onStoreError === 'open') {
        // Explicitly chosen availability over replay protection. The proof's
        // signature, method, URI and age were all still verified; only
        // single-use enforcement is lost.
        return true;
      }
      throw new StoreUnavailableError(
        `store unreachable during DPoP replay check: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }
}
