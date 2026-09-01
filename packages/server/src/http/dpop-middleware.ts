import { TokenInvalidError, TokenMissingError, type AuditSink } from '@ninsho/core';
import { verifyDpopProof } from '../dpop/proof.js';
import type { DpopReplayGuard } from '../dpop/replay.js';
import type { HttpRequest } from './types.js';

/**
 * Request-side DPoP handling — extracting the proof and establishing the key
 * thumbprint the token must be bound to.
 */

export interface DpopContext {
  readonly replayGuard: DpopReplayGuard;
  readonly maxAgeSeconds: number;
  readonly clockToleranceSeconds: number;
  readonly audit: AuditSink;
  /**
   * Reconstructs the absolute request URI the proof must match.
   *
   * Defaults to deriving it from the request, which requires trusting the
   * `Host` header. Supply your own in any deployment where that header is not
   * already normalised by a trusted proxy — see {@link defaultRequestUrl}.
   */
  readonly requestUrl?: (req: HttpRequest) => string;
}

/**
 * Reconstructs the request URI from the request itself.
 *
 * ─── Read this before relying on the default ──────────────────────────────
 * `Host` is a client-supplied header. If nothing upstream normalises it, an
 * attacker controls what this returns — and since the same value is used for
 * both sides of the `htu` comparison, they could make a proof minted for one
 * endpoint validate at another.
 *
 * The comparison is still not *useless* in that case: the proof is signed, so
 * the attacker must hold the key, which means they are the legitimate client
 * relaxing their own binding rather than a third party. But it does weaken the
 * guarantee to nothing meaningful.
 *
 * Behind a proxy that sets `Host` reliably — which is the normal deployment —
 * the default is correct. Elsewhere, supply `requestUrl` and build the URI from
 * configuration rather than from the request.
 * ──────────────────────────────────────────────────────────────────────────
 */
export function defaultRequestUrl(req: HttpRequest): string {
  const raw = req as unknown as {
    protocol?: string;
    secure?: boolean;
    originalUrl?: string;
    url?: string;
    headers: Record<string, string | string[] | undefined>;
  };

  const forwardedProto = raw.headers['x-forwarded-proto'];
  const protocol =
    typeof forwardedProto === 'string'
      ? (forwardedProto.split(',')[0] as string).trim()
      : (raw.protocol ?? (raw.secure === true ? 'https' : 'http'));

  const hostHeader = raw.headers['host'];
  const host = typeof hostHeader === 'string' ? hostHeader : 'localhost';

  const path = raw.originalUrl ?? raw.url ?? '/';
  return new URL(path, `${protocol}://${host}`).toString();
}

/** The `DPoP` header, per RFC 9449 §4.1. */
function extractProofHeader(req: HttpRequest): string {
  const header = req.headers['dpop'] ?? req.headers['DPoP'];

  // RFC 9449 §4.3 step 1: exactly one DPoP header. Two is ambiguous, and
  // resolving the ambiguity by picking one would let an attacker append a
  // proof of their own alongside the legitimate client's.
  if (Array.isArray(header)) {
    throw new TokenMissingError('multiple DPoP headers');
  }
  if (typeof header !== 'string' || header.length === 0) {
    throw new TokenMissingError('DPoP proof header is required');
  }
  return header;
}

/**
 * Verifies the DPoP proof on a request and returns the key thumbprint.
 *
 * `accessToken` is omitted on the login route, where the client sends its first
 * proof before any token exists. Everywhere else it must be supplied, so the
 * proof is bound to the specific token it accompanies.
 *
 * The returned value is passed to the engine, which compares it against the
 * token's own binding. Splitting it this way keeps the engine unaware of HTTP
 * and this function unaware of token formats.
 *
 * @throws {TokenMissingError} No proof, or more than one.
 * @throws {TokenInvalidError} The proof failed verification or was replayed.
 */
export async function establishProofOfPossession(
  req: HttpRequest,
  accessToken: string | undefined,
  context: DpopContext,
): Promise<string> {
  const proof = extractProofHeader(req);

  const method = (req as unknown as { method?: string }).method ?? 'GET';
  const url = (context.requestUrl ?? defaultRequestUrl)(req);

  let verified;
  try {
    verified = verifyDpopProof(proof, {
      method,
      url,
      // Omitted on the login route, where no token exists yet: RFC 9449 §4.3
      // step 11 only requires `ath` when one is presented. Passing an empty
      // string instead would demand a hash of nothing.
      ...(accessToken !== undefined && accessToken.length > 0 && { accessToken }),
      maxAgeSeconds: context.maxAgeSeconds,
      clockToleranceSeconds: context.clockToleranceSeconds,
    });
  } catch (error) {
    // The reason is diagnostic only. A client learns its proof was rejected,
    // not which of a dozen checks caught it.
    throw new TokenInvalidError(
      `DPoP proof rejected: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  // Single-use. Without this a captured proof stays replayable for its whole
  // acceptance window, and DPoP would protect against token theft in isolation
  // while remaining vulnerable to replay of the pair.
  const fresh = await context.replayGuard.claim(verified.jkt, verified.jti);
  if (!fresh) {
    context.audit.emit({
      type: 'token.rejected',
      at: new Date().toISOString(),
      reason: 'dpop_proof_replayed',
    });
    throw new TokenInvalidError(`DPoP proof ${verified.jti} has already been used`);
  }

  return verified.jkt;
}
