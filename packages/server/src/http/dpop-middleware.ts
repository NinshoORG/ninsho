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
 *
 * ─── The request target contributes a path, and only a path ───────────────
 * `req.url` is not always the `/path` shape it looks like. HTTP permits an
 * absolute-form target (`GET https://elsewhere/x HTTP/1.1`), and a
 * protocol-relative one (`//elsewhere/x`) is a path as far as any framework is
 * concerned. Resolving either against a base silently discards the base:
 * `new URL('//elsewhere/x', 'https://api.example.com/')` is
 * `https://elsewhere/x`.
 *
 * So the target is reduced to its path and query before anything is built from
 * it. Otherwise a client could steer this reconstruction to any origin it
 * liked and make a proof minted for one endpoint validate at another — its own
 * proof, since it holds the key, but the `htu` binding exists precisely to
 * stop that and would have been silently removable by a request line nobody
 * looked at.
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

  // Reduced to path and query, so an absolute or protocol-relative target
  // cannot replace the authority. The placeholder base is never returned; it
  // exists only to make a relative target parseable.
  const target = raw.originalUrl ?? raw.url ?? '/';
  let pathAndQuery = '/';
  try {
    const parsed = new URL(target, 'http://request-target.invalid');
    pathAndQuery = `${parsed.pathname}${parsed.search}`;
  } catch {
    // An unparseable target reads as the root rather than as an error: this
    // value is compared, not trusted, and a throw here would escape as a 500
    // where a mismatch is the right answer.
    pathAndQuery = '/';
  }

  try {
    return new URL(pathAndQuery, `${protocol}://${host}`).toString();
  } catch {
    // A `Host` or forwarded protocol that will not form a URL. Falling back to
    // a fixed base keeps the comparison total; it will simply not match.
    return new URL(pathAndQuery, 'http://localhost').toString();
  }
}

/** The `DPoP` header, per RFC 9449 §4.1. */
function extractProofHeader(req: HttpRequest): string {
  const header = req.headers['dpop'] ?? req.headers['DPoP'];

  // RFC 9449 §4.3 step 1: exactly one DPoP header. Two is ambiguous, and
  // resolving the ambiguity by picking one would let an attacker append a
  // proof of their own alongside the legitimate client's.
  //
  // Which shape the second one arrives in depends on the runtime, and the
  // array is the one Node does *not* produce — it joins duplicates of this
  // header with a comma. So `rawHeaders` is consulted first, exactly as it is
  // for `Authorization`. Without it a joined pair still failed, but as an
  // unparseable JWS rather than as the ambiguity it is.
  if (req.rawHeaders !== undefined) {
    let seen = 0;
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      if ((req.rawHeaders[i] as string).toLowerCase() === 'dpop') seen += 1;
    }
    if (seen > 1) {
      throw new TokenMissingError(`${seen} DPoP headers`);
    }
  }

  if (Array.isArray(header)) {
    throw new TokenMissingError('multiple DPoP headers');
  }
  if (typeof header !== 'string' || header.length === 0) {
    throw new TokenMissingError('DPoP proof header is required');
  }

  // A JWS carries no commas, so one here is a joined pair.
  if (header.includes(',')) {
    throw new TokenMissingError('multiple proofs in one DPoP header');
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
