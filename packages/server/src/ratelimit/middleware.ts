import { RateLimitError, toErrorResponse, type AuditSink } from '@ninsho/core';
import type { HttpRequest, HttpResponse, Middleware, NextFunction, ValueSelector } from '../http/types.js';
import { assertTrustProxy, clientIp, type TrustProxy } from './client-ip.js';
import type { RateLimiter } from './limiter.js';

/** One dimension of a limit. */
export interface BucketSpec {
  /** Requests permitted per window. */
  readonly limit: number;
  /** Window length in milliseconds. */
  readonly windowMs: number;
}

export interface RateLimitOptions {
  /**
   * Namespace for these counters, e.g. `'login'`. Keeps unrelated endpoints
   * from sharing a bucket — a shared namespace would let traffic to a busy
   * public route exhaust the allowance for sign-in.
   */
  readonly action: string;

  /**
   * Per-address limit. Guards against one host hammering an endpoint.
   */
  readonly perIp: BucketSpec;

  /**
   * Per-account limit, keyed by whatever `identify` returns.
   *
   * ─── Why a second dimension is not optional ───────────────────────────────
   * A per-IP limit alone does not stop credential stuffing. An attacker with a
   * botnet spreads attempts so no single address approaches the limit, while
   * one victim account absorbs thousands of guesses. The per-account bucket is
   * what notices that, and it is the half the predecessor lacked.
   *
   * The reverse case matters too: a per-IP limit alone punishes shared NAT,
   * where an office or a carrier can trip a limit no individual user caused.
   * ──────────────────────────────────────────────────────────────────────────
   *
   * Omit only for endpoints with no account identity to key on.
   */
  readonly perAccount?: BucketSpec;

  /**
   * Extracts the account identifier — typically the submitted email or
   * username. Required when `perAccount` is set.
   *
   * SECURITY: the returned value becomes part of a store key and may appear in
   * audit records. Return an identifier, never a password.
   */
  readonly identify?: ValueSelector;

  /**
   * How much of `X-Forwarded-For` to believe. No default — see
   * {@link TrustProxy} for why guessing is unsafe in both directions.
   */
  readonly trustProxy: TrustProxy;
}

/** Lower-cases and truncates an identifier so it cannot bloat a key. */
function normaliseIdentifier(value: string): string {
  // Case folding means `Alice@x.com` and `alice@x.com` share one bucket rather
  // than granting an attacker a fresh allowance per capitalisation.
  const folded = value.trim().toLowerCase();
  return folded.length <= 128 ? folded : folded.slice(0, 128);
}

/**
 * Creates rate-limiting middleware.
 *
 * On refusal responds 429 with `Retry-After`. Both dimensions are always
 * consumed, so an attacker cannot keep one counter low by tripping the other
 * first.
 */
export function createRateLimit(
  limiter: RateLimiter,
  audit: AuditSink,
  options: RateLimitOptions,
): Middleware {
  const { action, perIp, perAccount, identify } = options;

  // Validated eagerly, at construction. TypeScript already requires it, but a
  // JavaScript consumer passing nothing would otherwise reach clientIp() with
  // an undefined mode and fail deep inside address parsing — a confusing crash
  // in place of the explicit decision this setting exists to force.
  const trustProxy = assertTrustProxy(options.trustProxy);

  if (perAccount !== undefined && identify === undefined) {
    throw new Error(
      'ninsho: rateLimit() with perAccount also needs identify() — there is ' +
        'no account to key the bucket on otherwise.',
    );
  }

  return (req: HttpRequest, res: HttpResponse, next: NextFunction): void => {
    void (async (): Promise<void> => {
      const ip = clientIp(req, trustProxy);
      const buckets = [
        { bucket: `${action}:ip:${ip}`, limit: perIp.limit, windowMs: perIp.windowMs },
      ];

      if (perAccount !== undefined && identify !== undefined) {
        let identifier: string | undefined;
        try {
          identifier = identify(req);
        } catch {
          identifier = undefined;
        }
        // No identifier means no account bucket. The per-IP limit still
        // applies, so an attacker cannot escape limiting by omitting the
        // field — they only lose the ability to be tracked per account.
        if (typeof identifier === 'string' && identifier.trim().length > 0) {
          buckets.push({
            bucket: `${action}:acct:${normaliseIdentifier(identifier)}`,
            limit: perAccount.limit,
            windowMs: perAccount.windowMs,
          });
        }
      }

      try {
        const verdict = await limiter.enforce(buckets);
        if (res.setHeader !== undefined) {
          res.setHeader('X-RateLimit-Remaining', verdict.remaining);
        }
        next();
      } catch (error) {
        if (error instanceof RateLimitError) {
          audit.emit({
            type: 'ratelimit.exceeded',
            at: new Date().toISOString(),
            ip,
            reason: action,
          });
        }
        const { status, body } = toErrorResponse(error);
        if (status === 429 && res.setHeader !== undefined) {
          res.setHeader('Retry-After', (error as RateLimitError).retryAfter);
        }
        res.status(status).json(body);
      }
    })();
  };
}
