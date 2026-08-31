/**
 * Time helpers.
 *
 * Ninsho represents every timestamp as an ISO 8601 string, which is what the
 * PASETO specification requires for `iat` / `nbf` / `exp` (unlike JWT's
 * numeric epoch seconds). Using one representation everywhere avoids a class
 * of bug where a value is compared in the wrong unit — seconds against
 * milliseconds is a silent factor-of-1000 error that makes a token look
 * either permanently valid or permanently expired.
 *
 * All comparisons run against the local system clock. In a multi-host
 * deployment the hosts must agree to within the configured clock tolerance;
 * see `clockToleranceSeconds` in the server configuration.
 */

/** Current time, ISO 8601. */
export function nowIso(): string {
  return new Date().toISOString();
}

/**
 * An ISO 8601 timestamp `seconds` from now.
 * Negative values are permitted and produce a past timestamp — tests rely on
 * this to construct already-expired credentials.
 */
export function isoIn(seconds: number): string {
  return new Date(Date.now() + seconds * 1000).toISOString();
}

/**
 * An ISO 8601 timestamp `offsetSeconds` from a captured instant.
 *
 * Exists so that a record's `issuedAt` and `expiresAt` derive from *one*
 * reading of the clock. Calling `nowIso()` and then `isoIn(ttl)` reads it
 * twice, and a millisecond tick between them makes the recorded lifetime
 * differ from the configured one — harmless in effect, but it means the
 * lifetime is not exactly what was asked for, which is the kind of small
 * imprecision that makes later reasoning about expiry harder than it should be.
 */
export function isoFrom(baseMs: number, offsetSeconds = 0): string {
  return new Date(baseMs + offsetSeconds * 1000).toISOString();
}

/**
 * Parses an ISO 8601 timestamp to epoch milliseconds.
 * Returns `NaN` for anything unparseable; callers must treat `NaN` as invalid
 * rather than letting it flow into a comparison, where every `>` and `<`
 * silently evaluates false.
 */
export function isoToMs(iso: string): number {
  return new Date(iso).getTime();
}

/**
 * Whether an ISO 8601 timestamp is in the past.
 *
 * Fails closed: an unparseable timestamp is reported as expired. A credential
 * whose expiry cannot be determined must not be honoured.
 *
 * @param toleranceSeconds - Clock skew allowance. A token is treated as live
 *   until `tolerance` seconds past its stated expiry, which prevents spurious
 *   rejections when the issuing and verifying hosts disagree slightly.
 */
export function isExpired(iso: string, toleranceSeconds = 0): boolean {
  const ms = isoToMs(iso);
  if (Number.isNaN(ms)) return true;
  return Date.now() > ms + toleranceSeconds * 1000;
}

/**
 * Whether an ISO 8601 timestamp is still in the future — i.e. a `nbf` claim
 * has not yet come into effect.
 *
 * Fails closed: an unparseable timestamp is reported as not-yet-valid.
 */
export function isNotYetValid(iso: string, toleranceSeconds = 0): boolean {
  const ms = isoToMs(iso);
  if (Number.isNaN(ms)) return true;
  return Date.now() < ms - toleranceSeconds * 1000;
}

/**
 * Whole seconds remaining until `iso`, floored at 0.
 *
 * Used to set store TTLs so that a revocation entry expires at exactly the
 * moment the credential it blocks would have expired anyway — which is what
 * keeps the revocation list bounded without a cleanup job.
 */
export function secondsUntil(iso: string): number {
  const ms = isoToMs(iso);
  if (Number.isNaN(ms)) return 0;
  return Math.max(0, Math.ceil((ms - Date.now()) / 1000));
}
