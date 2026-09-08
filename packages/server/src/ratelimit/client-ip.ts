import { ConfigurationError } from '@ninshorg/core';
import type { HttpRequest } from '../http/types.js';

/**
 * How much of `X-Forwarded-For` to believe.
 *
 * ─── Audit finding H5 ─────────────────────────────────────────────────────
 * The predecessor keyed its rate limiter on `req.ip` and never mentioned proxy
 * configuration anywhere. That single omission breaks the limiter in both
 * directions, and which way depends on deployment rather than on code:
 *
 *   - Behind a load balancer with no proxy trust configured, every request
 *     carries the balancer's address. One global bucket: five failed logins
 *     from anyone lock out the entire internet.
 *
 *   - With proxy trust configured too permissively, `X-Forwarded-For` is
 *     attacker-controlled. Rotating one header defeats the limiter entirely.
 *
 * There is no safe default, because the right answer depends on infrastructure
 * the library cannot see. So Ninsho refuses to guess: `trustProxy` has no
 * default and a rate limiter cannot be constructed without one.
 * ──────────────────────────────────────────────────────────────────────────
 *
 *   - `false` — take the peer address only, ignoring forwarding headers.
 *     Correct when the process is directly exposed.
 *
 *   - a number — the count of trusted proxies in front of this process.
 *
 *     Each proxy appends the address it received the request from, so `n`
 *     trusted proxies contribute the *last* `n` entries of the chain and the
 *     client is at `chain.length - n`. Everything to the left of that is
 *     whatever the client typed. With one proxy and a chain of `[client]`,
 *     the client is `chain[0]`; `0` means no proxies and is treated as
 *     `false`.
 *
 *   - `'all'` — trust the leftmost entry. Only correct when something upstream
 *     is already rewriting the header; otherwise the value is whatever the
 *     client typed.
 */
export type TrustProxy = false | number | 'all';

/** Validates a `trustProxy` setting, refusing anything ambiguous. */
export function assertTrustProxy(value: unknown, field = 'trustProxy'): TrustProxy {
  if (value === false || value === 'all') return value;
  if (typeof value === 'number' && Number.isInteger(value) && value >= 0) {
    return value;
  }
  throw new ConfigurationError(
    `config.${field} must be false, a non-negative integer, or 'all'. ` +
      'There is no default: keying a rate limit on the wrong address either ' +
      'locks out every user behind a shared proxy, or lets one attacker ' +
      "bypass the limit by rotating an X-Forwarded-For header. Use false if " +
      'this process is directly exposed, or the number of proxies in front of it.',
  );
}

function firstHeader(req: HttpRequest, name: string): string | undefined {
  const raw = req.headers[name] ?? req.headers[name.toLowerCase()];
  if (Array.isArray(raw)) {
    // A repeated header is ambiguous. Joining matches how most proxies
    // serialize a chain they received in pieces.
    return raw.join(',');
  }
  return typeof raw === 'string' ? raw : undefined;
}

/** Reads the peer address the framework observed, if it exposes one. */
function peerAddress(req: HttpRequest): string | undefined {
  const candidate = req as unknown as {
    ip?: unknown;
    socket?: { remoteAddress?: unknown };
  };
  if (typeof candidate.ip === 'string' && candidate.ip.length > 0) return candidate.ip;
  const remote = candidate.socket?.remoteAddress;
  return typeof remote === 'string' && remote.length > 0 ? remote : undefined;
}

/**
 * Normalises an address so the same client cannot occupy two buckets.
 *
 * IPv6-mapped IPv4 (`::ffff:1.2.3.4`) is folded to its IPv4 form, and case and
 * whitespace are normalised. Without this, an attacker could double their
 * allowance simply by connecting over a different address family.
 */
function normalise(address: string): string {
  const trimmed = address.trim().toLowerCase();
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(trimmed);
  if (mapped !== null) return mapped[1] as string;
  // Strip a port from `host:port`, but only for IPv4 — a bare IPv6 address
  // contains colons of its own.
  const withPort = /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/.exec(trimmed);
  if (withPort !== null) return withPort[1] as string;
  return trimmed;
}

/**
 * Resolves the address to attribute a request to.
 *
 * Returns `'unknown'` when no address can be determined. That is deliberate:
 * every such request shares one bucket, so an environment that hides client
 * addresses degrades to a global limit rather than to no limit at all.
 */
export function clientIp(req: HttpRequest, trustProxy: TrustProxy): string {
  const peer = peerAddress(req);

  if (trustProxy === false) {
    return peer === undefined ? 'unknown' : normalise(peer);
  }

  // Zero trusted proxies is the same statement as `false`: nothing upstream is
  // entitled to speak for the client, so the header is not consulted at all.
  if (trustProxy === 0) {
    return peer === undefined ? 'unknown' : normalise(peer);
  }

  const forwarded = firstHeader(req, 'x-forwarded-for');
  if (forwarded === undefined) {
    return peer === undefined ? 'unknown' : normalise(peer);
  }

  const chain = forwarded
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0);

  if (chain.length === 0) {
    return peer === undefined ? 'unknown' : normalise(peer);
  }

  if (trustProxy === 'all') {
    // The leftmost entry is the original client *if* everything upstream is
    // honest. It is also the entry an attacker controls when anything upstream
    // is not, which is why this mode is opt-in and documented as such.
    return normalise(chain[0] as string);
  }

  // ─── Where the client sits, and why it is not one further left ───────────
  // Each trusted proxy appends the address it received the request from, so
  // `n` proxies contribute the last `n` entries and the client is the one just
  // before them. Entries an attacker prepends land to the *left* of that
  // index, which is what puts them out of reach.
  //
  // Reading one position further left is not a rounding error: with a single
  // proxy the chain holds one entry, so it lands past the start and falls back
  // to the peer — the proxy's own address — putting every user of the service
  // in one bucket. And an attacker who prepends a single entry moves the index
  // onto a value they chose. Those are the two failure modes named at the top
  // of this file, and off-by-one is enough to produce both.
  const index = chain.length - trustProxy;
  if (index < 0 || index >= chain.length) {
    // The chain is shorter than the configured proxy count — the request did
    // not traverse the expected path. Fall back to the peer address rather
    // than reaching for an attacker-supplied entry.
    return peer === undefined ? 'unknown' : normalise(peer);
  }
  return normalise(chain[index] as string);
}
