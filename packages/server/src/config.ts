import {
  ConfigurationError,
  type AuditSink,
  type BindingMode,
  type FailureMode,
  type KeySet,
  type TokenStrategy,
} from '@ninshorg/core';
import type { NinshoStore } from './store/types.js';
import { ConsoleAuditSink, safeSink } from './audit.js';
import type { OneTimeTokenOptions } from './tokens/one-time.js';

/**
 * Configuration for `new Ninsho(...)`.
 *
 * Only `store` is required. Every other field has a default chosen to be the
 * safe option, so the shortest possible configuration is also the most secure
 * one — a developer who configures nothing gets opaque tokens, fail-closed
 * behaviour, and five-minute access tokens.
 */
export interface NinshoConfig {
  /**
   * Where session state lives. Injected rather than constructed internally, so
   * choosing an implementation is a visible act in application code.
   */
  readonly store: NinshoStore;

  /**
   * Single-use token behaviour — password reset, email verification, magic
   * links. Defaults are a fifteen-minute lifetime, 256 bits of randomness, and
   * invalidating a subject's previous token when a new one is issued.
   */
  readonly oneTimeTokens?: OneTimeTokenOptions;

  /**
   * Access token format. Default `'opaque'`.
   * Choose `'paseto'` only when several services must verify independently
   * without sharing this store; it additionally requires `issuer`, `audience`
   * and a key set.
   */
  readonly strategy?: TokenStrategy;

  /** Access token lifetime in seconds. Default 300 (5 minutes). */
  readonly accessTokenTtl?: number;

  /** Refresh token lifetime in seconds. Default 604800 (7 days). */
  readonly refreshTokenTtl?: number;

  /**
   * What to do when the store is unreachable. Default `'closed'`.
   *
   * `'open'` allows requests through without a revocation check, which means
   * every revoked token works again for the duration of an outage. It is a
   * legitimate availability trade-off and an explicit security downgrade;
   * selecting it emits a `config.insecure` audit event at startup.
   */
  readonly onStoreError?: FailureMode;

  /**
   * How a token is bound to its holder. Default `'none'` (bearer semantics).
   *
   * `'dpop'` enables proof-of-possession (RFC 9449): tokens are bound to a key
   * the client holds privately, and every request must carry a fresh proof
   * signed by it. A stolen token is then useless on its own.
   *
   * Enabling it is a breaking change for clients — they must generate a key and
   * send a `DPoP` header on every request — so it is opt-in rather than
   * default.
   */
  readonly binding?: BindingMode;

  /**
   * Grace period in seconds during which a just-rotated refresh token still
   * resolves to its replacement. Default 30.
   *
   * Without this, two browser tabs refreshing at the same moment race: one
   * wins, the other presents a token that was valid microseconds earlier and
   * is logged out. The window is the trade-off knob between that false
   * positive and how quickly a genuine replay is caught. Set to 0 to disable
   * the grace window entirely and treat every replay as reuse.
   */
  readonly refreshGraceSeconds?: number;

  /**
   * How old a DPoP proof may be, in seconds. Default 60.
   *
   * Bounds both how long a captured proof stays replayable before the
   * single-use guard even matters, and how much replay state the store holds.
   * Too short and legitimate clients on slow links are rejected.
   */
  readonly dpopProofMaxAgeSeconds?: number;

  /** Clock skew allowance in seconds when checking time claims. Default 5. */
  readonly clockToleranceSeconds?: number;

  /** Where security events go. Default: JSON lines on stdout. */
  readonly audit?: AuditSink;

  // ── Required when strategy is 'paseto', ignored otherwise ────────────────

  /**
   * Identifier for this deployment, stamped as `iss` and required to match on
   * every verify.
   *
   * Required because without it a token minted by one deployment is accepted
   * by any other that happens to share a key — a staging token working in
   * production is not a theoretical concern.
   */
  readonly issuer?: string;

  /**
   * The service these tokens are for, stamped as `aud` and required to match.
   *
   * Required because a token for `orders-api` must be rejected by
   * `billing-api`. The predecessor omitted this entirely, so any service
   * holding the public key accepted tokens minted for any other.
   */
  readonly audience?: string;

  /**
   * Signing and verification keys. The active key signs; every key verifies,
   * which is what lets a rotation happen without signing everyone out.
   */
  readonly keys?: KeySet;
}

/** Configuration with every default applied. */
export interface ResolvedConfig {
  readonly store: NinshoStore;
  readonly strategy: TokenStrategy;
  readonly accessTokenTtl: number;
  readonly refreshTokenTtl: number;
  readonly onStoreError: FailureMode;
  readonly binding: BindingMode;
  readonly refreshGraceSeconds: number;
  readonly dpopProofMaxAgeSeconds: number;
  readonly clockToleranceSeconds: number;
  readonly audit: AuditSink;
  /** Present only when strategy is 'paseto'. */
  readonly issuer: string | undefined;
  readonly audience: string | undefined;
  readonly keys: KeySet | undefined;
  readonly oneTimeTokens: OneTimeTokenOptions | undefined;
  /** Conditions that are valid but weaken security. Emitted as audit events at startup. */
  readonly warnings: readonly string[];
}

export const DEFAULTS = {
  strategy: 'opaque' as const,
  /**
   * Five minutes, not the fifteen the predecessor used. Fail-closed
   * revocation means a token's blast radius is bounded by the store, but a
   * shorter window is still the cheapest defence against a stolen token, and
   * with refresh rotation the cost to a legitimate client is one extra
   * round trip every five minutes.
   */
  accessTokenTtl: 300,
  refreshTokenTtl: 604_800,
  onStoreError: 'closed' as const,
  binding: 'none' as const,
  /**
   * Thirty seconds. Long enough to absorb a multi-tab race and a slow mobile
   * round trip; short enough that a stolen token replayed by an attacker in
   * another session is almost always outside it.
   */
  refreshGraceSeconds: 30,
  /**
   * Sixty seconds, as RFC 9449 §11.1 suggests. Long enough for a slow mobile
   * round trip; short enough that a captured proof is stale almost immediately.
   */
  dpopProofMaxAgeSeconds: 60,
  clockToleranceSeconds: 5,
} as const;

/** Above this, an access token stops being short-lived enough to be one. */
const ACCESS_TTL_WARN_THRESHOLD = 3600;
/** Beyond a day, the value is certainly a mistake — probably a refresh TTL. */
const ACCESS_TTL_MAX = 86_400;
/** Past this, the grace window starts to meaningfully blunt reuse detection. */
const GRACE_WARN_THRESHOLD = 120;
/** Past this, a captured DPoP proof stays useful for an uncomfortably long time. */
const DPOP_MAX_AGE_WARN_THRESHOLD = 300;

const VALID_STRATEGIES: readonly TokenStrategy[] = ['opaque', 'paseto'];
const VALID_FAILURE_MODES: readonly FailureMode[] = ['closed', 'open'];
const VALID_BINDINGS: readonly BindingMode[] = ['none', 'dpop'];

/** The store methods that must be present for the engine to function. */
const REQUIRED_STORE_METHODS = [
  'get',
  'set',
  'setIfAbsent',
  'take',
  'increment',
  'delete',
  'exists',
  'sAdd',
  'sRemove',
  'sMembers',
  'ping',
  'close',
] as const;

/**
 * Validates configuration and applies defaults.
 *
 * Runs once, synchronously, during construction. A misconfigured deployment
 * therefore fails at boot with a message naming the problem, rather than at
 * the first authentication attempt with something opaque — an invalid TTL
 * discovered under production traffic is a much worse way to learn about it.
 *
 * @throws {ConfigurationError} On any invalid value.
 */
export function resolveConfig(config: NinshoConfig): ResolvedConfig {
  if (typeof config !== 'object' || config === null) {
    throw new ConfigurationError('Ninsho requires a configuration object');
  }

  const warnings: string[] = [];

  // ── store ────────────────────────────────────────────────────────────────
  const { store } = config;
  if (store === undefined || store === null) {
    throw new ConfigurationError(
      'config.store is required. Pass a RedisStore for production, or a ' +
        'MemoryStore for local development and tests.',
    );
  }
  const missing = REQUIRED_STORE_METHODS.filter(
    (m) => typeof (store as unknown as Record<string, unknown>)[m] !== 'function',
  );
  if (missing.length > 0) {
    throw new ConfigurationError(
      `config.store does not implement NinshoStore. Missing: ${missing.join(', ')}`,
    );
  }

  // ── strategy ─────────────────────────────────────────────────────────────
  const strategy = config.strategy ?? DEFAULTS.strategy;
  if (!VALID_STRATEGIES.includes(strategy)) {
    throw new ConfigurationError(
      `config.strategy must be one of: ${VALID_STRATEGIES.join(', ')}. Received: ${String(strategy)}`,
    );
  }
  // ── paseto-only requirements ─────────────────────────────────────────────
  // Demanded up front rather than defaulted. A silently-defaulted issuer or
  // audience would be worse than none: it would look like scoping while
  // matching everywhere.
  let issuer: string | undefined;
  let audience: string | undefined;
  let keys: KeySet | undefined;

  if (strategy === 'paseto') {
    issuer = requireNonEmptyString(config.issuer, 'issuer', 'paseto');
    audience = requireNonEmptyString(config.audience, 'audience', 'paseto');

    if (config.keys === undefined || config.keys === null) {
      throw new ConfigurationError(
        "config.keys is required when strategy is 'paseto'. Generate a keypair " +
          "with generateKeyPair('<kid>') and keep the private half out of source control.",
      );
    }
    keys = config.keys;
  } else {
    // Catching these early turns a silent no-op into an actionable error: a
    // developer who set an audience expects it to be enforced somewhere.
    for (const field of ['issuer', 'audience', 'keys'] as const) {
      if (config[field] !== undefined) {
        throw new ConfigurationError(
          `config.${field} is only meaningful when strategy is 'paseto'. ` +
            `The 'opaque' strategy has no signing keys and no claims to scope. ` +
            `Remove it, or set strategy: 'paseto'.`,
        );
      }
    }
  }

  // ── binding ──────────────────────────────────────────────────────────────
  const binding = config.binding ?? DEFAULTS.binding;
  if (!VALID_BINDINGS.includes(binding)) {
    throw new ConfigurationError(
      `config.binding must be one of: ${VALID_BINDINGS.join(', ')}. Received: ${String(binding)}`,
    );
  }
  const dpopProofMaxAgeSeconds =
    config.dpopProofMaxAgeSeconds ?? DEFAULTS.dpopProofMaxAgeSeconds;
  if (
    typeof dpopProofMaxAgeSeconds !== 'number' ||
    !Number.isFinite(dpopProofMaxAgeSeconds) ||
    dpopProofMaxAgeSeconds <= 0
  ) {
    throw new ConfigurationError(
      'config.dpopProofMaxAgeSeconds must be a positive finite number of seconds',
    );
  }
  if (binding === 'none' && config.dpopProofMaxAgeSeconds !== undefined) {
    throw new ConfigurationError(
      "config.dpopProofMaxAgeSeconds is only meaningful when binding is 'dpop'. " +
        'Setting it under bearer semantics would suggest a proof is being ' +
        'checked when none is.',
    );
  }
  if (binding === 'dpop' && dpopProofMaxAgeSeconds > DPOP_MAX_AGE_WARN_THRESHOLD) {
    warnings.push(
      `dpopProofMaxAgeSeconds is ${dpopProofMaxAgeSeconds}s. A wide window ` +
        'leaves a captured proof usable for that long against the single-use ' +
        'guard, and grows the replay state the store must hold.',
    );
  }

  // ── failure mode ─────────────────────────────────────────────────────────
  const onStoreError = config.onStoreError ?? DEFAULTS.onStoreError;
  if (!VALID_FAILURE_MODES.includes(onStoreError)) {
    throw new ConfigurationError(
      `config.onStoreError must be one of: ${VALID_FAILURE_MODES.join(', ')}. Received: ${String(onStoreError)}`,
    );
  }
  if (onStoreError === 'open') {
    // Fail-open is only coherent for a strategy that can establish identity
    // without the store. Under `opaque` the store *is* the identity, so there
    // is nothing to fall back on — "open" would mean admitting a request whose
    // caller is unknown. Rejecting the combination here stops a developer
    // believing they have configured graceful degradation when in fact the
    // setting can never take effect.
    if (strategy === 'opaque') {
      throw new ConfigurationError(
        "config.onStoreError 'open' has no meaning with the 'opaque' strategy: " +
          'the store holds the identity, so an outage leaves no way to ' +
          'identify the caller. Either keep the default fail-closed posture, ' +
          "or switch to the 'paseto' strategy, where a signature can be " +
          'verified locally and only the revocation check is lost.',
      );
    }
    warnings.push(
      "onStoreError is 'open': while the store is unreachable, revoked tokens " +
        'will be accepted. Revocation is not enforced during an outage.',
    );
  }

  // ── TTLs ─────────────────────────────────────────────────────────────────
  const accessTokenTtl = requirePositiveSeconds(
    config.accessTokenTtl,
    DEFAULTS.accessTokenTtl,
    'accessTokenTtl',
  );
  const refreshTokenTtl = requirePositiveSeconds(
    config.refreshTokenTtl,
    DEFAULTS.refreshTokenTtl,
    'refreshTokenTtl',
  );

  if (accessTokenTtl > ACCESS_TTL_MAX) {
    throw new ConfigurationError(
      `config.accessTokenTtl of ${accessTokenTtl}s exceeds the maximum of ` +
        `${ACCESS_TTL_MAX}s. An access token this long-lived is almost ` +
        'certainly a mistake — did you mean refreshTokenTtl?',
    );
  }
  if (accessTokenTtl > ACCESS_TTL_WARN_THRESHOLD) {
    warnings.push(
      `accessTokenTtl is ${accessTokenTtl}s. Long-lived access tokens widen ` +
        'the window in which a stolen token is useful; prefer a short TTL with refresh.',
    );
  }
  if (refreshTokenTtl <= accessTokenTtl) {
    throw new ConfigurationError(
      `config.refreshTokenTtl (${refreshTokenTtl}s) must be greater than ` +
        `config.accessTokenTtl (${accessTokenTtl}s), otherwise the refresh ` +
        'token expires before the token it exists to renew.',
    );
  }

  // ── refresh grace window ─────────────────────────────────────────────────
  const refreshGraceSeconds =
    config.refreshGraceSeconds ?? DEFAULTS.refreshGraceSeconds;
  if (
    typeof refreshGraceSeconds !== 'number' ||
    !Number.isFinite(refreshGraceSeconds) ||
    refreshGraceSeconds < 0
  ) {
    throw new ConfigurationError(
      'config.refreshGraceSeconds must be a non-negative finite number of seconds',
    );
  }
  if (refreshGraceSeconds > GRACE_WARN_THRESHOLD) {
    warnings.push(
      `refreshGraceSeconds is ${refreshGraceSeconds}s. A wide grace window ` +
        'lets a stolen refresh token be replayed undetected for that long, ' +
        'because a replay inside the window is indistinguishable from a ' +
        'legitimate parallel tab.',
    );
  }
  if (refreshGraceSeconds >= refreshTokenTtl) {
    throw new ConfigurationError(
      `config.refreshGraceSeconds (${refreshGraceSeconds}s) must be shorter ` +
        `than config.refreshTokenTtl (${refreshTokenTtl}s), otherwise every ` +
        'rotated token stays usable for its entire lifetime and reuse is ' +
        'never detected.',
    );
  }

  // ── clock tolerance ──────────────────────────────────────────────────────
  const clockToleranceSeconds = config.clockToleranceSeconds ?? DEFAULTS.clockToleranceSeconds;
  if (
    typeof clockToleranceSeconds !== 'number' ||
    !Number.isFinite(clockToleranceSeconds) ||
    clockToleranceSeconds < 0
  ) {
    throw new ConfigurationError(
      'config.clockToleranceSeconds must be a non-negative finite number of seconds',
    );
  }
  if (clockToleranceSeconds > accessTokenTtl) {
    throw new ConfigurationError(
      `config.clockToleranceSeconds (${clockToleranceSeconds}s) exceeds ` +
        `config.accessTokenTtl (${accessTokenTtl}s), which would keep every ` +
        'token valid past its own expiry.',
    );
  }

  // ── audit ────────────────────────────────────────────────────────────────
  const audit = config.audit;
  if (audit !== undefined && typeof audit.emit !== 'function') {
    throw new ConfigurationError('config.audit must implement AuditSink (an emit method)');
  }

  return {
    store,
    strategy,
    accessTokenTtl,
    refreshTokenTtl,
    onStoreError,
    binding,
    refreshGraceSeconds,
    dpopProofMaxAgeSeconds,
    clockToleranceSeconds,
    // Wrapped so a throwing sink can never fail an authentication.
    audit: safeSink(audit ?? new ConsoleAuditSink()),
    issuer,
    audience,
    keys,
    oneTimeTokens: config.oneTimeTokens,
    warnings,
  };
}

function requireNonEmptyString(
  value: string | undefined,
  field: string,
  strategy: string,
): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new ConfigurationError(
      `config.${field} is required when strategy is '${strategy}' and must be a non-empty string`,
    );
  }
  return value;
}

function requirePositiveSeconds(
  value: number | undefined,
  fallback: number,
  field: string,
): number {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new ConfigurationError(
      `config.${field} must be a positive finite number of seconds. Received: ${String(value)}`,
    );
  }
  if (!Number.isInteger(value)) {
    throw new ConfigurationError(
      `config.${field} must be a whole number of seconds. Received: ${String(value)}`,
    );
  }
  return value;
}
