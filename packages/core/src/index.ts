/**
 * @ninshorg/core — shared types, errors, and primitives.
 *
 * Consumed by `@ninshorg/server` and, in future, by the browser client package.
 * Contains no server- or browser-specific imports and has no runtime
 * dependencies.
 *
 * Application code should normally import from `@ninshorg/server`, which
 * re-exports everything here. This package is a direct dependency only for
 * projects sharing types across a boundary.
 */

// ── Types ───────────────────────────────────────────────────────────────────
export type {
  TokenStrategy,
  BindingMode,
  FailureMode,
  Principal,
  AuthContext,
  AccessRecord,
  RefreshRecord,
  TokenPair,
  PasetoClaims,
  SigningKey,
  VerificationKey,
  KeySet,
  SecurityEventType,
  SecurityEvent,
  AuditSink,
  SecuritySignals,
  ClientSignals,
} from './types.js';

// ── Errors ──────────────────────────────────────────────────────────────────
export {
  NinshoError,
  TokenMissingError,
  TokenInvalidError,
  TokenExpiredError,
  TokenRevokedError,
  RefreshInvalidError,
  RefreshReuseError,
  ForbiddenError,
  RateLimitError,
  StoreUnavailableError,
  ConfigurationError,
  KeyError,
  isNinshoError,
  toErrorResponse,
} from './errors.js';
export type { ErrorResponse } from './errors.js';

// ── Primitives ──────────────────────────────────────────────────────────────
export {
  generateId,
  generateToken,
  sha256,
  hashToken,
  hashSignal,
  safeEqual,
} from './crypto.js';

export {
  nowIso,
  isoIn,
  isoFrom,
  isoToMs,
  isExpired,
  isNotYetValid,
  secondsUntil,
} from './time.js';
