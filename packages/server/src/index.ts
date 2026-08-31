/**
 * @ninsho/server — the Ninsho authentication engine.
 *
 * ─── Status: v0.1.0, Phase 6 ──────────────────────────────────────────────
 * What exists: the storage seam, the opaque token engine, sessions with
 * refresh-token rotation and reuse detection, configuration validation, and
 * audit sinks.
 *
 * What does not exist yet: an official example app, and DPoP (the `cnf` claim
 * slot and `BindingMode` are reserved for it but nothing implements it).
 * ──────────────────────────────────────────────────────────────────────────
 *
 * @example The whole setup
 * ```ts
 * import { Ninsho, RedisStore } from '@ninsho/server';
 *
 * const auth = new Ninsho({ store: new RedisStore(process.env.REDIS_URL!) });
 *
 * app.post('/login',
 *   auth.rateLimit({
 *     action: 'login',
 *     perIp: { limit: 20, windowMs: 900_000 },
 *     perAccount: { limit: 5, windowMs: 900_000 },
 *     identify: (req) => (req.body as { email?: string })?.email,
 *     trustProxy: false,
 *   }),
 *   async (req, res) => {
 *     // Verify credentials yourself, then:
 *     const pair = await auth.createSession({ userId, roles: ['user'], scopes: [] });
 *     res.json(pair);
 *   });
 *
 * app.get('/me', auth.verify(), (req, res) => res.json(getAuth(req)));
 * app.get('/users/:id/orders',
 *   auth.verify(),
 *   auth.requireOwner((req) => req.params?.id),
 *   handler);
 * ```
 */

// ── Main entry point ────────────────────────────────────────────────────────
export { Ninsho } from './ninsho.js';

// ── Rate limiting ───────────────────────────────────────────────────────────
export { RateLimiter, createRateLimit, clientIp, assertTrustProxy } from './ratelimit/index.js';
export type {
  RateLimitOptions,
  BucketSpec,
  BucketVerdict,
  LimiterOptions,
  TrustProxy,
} from './ratelimit/index.js';

// ── Storage ─────────────────────────────────────────────────────────────────
export type { NinshoStore } from './store/index.js';
export { MemoryStore, RedisStore } from './store/index.js';
export type { RedisStoreOptions } from './store/index.js';

// ── Token engines ───────────────────────────────────────────────────────────
export type {
  TokenEngine,
  IssueAccessTokenInput,
  IssuedAccessToken,
  OpaqueEngineOptions,
  VerifyOptions,
} from './engine/index.js';
export { OpaqueEngine, PasetoEngine } from './engine/index.js';
export type { PasetoEngineOptions } from './engine/index.js';

// ── Keys (paseto strategy only) ─────────────────────────────────────────────
export { KeyRing, generateKeyPair, loadPrivateKey, loadPublicKey } from './keys/index.js';

// ── PASETO v4.public primitives ─────────────────────────────────────────────
// Exported for testing and for advanced callers. Application code should use
// PasetoEngine rather than signing tokens directly.
export {
  signV4Public,
  verifyV4Public,
  readFooterUnverified,
  PasetoFormatError,
  V4_PUBLIC_HEADER,
} from './paseto/index.js';

// ── Sessions ────────────────────────────────────────────────────────────────
export { SessionManager } from './session/index.js';
export type {
  SessionManagerOptions,
  ConsumedRefreshRecord,
  GraceRecord,
  SessionMeta,
  SessionSummary,
  RevocationReason,
} from './session/index.js';

// ── HTTP middleware ─────────────────────────────────────────────────────────
// Framework-agnostic by structural typing: Express Request/Response satisfy
// these shapes, so no Express dependency is needed.
export type {
  HttpRequest,
  HttpResponse,
  NextFunction,
  Middleware,
  ValueSelector,
  MiddlewareOptions,
} from './http/index.js';
export {
  getAuth,
  createVerify,
  createRequireRole,
  createRequireAllRoles,
  createRequireScope,
  createRequireOwner,
  createRequireTenant,
  createErrorHandler,
} from './http/index.js';

// ── Configuration ───────────────────────────────────────────────────────────
export { resolveConfig, DEFAULTS } from './config.js';
export type { NinshoConfig, ResolvedConfig } from './config.js';

// ── Audit ───────────────────────────────────────────────────────────────────
export {
  ConsoleAuditSink,
  NullAuditSink,
  MemoryAuditSink,
  safeSink,
} from './audit.js';

// ── Store key namespace ─────────────────────────────────────────────────────
// Exported for operators inspecting a live store and for tests. Application
// code should not construct keys directly.
export { KEYS } from './keys.js';

// ── Re-exported from @ninsho/core ───────────────────────────────────────────
// So consumers need only one dependency.
export type {
  TokenStrategy,
  BindingMode,
  KeySet,
  SigningKey,
  VerificationKey,
  PasetoClaims,
  FailureMode,
  Principal,
  AuthContext,
  AccessRecord,
  RefreshRecord,
  TokenPair,
  SecurityEvent,
  SecurityEventType,
  AuditSink,
  ErrorResponse,
} from '@ninsho/core';

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
} from '@ninsho/core';
