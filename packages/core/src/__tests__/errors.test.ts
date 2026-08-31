import { describe, it, expect } from 'vitest';
import {
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
} from '../errors.js';

/**
 * Every concrete error, with the status it must map to.
 * Kept as a table so adding an error without deciding its status fails here.
 */
const ALL_ERRORS: ReadonlyArray<[string, () => NinshoError, number, string]> = [
  ['TokenMissingError', () => new TokenMissingError(), 401, 'TOKEN_MISSING'],
  ['TokenInvalidError', () => new TokenInvalidError(), 401, 'TOKEN_INVALID'],
  ['TokenExpiredError', () => new TokenExpiredError(), 401, 'TOKEN_EXPIRED'],
  ['TokenRevokedError', () => new TokenRevokedError(), 401, 'TOKEN_REVOKED'],
  ['RefreshInvalidError', () => new RefreshInvalidError(), 401, 'REFRESH_INVALID'],
  ['RefreshReuseError', () => new RefreshReuseError(), 401, 'REFRESH_REUSE_DETECTED'],
  ['ForbiddenError', () => new ForbiddenError(), 403, 'FORBIDDEN'],
  ['RateLimitError', () => new RateLimitError(30), 429, 'RATE_LIMIT_EXCEEDED'],
  ['StoreUnavailableError', () => new StoreUnavailableError(), 503, 'SERVICE_UNAVAILABLE'],
  ['ConfigurationError', () => new ConfigurationError('bad config'), 500, 'CONFIGURATION_ERROR'],
  ['KeyError', () => new KeyError('bad key'), 500, 'KEY_ERROR'],
];

describe('error taxonomy', () => {
  it.each(ALL_ERRORS)('%s maps to the right status and code', (_name, make, status, code) => {
    const err = make();
    expect(err.status).toBe(status);
    expect(err.code).toBe(code);
  });

  it.each(ALL_ERRORS)('%s is a real Error and a NinshoError', (_name, make) => {
    const err = make();
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(NinshoError);
    expect(isNinshoError(err)).toBe(true);
    // Stack capture must survive the prototype fix-up in the base constructor.
    expect(typeof err.stack).toBe('string');
  });

  it('names each error after its own class, not the base', () => {
    expect(new TokenExpiredError().name).toBe('TokenExpiredError');
    expect(new ForbiddenError().name).toBe('ForbiddenError');
  });
});

/**
 * REGRESSION — the previous implementation interpolated raw dependency error
 * text into the 401 body, leaking library internals to unauthenticated
 * callers. `detail` now lives outside anything `toResponse()` reads, so the
 * leak is structurally impossible rather than merely avoided by convention.
 */
describe('detail never reaches the client', () => {
  const SECRET_DETAIL =
    'ed25519 verify failed for kid=2026-08 at /srv/app/node_modules/paseto/lib/v4.js:88';

  /** Every error, constructed with diagnostic detail attached. */
  const WITH_DETAIL: ReadonlyArray<[string, NinshoError]> = [
    ['TokenMissingError', new TokenMissingError(SECRET_DETAIL)],
    ['TokenInvalidError', new TokenInvalidError(SECRET_DETAIL)],
    ['TokenExpiredError', new TokenExpiredError(SECRET_DETAIL)],
    ['TokenRevokedError', new TokenRevokedError(SECRET_DETAIL)],
    ['RefreshInvalidError', new RefreshInvalidError(SECRET_DETAIL)],
    ['RefreshReuseError', new RefreshReuseError(SECRET_DETAIL)],
    ['ForbiddenError', new ForbiddenError(SECRET_DETAIL)],
    ['RateLimitError', new RateLimitError(30, SECRET_DETAIL)],
    ['StoreUnavailableError', new StoreUnavailableError(SECRET_DETAIL)],
    ['ConfigurationError', new ConfigurationError('invalid config', SECRET_DETAIL)],
    ['KeyError', new KeyError('invalid key', SECRET_DETAIL)],
  ];

  it('covers every error class in the taxonomy', () => {
    expect(WITH_DETAIL.length).toBe(ALL_ERRORS.length);
  });

  it.each(WITH_DETAIL)('%s keeps detail out of toResponse()', (_name, err) => {
    const serialized = JSON.stringify(err.toResponse());
    expect(serialized).not.toContain('paseto');
    expect(serialized).not.toContain('/srv/app');
    expect(serialized).not.toContain('kid=');
    expect(serialized).not.toContain('node_modules');
  });

  it('exposes only code and message — no extra keys ride along', () => {
    const err = new TokenInvalidError(SECRET_DETAIL);
    const body = err.toResponse();

    expect(Object.keys(body)).toEqual(['error']);
    expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    expect(body.error.message).toBe('Invalid authentication credentials');
  });

  it('still records detail server-side for diagnosis', () => {
    const err = new TokenInvalidError(SECRET_DETAIL);
    expect(err.detail).toBe(SECRET_DETAIL);
  });
});

/**
 * The four 401 authentication failures must be indistinguishable in the
 * response body beyond their code. If an attacker could tell "revoked" from
 * "malformed" via the message, they would learn whether a token was ever real.
 */
describe('401 responses do not explain themselves', () => {
  it('uses a generic message for every authentication failure', () => {
    const messages = [
      new TokenMissingError().message,
      new TokenInvalidError().message,
      new TokenExpiredError().message,
      new TokenRevokedError().message,
    ];
    for (const m of messages) {
      expect(m).not.toMatch(/signature|payload|claim|redis|store|key/i);
    }
  });

  it('gives reuse detection the same message as an ordinary refresh failure', () => {
    // The distinct code lets the host app react; the message must not tell an
    // attacker that theft detection fired.
    expect(new RefreshReuseError().message).toBe(new RefreshInvalidError().message);
  });
});

describe('toErrorResponse', () => {
  it('passes through a Ninsho error', () => {
    const { status, body } = toErrorResponse(new ForbiddenError('missing scope orders:write'));
    expect(status).toBe(403);
    expect(body.error.code).toBe('FORBIDDEN');
    expect(JSON.stringify(body)).not.toContain('orders:write');
  });

  it.each([
    ['a plain Error', new Error('connect ECONNREFUSED 10.0.0.5:6379')],
    ['a string', 'boom'],
    ['null', null],
    ['an object carrying secrets', { password: 'hunter2', token: 'abc' }],
  ])('collapses %s to a generic 500', (_label, thrown) => {
    const { status, body } = toErrorResponse(thrown);
    expect(status).toBe(500);
    expect(body.error.code).toBe('INTERNAL_ERROR');

    const serialized = JSON.stringify(body);
    expect(serialized).not.toContain('ECONNREFUSED');
    expect(serialized).not.toContain('10.0.0.5');
    expect(serialized).not.toContain('hunter2');
  });

  it('reports a non-Ninsho value as not a Ninsho error', () => {
    expect(isNinshoError(new Error('nope'))).toBe(false);
    expect(isNinshoError(undefined)).toBe(false);
  });
});

describe('RateLimitError', () => {
  it('carries retryAfter for the Retry-After header without exposing it in the body', () => {
    const err = new RateLimitError(847);
    expect(err.retryAfter).toBe(847);
    expect(Object.keys(err.toResponse().error).sort()).toEqual(['code', 'message']);
  });
});
