import { describe, it, expect } from 'vitest';
import { ConfigurationError } from '@ninsho/core';
import { MemoryStore } from '../store/memory.js';
import { MemoryAuditSink } from '../audit.js';
import { generateKeyPair } from '../keys/keyring.js';
import { resolveConfig, DEFAULTS, type NinshoConfig } from '../config.js';

const store = new MemoryStore();
const KEY = generateKeyPair('test-key');
const base = (overrides: Partial<NinshoConfig> = {}): NinshoConfig => ({
  store,
  ...overrides,
});

/**
 * Defaults are a security decision, so they are asserted rather than assumed.
 *
 * Two of these are direct reversals of audit findings: the predecessor
 * defaulted to fail-open (so a store outage silently disabled revocation, its
 * headline feature) and to a 15-minute access token.
 */
describe('secure defaults', () => {
  it('defaults to the opaque strategy, which needs no signing keys', () => {
    expect(resolveConfig(base()).strategy).toBe('opaque');
    expect(DEFAULTS.strategy).toBe('opaque');
  });

  it('defaults to fail-closed', () => {
    expect(resolveConfig(base()).onStoreError).toBe('closed');
    expect(DEFAULTS.onStoreError).toBe('closed');
  });

  it('defaults to bearer semantics, not an unimplemented binding', () => {
    expect(resolveConfig(base()).binding).toBe('none');
  });

  it('defaults to a 5-minute access token', () => {
    expect(resolveConfig(base()).accessTokenTtl).toBe(300);
  });

  it('defaults to a 7-day refresh token', () => {
    expect(resolveConfig(base()).refreshTokenTtl).toBe(604_800);
  });

  it('raises no warnings for the default configuration', () => {
    expect(resolveConfig(base()).warnings).toEqual([]);
  });
});

describe('store validation', () => {
  it.each([
    ['undefined', undefined],
    ['null', null],
  ])('rejects a %s store', (_label, value) => {
    expect(() => resolveConfig({ store: value } as unknown as NinshoConfig)).toThrow(
      ConfigurationError,
    );
  });

  it('names the missing methods when given something that is not a store', () => {
    expect(() =>
      resolveConfig({ store: { get: () => null } } as unknown as NinshoConfig),
    ).toThrow(/Missing:.*set/);
  });

  it('rejects a non-object configuration', () => {
    expect(() => resolveConfig(null as unknown as NinshoConfig)).toThrow(ConfigurationError);
  });
});

describe('strategy validation', () => {
  it('rejects an unknown strategy', () => {
    expect(() => resolveConfig(base({ strategy: 'jwt' as never }))).toThrow(
      /must be one of: opaque, paseto/,
    );
  });

  it('accepts paseto when it is fully configured', () => {
    const resolved = resolveConfig(
      base({
        strategy: 'paseto',
        issuer: 'https://id.acme.test',
        audience: 'orders-api',
        keys: { active: KEY },
      }),
    );
    expect(resolved.strategy).toBe('paseto');
    expect(resolved.issuer).toBe('https://id.acme.test');
    expect(resolved.audience).toBe('orders-api');
  });
});

/**
 * Audit finding H4. These are required rather than defaulted, because a
 * silently-defaulted issuer or audience is worse than none: it looks like
 * scoping while matching everywhere.
 */
describe('paseto requirements', () => {
  it.each(['issuer', 'audience', 'keys'] as const)('requires %s', (field) => {
    const full = {
      strategy: 'paseto' as const,
      issuer: 'https://id.acme.test',
      audience: 'orders-api',
      keys: { active: KEY },
    };
    const { [field]: _omitted, ...rest } = full;
    expect(() => resolveConfig(base(rest))).toThrow(new RegExp(`config\\.${field}`));
  });

  it.each([
    ['an empty string', ''],
    ['whitespace only', '   '],
  ])('rejects an issuer that is %s', (_label, value) => {
    expect(() =>
      resolveConfig(
        base({ strategy: 'paseto', issuer: value, audience: 'a', keys: { active: KEY } }),
      ),
    ).toThrow(ConfigurationError);
  });

  /**
   * Setting an audience under the opaque strategy would silently do nothing.
   * A developer who configured it expects it to be enforced somewhere, so the
   * mismatch is an error rather than a no-op.
   */
  it.each(['issuer', 'audience', 'keys'] as const)(
    'rejects %s when the strategy is opaque',
    (field) => {
      const value = field === 'keys' ? { active: KEY } : 'something';
      expect(() => resolveConfig(base({ [field]: value }))).toThrow(
        /only meaningful when strategy is 'paseto'/,
      );
    },
  );

  it('leaves the paseto fields undefined under the opaque strategy', () => {
    const resolved = resolveConfig(base());
    expect(resolved.issuer).toBeUndefined();
    expect(resolved.audience).toBeUndefined();
    expect(resolved.keys).toBeUndefined();
  });
});

describe('binding validation', () => {
  it('accepts none', () => {
    expect(resolveConfig(base({ binding: 'none' })).binding).toBe('none');
  });

  it('accepts dpop, enabling proof-of-possession', () => {
    const resolved = resolveConfig(base({ binding: 'dpop' }));
    expect(resolved.binding).toBe('dpop');
  });

  it('defaults the DPoP proof window to 60 seconds', () => {
    expect(resolveConfig(base({ binding: 'dpop' })).dpopProofMaxAgeSeconds).toBe(60);
  });

  /**
   * Setting the proof window under bearer semantics would suggest a proof is
   * being checked when none is — the same class of false assurance as silently
   * accepting `dpop` used to be.
   */
  it('rejects a DPoP proof window under bearer semantics', () => {
    expect(() => resolveConfig(base({ dpopProofMaxAgeSeconds: 30 }))).toThrow(
      /only meaningful when binding is 'dpop'/,
    );
  });

  it.each([0, -1, Number.NaN])('rejects a proof window of %s', (value) => {
    expect(() =>
      resolveConfig(base({ binding: 'dpop', dpopProofMaxAgeSeconds: value })),
    ).toThrow(ConfigurationError);
  });

  it('warns about a proof window wide enough to blunt replay protection', () => {
    const resolved = resolveConfig(base({ binding: 'dpop', dpopProofMaxAgeSeconds: 3600 }));
    expect(resolved.warnings.join(' ')).toMatch(/captured proof usable/);
  });

  it('rejects an unknown binding', () => {
    expect(() => resolveConfig(base({ binding: 'fingerprint' as never }))).toThrow(
      /must be one of: none, dpop/,
    );
  });
});

describe('failure mode', () => {
  const paseto = (overrides: Partial<NinshoConfig> = {}): NinshoConfig =>
    base({
      strategy: 'paseto',
      issuer: 'https://id.acme.test',
      audience: 'orders-api',
      keys: { active: KEY },
      ...overrides,
    });

  it('accepts open under paseto but records a warning', () => {
    const resolved = resolveConfig(paseto({ onStoreError: 'open' }));
    expect(resolved.onStoreError).toBe('open');
    expect(resolved.warnings.join(' ')).toMatch(/revoked tokens will be accepted/i);
  });

  /**
   * Fail-open is only coherent for a strategy that can establish identity
   * without the store. Under `opaque` the store *is* the identity, so "open"
   * would mean admitting a request whose caller is unknown — the setting could
   * never take effect, and accepting it silently would leave a developer
   * believing they had configured graceful degradation.
   */
  it('rejects open under opaque, where it could never take effect', () => {
    expect(() => resolveConfig(base({ onStoreError: 'open' }))).toThrow(
      /has no meaning with the 'opaque' strategy/,
    );
  });

  it('explains the two ways forward when it rejects that combination', () => {
    expect(() => resolveConfig(base({ onStoreError: 'open' }))).toThrow(
      /fail-closed posture, or switch to the 'paseto' strategy/,
    );
  });

  it('accepts the fail-closed default under either strategy', () => {
    expect(resolveConfig(base()).onStoreError).toBe('closed');
    expect(resolveConfig(paseto()).onStoreError).toBe('closed');
  });

  it('rejects an unknown failure mode', () => {
    expect(() => resolveConfig(base({ onStoreError: 'retry' as never }))).toThrow(
      /must be one of: closed, open/,
    );
  });
});

describe('TTL validation', () => {
  it.each([
    ['zero', 0],
    ['negative', -1],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['a string', '300'],
    ['fractional', 300.5],
  ])('rejects an accessTokenTtl that is %s', (_label, value) => {
    expect(() => resolveConfig(base({ accessTokenTtl: value as number }))).toThrow(
      ConfigurationError,
    );
  });

  it.each([
    ['zero', 0],
    ['negative', -1],
    ['NaN', Number.NaN],
  ])('rejects a refreshTokenTtl that is %s', (_label, value) => {
    expect(() => resolveConfig(base({ refreshTokenTtl: value as number }))).toThrow(
      ConfigurationError,
    );
  });

  it('rejects a refresh TTL that is not longer than the access TTL', () => {
    expect(() =>
      resolveConfig(base({ accessTokenTtl: 3600, refreshTokenTtl: 3600 })),
    ).toThrow(/must be greater than/);
  });

  it('rejects an access TTL beyond a day as an obvious mistake', () => {
    expect(() =>
      resolveConfig(base({ accessTokenTtl: 86_401, refreshTokenTtl: 200_000 })),
    ).toThrow(/did you mean refreshTokenTtl/);
  });

  it('warns about a long-lived access token without refusing it', () => {
    const resolved = resolveConfig(base({ accessTokenTtl: 7200 }));
    expect(resolved.accessTokenTtl).toBe(7200);
    expect(resolved.warnings.join(' ')).toMatch(/Long-lived access tokens/);
  });

  it('accepts a short access TTL without complaint', () => {
    expect(resolveConfig(base({ accessTokenTtl: 60 })).warnings).toEqual([]);
  });
});

describe('refresh grace window', () => {
  it('defaults to 30 seconds', () => {
    expect(resolveConfig(base()).refreshGraceSeconds).toBe(30);
  });

  it('accepts zero, meaning every replay counts as reuse', () => {
    expect(resolveConfig(base({ refreshGraceSeconds: 0 })).refreshGraceSeconds).toBe(0);
  });

  it('rejects a negative window', () => {
    expect(() => resolveConfig(base({ refreshGraceSeconds: -1 }))).toThrow(ConfigurationError);
  });

  /**
   * A replay inside the window is indistinguishable from a legitimate parallel
   * tab, so a wide window is a period during which a stolen token can be used
   * undetected. Valid, but the developer should know.
   */
  it('warns about a wide window without refusing it', () => {
    const resolved = resolveConfig(base({ refreshGraceSeconds: 600 }));
    expect(resolved.refreshGraceSeconds).toBe(600);
    expect(resolved.warnings.join(' ')).toMatch(/replayed undetected/);
  });

  it('rejects a window as long as the refresh lifetime, which would disable detection', () => {
    expect(() =>
      resolveConfig(base({ refreshTokenTtl: 3600, refreshGraceSeconds: 3600 })),
    ).toThrow(/reuse is never detected/);
  });

  it('raises no warning at the default', () => {
    expect(resolveConfig(base({ refreshGraceSeconds: 30 })).warnings).toEqual([]);
  });
});

describe('clock tolerance', () => {
  it('defaults to 5 seconds', () => {
    expect(resolveConfig(base()).clockToleranceSeconds).toBe(5);
  });

  it('accepts zero', () => {
    expect(resolveConfig(base({ clockToleranceSeconds: 0 })).clockToleranceSeconds).toBe(0);
  });

  it('rejects a negative tolerance', () => {
    expect(() => resolveConfig(base({ clockToleranceSeconds: -1 }))).toThrow(ConfigurationError);
  });

  /**
   * A tolerance wider than the token lifetime would keep every token valid
   * past its own expiry — a configuration that quietly disables expiry
   * altogether.
   */
  it('rejects a tolerance wider than the access token lifetime', () => {
    expect(() =>
      resolveConfig(base({ accessTokenTtl: 300, clockToleranceSeconds: 301 })),
    ).toThrow(/would keep every token valid past its own expiry/);
  });
});

describe('audit sink', () => {
  it('accepts a custom sink', () => {
    const sink = new MemoryAuditSink();
    const resolved = resolveConfig(base({ audit: sink }));
    resolved.audit.emit({ type: 'session.created', at: new Date().toISOString() });
    expect(sink.events).toHaveLength(1);
  });

  it('rejects something that is not a sink', () => {
    expect(() => resolveConfig(base({ audit: {} as never }))).toThrow(/must implement AuditSink/);
  });

  /**
   * Auditing is best-effort: a broken log transport must not be able to deny
   * authentication. The failure still surfaces on stderr rather than vanishing.
   */
  it('does not let a throwing sink propagate', () => {
    const resolved = resolveConfig(
      base({
        audit: {
          emit: () => {
            throw new Error('log pipeline down');
          },
        },
      }),
    );
    expect(() =>
      resolved.audit.emit({ type: 'session.created', at: new Date().toISOString() }),
    ).not.toThrow();
  });
});

describe('error reporting', () => {
  it('names the offending field so a misconfiguration is actionable', () => {
    expect(() => resolveConfig(base({ accessTokenTtl: -5 }))).toThrow(/config\.accessTokenTtl/);
  });

  it('surfaces configuration errors as developer-facing 500s, not client 4xxs', () => {
    // These are thrown at construction; a server that hits one never serves.
    const error = (() => {
      try {
        resolveConfig(base({ accessTokenTtl: -5 }));
        return null;
      } catch (e) {
        return e as ConfigurationError;
      }
    })();

    expect(error?.status).toBe(500);
    expect(error?.code).toBe('CONFIGURATION_ERROR');
  });
});
