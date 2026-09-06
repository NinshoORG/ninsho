import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash } from 'node:crypto';
import { app, resetWorld } from './server.ts';

/**
 * The playground, tested over real HTTP.
 *
 * ─── Why a demo needs tests ───────────────────────────────────────────────
 * Every panel makes a claim to whoever is reading it: that the raw token is
 * never in the store, that a replayed refresh token kills the family, that a
 * reset link works exactly once. Those are the same claims the README makes,
 * restated to an audience with no way to check them.
 *
 * A demonstration that quietly stopped demonstrating would therefore be worse
 * than a broken test — it would be a page telling visitors something untrue
 * while looking entirely convincing. So each claim the UI prints is asserted
 * here against the running server.
 * ──────────────────────────────────────────────────────────────────────────
 */

let server: Server;
let baseUrl: string;

const sha256 = (value: string): string => createHash('sha256').update(value, 'utf8').digest('hex');

/**
 * A cookie jar, because the playground now gives each visitor their own world.
 *
 * Without one every request would arrive as a new visitor and see an empty
 * store — which is the isolation working, and useless for testing a sequence.
 */
class Visitor {
  #cookie: string | undefined;

  async request(path: string, method: string, body?: unknown): Promise<Record<string, unknown>> {
    const response = await fetch(`${baseUrl}${path}`, {
      method,
      headers: {
        'content-type': 'application/json',
        ...(this.#cookie !== undefined ? { cookie: this.#cookie } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });

    const set = (response.headers.getSetCookie?.() ?? []).find((c) =>
      c.startsWith('ninsho_playground='),
    );
    if (set !== undefined) this.#cookie = set.split(';')[0];

    return (await response.json()) as Record<string, unknown>;
  }

  post(path: string, body?: unknown): Promise<Record<string, unknown>> {
    return this.request(path, 'POST', body ?? {});
  }

  get(path: string): Promise<Record<string, unknown>> {
    return this.request(path, 'GET');
  }
}

/** The visitor most tests act as. */
let me: Visitor;

const call = (path: string, body?: unknown): Promise<Record<string, unknown>> =>
  me.post(path, body);
const get = (path: string): Promise<Record<string, unknown>> => me.get(path);

beforeAll(async () => {
  server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(async () => {
  await resetWorld();
  me = new Visitor();
});

/** The headline claim, and the one a visitor is invited to check themselves. */
describe('the raw token never reaches the store', () => {
  it('stores the hash and not the value', async () => {
    const created = await call('/api/session/create');
    const tokens = created['tokens'] as { accessToken: string; refreshToken: string };

    const store = await get('/api/store');
    const blob = JSON.stringify(store);

    expect(blob).not.toContain(tokens.accessToken);
    expect(blob).not.toContain(tokens.refreshToken);
    expect(blob).toContain(sha256(tokens.accessToken));
    expect(blob).toContain(sha256(tokens.refreshToken));
  });

  it('reports store operations that contain no raw token either', async () => {
    // The trace is what the page prints beside the tokens. If a credential
    // leaked into it, the panel would be displaying the very thing it says is
    // never written.
    const created = await call('/api/session/create');
    const tokens = created['tokens'] as { accessToken: string; refreshToken: string };
    const trace = JSON.stringify(created['trace']);

    expect(trace).not.toContain(tokens.accessToken);
    expect(trace).not.toContain(tokens.refreshToken);
  });

  it('namespaces and versions every key', async () => {
    await call('/api/session/create');
    const { keys } = (await get('/api/store')) as { keys: { key: string }[] };

    expect(keys.length).toBeGreaterThan(0);
    for (const entry of keys) expect(entry.key).toMatch(/^ninsho:v1:/);
  });
});

describe('the attacks actually fail', () => {
  it('refuses a replayed refresh token and kills the family', async () => {
    await call('/api/session/create');
    await call('/api/session/refresh');
    const result = await call('/api/attack/replay-refresh');

    expect(result['rejected']).toBe(true);
    expect(result['code']).toBe('REFRESH_REUSE_DETECTED');
    // The panel claims the legitimate token dies too. It must.
    expect(result['liveTokenStillWorks']).toBe(false);
  });

  it('classifies the replay as coming from a different client', async () => {
    // The demo presents the stolen token with a different user agent and
    // address, so the audit event should say so — that is the difference
    // between an alarm and an actionable one.
    await call('/api/session/create');
    await call('/api/session/refresh');
    const result = await call('/api/attack/replay-refresh');

    const events = (result['trace'] as { events: { type: string; signalMatch?: string }[] }).events;
    const reuse = events.find((e) => e.type === 'refresh.reuse_detected');

    expect(reuse).toBeDefined();
    expect(reuse?.signalMatch).toBe('different');
  });

  it('refuses a token with a single character changed', async () => {
    await call('/api/session/create');
    const result = await call('/api/attack/tamper-token');

    expect(result['rejected']).toBe(true);
    expect(result['code']).toBe('TOKEN_INVALID');
    // The panel shows both, so they must genuinely differ by one character.
    const original = result['original'] as string;
    const tampered = result['tampered'] as string;
    expect(tampered).not.toBe(original);
    expect(tampered.length).toBe(original.length);
  });

  it('accepts a reset link once and refuses it the second time', async () => {
    const result = await call('/api/attack/replay-reset-link');

    expect(result['first']).toBe('accepted');
    expect(result['second']).toBe('ONE_TIME_TOKEN_INVALID');
  });

  it('leaves exactly one link usable when two are raced', async () => {
    // The regression the panel says found a real bug. If it ever reports 2
    // again, the page is describing a fix that is no longer there.
    for (let round = 0; round < 5; round += 1) {
      await resetWorld();
      const result = await call('/api/attack/race-reset-links');
      expect(result['survivors'], `round ${round}`).toBe(1);
    }
  });

  it('refuses to replay before anything has been rotated', async () => {
    // The guard on the demo itself: replaying with nothing spent must not
    // produce a misleading "attack refused".
    await call('/api/session/create');
    const result = await call('/api/attack/replay-refresh');

    expect(result['ok']).toBe(false);
    expect(String(result['message'])).toMatch(/Refresh at least once/);
  });
});

describe('the anatomy decoders describe real artefacts', () => {
  it('maps WebAuthn authenticator data field by field', async () => {
    const result = await call('/api/anatomy/webauthn');
    const decodes = result['decodes'] as { title: string; fields: { name: string; offset: number; length: number }[] }[];

    const registration = decodes.find((d) => d.title.includes('registration'));
    expect(registration).toBeDefined();

    const names = registration!.fields.map((f) => f.name);
    expect(names).toEqual(
      expect.arrayContaining(['rpIdHash', 'flags', 'signCount', 'aaguid', 'credentialPublicKey']),
    );

    // The offsets are the reason the view exists, so they must be the spec's.
    const byName = (name: string) => registration!.fields.find((f) => f.name === name);
    expect(byName('rpIdHash')).toMatchObject({ offset: 0, length: 32 });
    expect(byName('flags')).toMatchObject({ offset: 32, length: 1 });
    expect(byName('signCount')).toMatchObject({ offset: 33, length: 4 });
    expect(byName('aaguid')).toMatchObject({ offset: 37, length: 16 });
  });

  it('breaks out all eight flag bits', async () => {
    const result = await call('/api/anatomy/webauthn');
    const decodes = result['decodes'] as { title: string; fields: { name: string }[] }[];
    const registration = decodes.find((d) => d.title.includes('registration'));

    const bits = registration!.fields.filter((f) => f.name.startsWith('bit '));
    expect(bits).toHaveLength(8);
  });

  it('shows an assertion carrying no credential', async () => {
    // The contrast that makes the registration decode legible: an assertion is
    // the 37-byte header alone, because carrying credential data would be
    // refused.
    const result = await call('/api/anatomy/webauthn');
    const decodes = result['decodes'] as { title: string; totalBytes: number }[];
    const assertion = decodes.find((d) => d.title.includes('assertion'));

    expect(assertion?.totalBytes).toBe(37);
  });

  it('decodes a PASETO token that carries no algorithm header', async () => {
    const result = await call('/api/anatomy/paseto');
    const token = result['token'] as string;
    expect(token.startsWith('v4.public.')).toBe(true);

    const fields = (result['decodes'] as { fields: { name: string; value: string }[] }[])[0]!.fields;
    const names = fields.map((f) => f.name);

    expect(names).toEqual(expect.arrayContaining(['version', 'purpose', 'payload', 'signature']));
    // The claim the panel makes: there is no `alg` to attack.
    expect(names).not.toContain('alg');
    expect(fields.find((f) => f.name === 'version')?.value).toBe('v4');
    expect(fields.find((f) => f.name === 'purpose')?.value).toBe('public');
  });

  it('carries auth_time in the payload, which rotation does not reset', async () => {
    const result = await call('/api/anatomy/paseto');
    const fields = (result['decodes'] as { fields: { name: string; value: string }[] }[])[0]!.fields;
    const payload = fields.find((f) => f.name === 'payload')?.value ?? '';

    expect(payload).toContain('auth_time');
  });

  it('accepts a DPoP proof once and refuses the replay', async () => {
    const result = await call('/api/anatomy/dpop');

    expect(result['firstUse']).toBe('accepted');
    expect(String(result['replay'])).toMatch(/already been used/);
  });
});

/**
 * The section a visitor does not have to take on trust — so the parts the
 * server can be held to are asserted here.
 */
describe('live DPoP binding', () => {
  const thumbprint = 'test-thumbprint-not-a-real-key';

  it('binds a token to a thumbprint', async () => {
    const result = await call('/api/dpop/bind', { thumbprint });

    expect(result['ok']).toBe(true);
    expect(typeof result['accessToken']).toBe('string');
  });

  it('refuses the token presented with no proof at all', async () => {
    // Exactly what a thief who exfiltrated the token holds. This is the claim
    // the whole mechanism rests on.
    await call('/api/dpop/bind', { thumbprint });
    const result = await call('/api/dpop/call', { thumbprint, omitProof: true });

    expect(result['accepted']).toBe(false);
    expect(String(result['detail'])).toMatch(/proof/i);
  });

  it('refuses a malformed proof', async () => {
    await call('/api/dpop/bind', { thumbprint });
    const result = await call('/api/dpop/call', { thumbprint, proof: 'not.a.proof' });

    expect(result['accepted']).toBe(false);
  });

  it('refuses a call for a thumbprint that never bound', async () => {
    const result = await call('/api/dpop/call', { thumbprint: 'never-seen', proof: 'x' });
    expect(result['ok']).toBe(false);
  });
});

/**
 * Sharing one world was fine on a laptop and wrong the moment two people open
 * the page — and it would have misrepresented the library, since a visitor
 * seeing keys they did not create would reasonably conclude Ninsho leaks state
 * between callers.
 */
describe('visitors do not see each other', () => {
  it('gives each visitor their own keyspace', async () => {
    const alice = new Visitor();
    const bob = new Visitor();

    const created = await alice.post('/api/session/create');
    const tokens = created['tokens'] as { accessToken: string };

    const bobsStore = (await bob.get('/api/store')) as { keys: unknown[] };
    expect(bobsStore.keys).toHaveLength(0);
    expect(JSON.stringify(bobsStore)).not.toContain(tokens.accessToken);

    // And Alice still has hers.
    const alicesStore = (await alice.get('/api/store')) as { keys: unknown[] };
    expect(alicesStore.keys.length).toBeGreaterThan(0);
  });

  it('does not let one visitor’s replay revoke another’s session', async () => {
    // The demonstration that revokes a family. If worlds were shared it would
    // sign out whoever else was midway through the page.
    const alice = new Visitor();
    const bob = new Visitor();

    await alice.post('/api/session/create');
    await bob.post('/api/session/create');
    await bob.post('/api/session/refresh');
    await bob.post('/api/attack/replay-refresh');

    const alicesVerify = await alice.post('/api/session/verify');
    expect(alicesVerify['ok']).toBe(true);
  });

  it('resets only the visitor who asked', async () => {
    const alice = new Visitor();
    const bob = new Visitor();

    await alice.post('/api/session/create');
    await bob.post('/api/session/create');
    await bob.post('/api/reset');

    expect(((await alice.get('/api/store')) as { keys: unknown[] }).keys.length).toBeGreaterThan(0);
    expect(((await bob.get('/api/store')) as { keys: unknown[] }).keys).toHaveLength(0);
  });
});

describe('the demonstration surface itself', () => {
  it('serves the browser client from the package it was built from', async () => {
    // Vendoring a copy would let it go stale, and the section's whole point is
    // that the page runs the code an application installs.
    const response = await fetch(`${baseUrl}/vendor/index.js`);
    const source = await response.text();

    expect(response.status).toBe(200);
    expect(source).toContain('generateDpopKey');
  });

  it('starts clean after a reset', async () => {
    await call('/api/session/create');
    expect(((await get('/api/store')) as { keys: unknown[] }).keys.length).toBeGreaterThan(0);

    await call('/api/reset');
    expect(((await get('/api/store')) as { keys: unknown[] }).keys).toHaveLength(0);
  });
});

/**
 * The attestation panel prints a verdict beside a claim about what *should*
 * have happened. If the panel ever printed "refused, as expected" while the
 * verifier had in fact accepted the ceremony, the page would be reassuring
 * visitors with the opposite of the truth — so the two are checked against
 * each other here rather than only rendered next to each other.
 */
describe('the attestation panel demonstrates real verification', () => {
  const attest = (format: string, scenario: string): Promise<Record<string, unknown>> =>
    call('/api/attestation', { format, scenario });

  type Verdict = { accepted: boolean; type?: string; format?: string; detail?: string; aaguidVerified?: boolean; aaguid?: string };

  it.each(['packed', 'apple', 'tpm', 'fido-u2f', 'android-key', 'android-safetynet'])(
    'accepts a genuine %s ceremony against the root that issued it',
    async (format) => {
      const result = await attest(format, 'genuine');
      const verdict = result['verdict'] as Verdict;

      expect(result['expected']).toBe('accepted');
      expect(verdict.accepted).toBe(true);
      expect(verdict.format).toBe(format);
      expect(verdict.type).toBe('basic');
    },
  );

  it.each(['packed', 'apple', 'tpm', 'fido-u2f', 'android-key', 'android-safetynet'])(
    'refuses a %s ceremony with no trust anchors',
    async (format) => {
      // The scenario the panel exists to make vivid: the chain is genuine and
      // the verifier still refuses, because a chain checked against no root
      // proves nothing.
      const result = await attest(format, 'no-anchors');
      const verdict = result['verdict'] as Verdict;

      expect(result['expected']).toBe('refused');
      expect(verdict.accepted).toBe(false);
      expect(String(verdict.detail)).toMatch(/requires trustAnchors/);
    },
  );

  it.each(['packed', 'apple', 'tpm', 'fido-u2f', 'android-key', 'android-safetynet'])(
    'refuses a %s ceremony checked against the wrong root',
    async (format) => {
      const result = await attest(format, 'wrong-root');
      const verdict = result['verdict'] as Verdict;

      expect(verdict.accepted).toBe(false);
      expect(String(verdict.detail)).toMatch(/does not reach a trusted root/);
    },
  );

  it.each(['packed', 'tpm', 'fido-u2f', 'android-key', 'android-safetynet'])(
    'refuses a %s ceremony whose signature was tampered with',
    async (format) => {
      // `apple` is absent on purpose: the format carries no signature to
      // tamper with, which is itself worth knowing.
      const result = await attest(format, 'tampered');
      const verdict = result['verdict'] as Verdict;

      expect(verdict.accepted).toBe(false);
      expect(String(verdict.detail)).toMatch(/did not verify/);
    },
  );

  it('refuses a format name the library does not know, even allowlisted', async () => {
    // Every format WebAuthn defines is verified now, so the panel offers a
    // real format from somewhere else — Apple's App Attest — to show that the
    // mechanism still fails closed rather than the gap it used to demonstrate.
    const result = await attest('appattest', 'genuine');
    const verdict = result['verdict'] as Verdict;

    expect(result['expected']).toBe('refused');
    expect(verdict.accepted).toBe(false);
    expect(String(verdict.detail)).toMatch(/cannot be verified/);
  });

  it('reports android-safetynet as vouching for a device, not a model', async () => {
    // The panel's most easily overstated claim about the weakest format:
    // Google inspected the phone, and said nothing about where the key lives.
    const result = await attest('android-safetynet', 'genuine');
    const verdict = result['verdict'] as Verdict;

    expect(verdict.accepted).toBe(true);
    expect(verdict.aaguidVerified).toBe(false);
  });

  it('reads android-key from the hardware-enforced authorization list', async () => {
    // What the panel claims about the format, and the claim most easily
    // overstated: a software-enforced list is the OS vouching for itself.
    const result = await attest('android-key', 'genuine');
    const statement = result['statement'] as { name: string; note: string }[];

    const x5c = statement.find((f) => f.name === 'x5c');
    expect(x5c?.note).toMatch(/key description/);
    expect((result['verdict'] as Verdict).accepted).toBe(true);
  });

  it('reports fido-u2f as conveying no verified AAGUID', async () => {
    // The panel's most easily-overstated claim. U2F has no model identifier,
    // so a verified statement proves the hardware and says nothing about which
    // device it is.
    const result = await attest('fido-u2f', 'genuine');
    const verdict = result['verdict'] as Verdict;

    expect(verdict.accepted).toBe(true);
    expect(verdict.aaguidVerified).toBe(false);
    expect(verdict.aaguid).toBe('0'.repeat(32));
  });

  it('reports packed as vouching for the AAGUID', async () => {
    const result = await attest('packed', 'genuine');
    const verdict = result['verdict'] as Verdict;

    expect(verdict.aaguidVerified).toBe(true);
    expect(verdict.aaguid).not.toBe('0'.repeat(32));
  });

  it('annotates the statement fields the format actually carries', async () => {
    const result = await attest('tpm', 'genuine');
    const statement = result['statement'] as { name: string; note: string }[];

    expect(statement.map((f) => f.name)).toEqual(
      expect.arrayContaining(['ver', 'alg', 'sig', 'certInfo', 'pubArea', 'x5c']),
    );
    // Every field carries an explanation, or the table is a hex dump with
    // extra steps.
    for (const field of statement) expect(field.note.length).toBeGreaterThan(20);
  });

  it('shows apple carrying a certificate and no signature', async () => {
    const result = await attest('apple', 'genuine');
    const statement = result['statement'] as { name: string }[];

    expect(statement.map((f) => f.name)).toEqual(['x5c']);
  });

  it('shows the none statement as empty', async () => {
    const result = await attest('none', 'genuine');
    const statement = result['statement'] as { name: string }[];

    expect(statement.map((f) => f.name)).toEqual(['(empty)']);
    expect((result['verdict'] as Verdict).accepted).toBe(true);
    expect((result['verdict'] as Verdict).type).toBe('none');
  });

  it('decodes the bytes of whichever ceremony it just ran', async () => {
    const result = await attest('tpm', 'genuine');
    const decodes = result['decodes'] as { title: string; fields: { name: string }[] }[];

    const authData = decodes.find((d) => d.title.includes('authenticatorData'));
    expect(authData?.fields.map((f) => f.name)).toEqual(
      expect.arrayContaining(['rpIdHash', 'flags', 'signCount', 'aaguid']),
    );
  });

  it('refuses a format or scenario it does not offer', async () => {
    const response = await fetch(`${baseUrl}/api/attestation`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ format: 'not-a-format', scenario: 'genuine' }),
    });
    expect(response.status).toBe(400);
  });
});

/**
 * The rate-limit panel makes four claims a visitor cannot check by looking.
 *
 * The X-Forwarded-For one is the reason these tests exist rather than a
 * screenshot: writing this panel is what found the resolution off-by-one, and
 * before the fix the demonstration showed five separate buckets and zero
 * refusals while its own prose said the opposite.
 */
describe('the rate-limit panel demonstrates real limiting', () => {
  it('stops credential stuffing that no per-IP bucket would notice', async () => {
    const result = await call('/api/attack/credential-stuffing');
    const attempts = result['attempts'] as { ip: string; allowed: boolean }[];

    expect(result['rejected']).toBe(true);

    // Every attempt from a different address, and none of them near the
    // per-IP allowance — so the per-account bucket is doing all the work.
    const addresses = new Set(attempts.map((a) => a.ip));
    expect(addresses.size).toBe(attempts.length);
    expect(attempts.length).toBeLessThan(result['perIpLimit'] as number);

    expect(result['allowedAttempts']).toBe(result['perAccountLimit']);
    expect(result['blockedAttempts']).toBeGreaterThan(0);
  });

  it('does not sign out a bystander behind the same address', async () => {
    const result = await call('/api/attack/nat-bystander');
    const outcomes = result['outcomes'] as string[];
    const claim = result['claim'] as { text: string; holds: boolean };

    // The last line is the bystander's first ever attempt.
    expect(outcomes[outcomes.length - 1]).toContain('allowed');
    expect(claim.holds).toBe(true);
    expect(claim.text).not.toContain('bug');
    // And the colleague really was limited, or the test proves nothing.
    expect(outcomes.filter((o) => o.includes('refused')).length).toBeGreaterThan(0);
  });

  it('resolves every forged X-Forwarded-For chain to one bucket', async () => {
    // REGRESSION. With the resolution off by one this returned five distinct
    // buckets and refused nothing: rotating the header minted a fresh
    // allowance per request, which is the limiter counting nothing at all.
    const result = await call('/api/attack/forged-forwarded-for');
    const attempts = result['attempts'] as { forwarded: string; allowed: boolean }[];

    expect(result['rejected']).toBe(true);
    expect(result['blockedAttempts']).toBe(attempts.length - (result['perIpLimit'] as number));

    // Each attempt prepended more invented hops, and none of them helped.
    const chains = new Set(attempts.map((a) => a.forwarded));
    expect(chains.size).toBe(attempts.length);

    const buckets = new Set(
      (result['trace'] as { storeOps: { key: string }[] }).storeOps
        .filter((op) => op.key.includes(':ip:'))
        .map((op) => op.key.split(':ip:')[1]?.split(':')[0]),
    );
    expect([...buckets]).toEqual([result['resolvedTo']]);
  });

  it('does not permit a double burst across a window boundary', async () => {
    // A fixed-window counter resets on the tick, so spending the allowance
    // either side of it yields twice the limit in a moment.
    const result = await call('/api/attack/window-boundary');

    expect(result['requestsSent']).toBe(8);
    expect(result['allowedTotal']).toBeLessThan(8);
    expect(result['rejected']).toBe(true);
  });
});

/**
 * What changes when the page is reachable from the internet.
 *
 * These are deployment properties rather than demonstrations, and they are
 * asserted for the same reason the demonstrations are: a security library
 * whose own demo hands out free CPU and serves without a content policy is
 * making an argument against itself.
 */
describe('the deployment surface', () => {
  it('answers a health probe without creating a visitor world', async () => {
    // A probe every few seconds would otherwise leave the sweeper clearing up
    // after the load balancer for the life of the process.
    const before = (await get('/health'))['worlds'] as number;
    await get('/health');
    await get('/health');
    const after = (await get('/health'))['worlds'] as number;

    expect(after).toBe(before);
  });

  it('reports its status outside the rate-limited API', async () => {
    const res = await fetch(`${baseUrl}/health`);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ status: 'ok' });
  });

  it('serves the page with a policy strict enough to matter', async () => {
    // Every script and style the page loads is its own, from this origin, with
    // no CDN and no inline handlers — so the policy can be strict, and a demo
    // that had to relax its own would be a poor advertisement.
    const res = await fetch(`${baseUrl}/`);
    const csp = res.headers.get('content-security-policy') ?? '';

    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain('unsafe-eval');

    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('referrer-policy')).toBe('no-referrer');
    expect(res.headers.get('x-powered-by')).toBeNull();
  });

  it('carries the same headers on the API, not only on the page', async () => {
    const res = await fetch(`${baseUrl}/api/store`);
    expect(res.headers.get('content-security-policy')).toContain("default-src 'none'");
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
  });

  it('limits the routes that mint keys', async () => {
    // `/api/attestation` generates an RSA key per SafetyNet or metadata run —
    // about 100ms of CPU, unauthenticated. Worth demonstrating; not worth
    // serving thousands of times a minute to one visitor.
    const attempts: number[] = [];
    for (let i = 0; i < 25; i += 1) {
      const res = await fetch(`${baseUrl}/api/attestation`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ format: 'none', scenario: 'genuine' }),
      });
      attempts.push(res.status);
    }

    expect(attempts).toContain(429);
    // And the limit is the expensive one, not the general API allowance.
    expect(attempts.filter((s) => s === 200).length).toBeLessThanOrEqual(20);
  });

  it('answers a refused request the way the library does', async () => {
    for (let i = 0; i < 25; i += 1) {
      await fetch(`${baseUrl}/api/attestation`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ format: 'none', scenario: 'genuine' }),
      });
    }

    const res = await fetch(`${baseUrl}/api/attestation`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ format: 'none', scenario: 'genuine' }),
    });

    expect(res.status).toBe(429);
    expect(res.headers.get('retry-after')).toBeTruthy();
    expect(await res.json()).toMatchObject({ error: { code: 'RATE_LIMIT_EXCEEDED' } });
  });
});

/**
 * Two things the HTTP tests could not see, both found in a browser.
 *
 * The suite drives the API. The page drives the API *and* renders the result,
 * and the strict Content Security Policy applies to the rendering — so a
 * violation there is invisible here unless it is asserted deliberately.
 */
describe('the page satisfies its own content policy', () => {
  it('ships no inline style attributes to apply', async () => {
    // REGRESSION. The byte-map renderer indented nested fields with
    // `style="padding-left:2rem"`, which `style-src 'self'` forbids: the rows
    // rendered flat and the console filled with violations. A demonstration
    // that had to relax its own policy to indent a table would be arguing
    // against itself, so the indent is a class and the policy stays.
    const client = await fetch(`${baseUrl}/app.js`);
    const source = await client.text();

    expect(source).not.toMatch(/style\s*=\s*["'`]/);
    expect(source).toContain('nested');

    const page = await fetch(`${baseUrl}/`);
    expect(await page.text()).not.toMatch(/<[^>]+\sstyle\s*=/);
  });

  it('defines the class the renderer reaches for', async () => {
    // The other half: a class nothing styles indents nothing, and the page
    // would look correct in a test and wrong on screen.
    const css = await (await fetch(`${baseUrl}/style.css`)).text();
    expect(css).toMatch(/\.nested\s*\{[^}]*padding-left/);
  });
});

/**
 * The browser posts with a JSON content type and no body for every button that
 * takes no arguments. The tests always send `{}`, so this shape was never
 * exercised — and Express 5's body parser is stricter than Express 4's about
 * what an empty body means.
 */
describe('a button that sends no body', () => {
  it.each([
    ['/api/session/create'],
    ['/api/anatomy/webauthn'],
    ['/api/attack/credential-stuffing'],
  ])('is accepted at %s, as the page sends it', async (path) => {
    const res = await fetch(`${baseUrl}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
    });

    expect(res.status).toBe(200);
  });
});
