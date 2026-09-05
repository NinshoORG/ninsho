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
