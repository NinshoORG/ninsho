import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { MemoryStore } from '@ninsho/server';
import { VirtualAuthenticator, FLAG_UP, FLAG_UV, FLAG_AT } from '@ninsho/webauthn/testing';
import { createApp } from './app.js';
import { resetUsers } from './users.js';
import { resetCredentials } from './credentials.js';

/**
 * Passkeys, end to end over real HTTP.
 *
 * ─── Why this file exists ─────────────────────────────────────────────────
 * `packages/webauthn` tests the verifier against a virtual authenticator
 * directly. That proves the ceremony logic. It cannot prove that the routes
 * around it are wired correctly — that the challenge is consumed at the right
 * moment, that the counter is written back, that a rejection maps to a 401
 * rather than a 500, that adding a passkey requires a session.
 *
 * Those are the mistakes an integration makes, and they are invisible to a
 * unit test of the library. So the whole thing runs over a real socket, with
 * an authenticator holding real keys and producing real signatures.
 *
 * The RP ID and origin are pinned so the authenticator and the server agree on
 * what site this is — in a browser that is the page's own origin; here it has
 * to be stated.
 * ──────────────────────────────────────────────────────────────────────────
 */

const RP_ID = 'localhost';
const ORIGIN = 'https://localhost';
const PASSWORD = 'correct-horse-battery-staple';

let server: Server;
let baseUrl: string;
let store: MemoryStore;

interface Json {
  readonly status: number;
  readonly body: Record<string, unknown>;
  readonly headers: Headers;
}

async function call(
  path: string,
  init: RequestInit & { token?: string } = {},
): Promise<Json> {
  const headers = new Headers(init.headers);
  headers.set('content-type', 'application/json');
  if (init.token !== undefined) headers.set('authorization', `Bearer ${init.token}`);

  const response = await fetch(`${baseUrl}${path}`, { ...init, headers, redirect: 'manual' });
  const text = await response.text();
  return {
    status: response.status,
    body: text.length > 0 ? (JSON.parse(text) as Record<string, unknown>) : {},
    headers: response.headers,
  };
}

const b64u = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');
const fromB64u = (value: string): Uint8Array => new Uint8Array(Buffer.from(value, 'base64url'));

async function signUp(email: string): Promise<{ token: string; id: string }> {
  const res = await call('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ email, password: PASSWORD }),
  });
  return {
    token: res.body['accessToken'] as string,
    id: (res.body['user'] as { id: string }).id,
  };
}

/** Runs the full registration ceremony through the HTTP API. */
async function addPasskey(
  token: string,
  authenticator: VirtualAuthenticator,
  overrides: { origin?: string; rpId?: string; flags?: number } = {},
): Promise<Json> {
  const start = await call('/auth/passkey/register/start', { method: 'POST', token });
  const options = start.body as { challenge: string };

  const response = await authenticator.register({
    challenge: fromB64u(options.challenge),
    origin: overrides.origin ?? ORIGIN,
    rpId: overrides.rpId ?? RP_ID,
    ...(overrides.flags !== undefined ? { flags: overrides.flags } : {}),
  });

  return call('/auth/passkey/register/finish', {
    method: 'POST',
    token,
    body: JSON.stringify({
      clientDataJSON: b64u(response.clientDataJSON),
      attestationObject: b64u(response.attestationObject),
    }),
  });
}

/** Runs the full sign-in ceremony through the HTTP API. */
async function signInWithPasskey(
  authenticator: VirtualAuthenticator,
  overrides: { origin?: string; rpId?: string; signCount?: number; userHandle?: string } = {},
): Promise<Json> {
  const start = await call('/auth/passkey/login/start', { method: 'POST' });
  const options = start.body as { challenge: string };

  const assertion = await authenticator.authenticate({
    challenge: fromB64u(options.challenge),
    origin: overrides.origin ?? ORIGIN,
    rpId: overrides.rpId ?? RP_ID,
    ...(overrides.signCount !== undefined ? { signCount: overrides.signCount } : {}),
    ...(overrides.userHandle !== undefined
      ? { userHandle: new TextEncoder().encode(overrides.userHandle) }
      : {}),
  });

  return call('/auth/passkey/login/finish', {
    method: 'POST',
    body: JSON.stringify({
      credentialId: b64u(assertion.credentialId),
      clientDataJSON: b64u(assertion.clientDataJSON),
      authenticatorData: b64u(assertion.authenticatorData),
      signature: b64u(assertion.signature),
      ...(assertion.userHandle ? { userHandle: b64u(assertion.userHandle) } : {}),
    }),
  });
}

beforeEach(async () => {
  resetUsers();
  resetCredentials();
  store = new MemoryStore();
  const { app } = createApp({
    store,
    secureCookies: false,
    trustProxy: false,
    rpId: RP_ID,
    webauthnOrigin: ORIGIN,
  });

  server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await store.close();
});

describe('adding a passkey', () => {
  it('registers one and returns a usable session afterwards', async () => {
    const { token, id } = await signUp('ada@example.test');
    const authenticator = await VirtualAuthenticator.create();

    const added = await addPasskey(token, authenticator);
    expect(added.status).toBe(201);
    expect(added.body['credentialId']).toBe(b64u(authenticator.credentialId));

    const signIn = await signInWithPasskey(authenticator);
    expect(signIn.status).toBe(200);
    expect((signIn.body['user'] as { id: string }).id).toBe(id);
    expect(signIn.body['accessToken']).toBeTruthy();

    // The token the passkey produced is a normal Ninsho session token.
    const me = await call('/me', { token: signIn.body['accessToken'] as string });
    expect(me.status).toBe(200);
    expect(me.body['email']).toBe('ada@example.test');
  });

  it('sets the refresh cookie, as password login does', async () => {
    // The passkey path must not accidentally return the refresh token in the
    // body where application code could log it.
    const { token } = await signUp('ada@example.test');
    const authenticator = await VirtualAuthenticator.create();
    await addPasskey(token, authenticator);

    const signIn = await signInWithPasskey(authenticator);
    const setCookie = signIn.headers.getSetCookie?.() ?? [];
    const cookie = setCookie.find((c) => c.startsWith('ninsho_rt='));

    expect(cookie).toBeDefined();
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/SameSite=Strict/i);
    expect(signIn.body['refreshToken']).toBeUndefined();
  });

  it('carries roles from the directory, not from the passkey', async () => {
    // WebAuthn proves who, never what they may do.
    const { token } = await signUp('ada@example.test');
    const authenticator = await VirtualAuthenticator.create();
    await addPasskey(token, authenticator);

    const signIn = await signInWithPasskey(authenticator);
    const admin = await call('/admin/reports', {
      token: signIn.body['accessToken'] as string,
    });
    // The default role is `user`, so admin is refused — the passkey conferred
    // no authority of its own.
    expect(admin.status).toBe(403);
  });

  it('lists the passkeys on the account without returning key material', async () => {
    const { token } = await signUp('ada@example.test');
    await addPasskey(token, await VirtualAuthenticator.create());

    const list = await call('/auth/passkeys', { token });
    const passkeys = list.body['passkeys'] as Record<string, unknown>[];

    expect(passkeys).toHaveLength(1);
    expect(passkeys[0]).toHaveProperty('credentialId');
    expect(JSON.stringify(list.body)).not.toMatch(/publicKey/);
  });

  it('excludes existing credentials from a second registration', async () => {
    const { token } = await signUp('ada@example.test');
    const authenticator = await VirtualAuthenticator.create();
    await addPasskey(token, authenticator);

    const start = await call('/auth/passkey/register/start', { method: 'POST', token });
    const exclude = start.body['excludeCredentials'] as { id: string }[];

    expect(exclude).toHaveLength(1);
    expect(exclude[0]?.id).toBe(b64u(authenticator.credentialId));
  });

  it('supports more than one passkey on an account', async () => {
    const { token, id } = await signUp('ada@example.test');
    const laptop = await VirtualAuthenticator.create();
    const phone = await VirtualAuthenticator.create();

    expect((await addPasskey(token, laptop)).status).toBe(201);
    expect((await addPasskey(token, phone)).status).toBe(201);

    for (const authenticator of [laptop, phone]) {
      const signIn = await signInWithPasskey(authenticator);
      expect(signIn.status).toBe(200);
      expect((signIn.body['user'] as { id: string }).id).toBe(id);
    }
  });
});

/**
 * Adding a passkey is adding a new way into the account, so it must be at
 * least as protected as using one.
 */
describe('registration requires a session', () => {
  it('refuses to start a ceremony without a token', async () => {
    const res = await call('/auth/passkey/register/start', { method: 'POST' });
    expect(res.status).toBe(401);
  });

  it('refuses to finish a ceremony without a token', async () => {
    const res = await call('/auth/passkey/register/finish', {
      method: 'POST',
      body: JSON.stringify({ clientDataJSON: 'x', attestationObject: 'y' }),
    });
    expect(res.status).toBe(401);
  });

  it('refuses to finish another user’s ceremony', async () => {
    // The victim starts a registration; the attacker submits the response
    // under their own session. The signature is valid either way — only the
    // challenge-to-user binding catches this.
    const victim = await signUp('victim@example.test');
    const attacker = await signUp('attacker@example.test');
    const authenticator = await VirtualAuthenticator.create();

    const start = await call('/auth/passkey/register/start', {
      method: 'POST',
      token: victim.token,
    });
    const response = await authenticator.register({
      challenge: fromB64u((start.body as { challenge: string }).challenge),
      origin: ORIGIN,
      rpId: RP_ID,
    });

    const res = await call('/auth/passkey/register/finish', {
      method: 'POST',
      token: attacker.token,
      body: JSON.stringify({
        clientDataJSON: b64u(response.clientDataJSON),
        attestationObject: b64u(response.attestationObject),
      }),
    });

    expect(res.status).toBe(400);
    // And nothing was written to the attacker's account.
    const list = await call('/auth/passkeys', { token: attacker.token });
    expect(list.body['passkeys']).toHaveLength(0);
  });
});

/**
 * Adding a passkey is adding a new way into the account, so a live session is
 * not enough — someone at an unlocked laptop has one of those.
 */
describe('enrolling a passkey needs a recent login', () => {
  it('refuses when the authentication is older than the window', async () => {
    // A server whose step-up window has already passed by the time the user
    // tries to enrol.
    await new Promise<void>((resolve) => server.close(() => resolve()));
    resetUsers();
    resetCredentials();
    store = new MemoryStore();
    const { app } = createApp({
      store,
      secureCookies: false,
      trustProxy: false,
      rpId: RP_ID,
      webauthnOrigin: ORIGIN,
      passkeyStepUpSeconds: 1,
    });
    server = await new Promise((resolve) => {
      const s = app.listen(0, () => resolve(s));
    });
    baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    const { token } = await signUp('ada@example.test');
    // Wait past the one-second window.
    await new Promise((resolve) => setTimeout(resolve, 1100));

    const res = await call('/auth/passkey/register/start', { method: 'POST', token });
    expect(res.status).toBe(403);
  });

  it('allows enrolment immediately after signing in', async () => {
    // The same route, inside the window — so the rejection above came from the
    // freshness policy and not from something else being wrong.
    const { token } = await signUp('ada@example.test');
    const res = await call('/auth/passkey/register/start', { method: 'POST', token });
    expect(res.status).toBe(200);
  });

  it('cannot be satisfied by refreshing', async () => {
    // The point of reading the authentication time rather than the token's:
    // a stale session that refreshes gets a brand-new access token and must
    // still be refused.
    await new Promise<void>((resolve) => server.close(() => resolve()));
    resetUsers();
    resetCredentials();
    store = new MemoryStore();
    const { app } = createApp({
      store,
      secureCookies: false,
      trustProxy: false,
      rpId: RP_ID,
      webauthnOrigin: ORIGIN,
      passkeyStepUpSeconds: 1,
    });
    server = await new Promise((resolve) => {
      const s = app.listen(0, () => resolve(s));
    });
    baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    const registration = await call('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email: 'ada@example.test', password: PASSWORD }),
    });
    const cookie = (registration.headers.getSetCookie?.() ?? [])
      .find((c) => c.startsWith('ninsho_rt='))
      ?.split(';')[0] as string;

    await new Promise((resolve) => setTimeout(resolve, 1100));

    const refreshed = await fetch(`${baseUrl}/auth/refresh`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
    });
    const body = (await refreshed.json()) as { accessToken: string };
    expect(refreshed.status).toBe(200);

    // A token minted seconds ago, on an authentication that is not.
    const res = await call('/auth/passkey/register/start', {
      method: 'POST',
      token: body.accessToken,
    });
    expect(res.status).toBe(403);
  });
});

describe('replay and tampering', () => {
  it('refuses a replayed assertion', async () => {
    const { token } = await signUp('ada@example.test');
    const authenticator = await VirtualAuthenticator.create();
    await addPasskey(token, authenticator);

    // Capture a genuine assertion, then submit it twice.
    const start = await call('/auth/passkey/login/start', { method: 'POST' });
    const assertion = await authenticator.authenticate({
      challenge: fromB64u((start.body as { challenge: string }).challenge),
      origin: ORIGIN,
      rpId: RP_ID,
    });
    const body = JSON.stringify({
      credentialId: b64u(assertion.credentialId),
      clientDataJSON: b64u(assertion.clientDataJSON),
      authenticatorData: b64u(assertion.authenticatorData),
      signature: b64u(assertion.signature),
    });

    expect((await call('/auth/passkey/login/finish', { method: 'POST', body })).status).toBe(200);
    expect((await call('/auth/passkey/login/finish', { method: 'POST', body })).status).toBe(401);
  });

  it('refuses a registration response replayed a second time', async () => {
    const { token } = await signUp('ada@example.test');
    const authenticator = await VirtualAuthenticator.create();

    const start = await call('/auth/passkey/register/start', { method: 'POST', token });
    const response = await authenticator.register({
      challenge: fromB64u((start.body as { challenge: string }).challenge),
      origin: ORIGIN,
      rpId: RP_ID,
    });
    const body = JSON.stringify({
      clientDataJSON: b64u(response.clientDataJSON),
      attestationObject: b64u(response.attestationObject),
    });

    expect((await call('/auth/passkey/register/finish', { method: 'POST', token, body })).status)
      .toBe(201);
    expect((await call('/auth/passkey/register/finish', { method: 'POST', token, body })).status)
      .toBe(400);
  });

  it('refuses an assertion from a different origin', async () => {
    const { token } = await signUp('ada@example.test');
    const authenticator = await VirtualAuthenticator.create();
    await addPasskey(token, authenticator);

    const res = await signInWithPasskey(authenticator, { origin: 'https://evil.example' });
    expect(res.status).toBe(401);
  });

  it('refuses an assertion for a different relying party', async () => {
    const { token } = await signUp('ada@example.test');
    const authenticator = await VirtualAuthenticator.create();
    await addPasskey(token, authenticator);

    const res = await signInWithPasskey(authenticator, { rpId: 'evil.example' });
    expect(res.status).toBe(401);
  });

  it('refuses another authenticator’s signature under a stolen credential id', async () => {
    const { token } = await signUp('ada@example.test');
    const legitimate = await VirtualAuthenticator.create();
    const attacker = await VirtualAuthenticator.create();
    await addPasskey(token, legitimate);

    const start = await call('/auth/passkey/login/start', { method: 'POST' });
    const forged = await attacker.authenticate({
      challenge: fromB64u((start.body as { challenge: string }).challenge),
      origin: ORIGIN,
      rpId: RP_ID,
    });

    const res = await call('/auth/passkey/login/finish', {
      method: 'POST',
      body: JSON.stringify({
        // The victim's credential id, the attacker's signature.
        credentialId: b64u(legitimate.credentialId),
        clientDataJSON: b64u(forged.clientDataJSON),
        authenticatorData: b64u(forged.authenticatorData),
        signature: b64u(forged.signature),
      }),
    });

    expect(res.status).toBe(401);
  });

  it('refuses an unknown credential the same way it refuses a bad signature', async () => {
    // A different answer here would tell an attacker which credential ids are
    // real.
    const { token } = await signUp('ada@example.test');
    const authenticator = await VirtualAuthenticator.create();
    await addPasskey(token, authenticator);

    const unknown = await call('/auth/passkey/login/finish', {
      method: 'POST',
      body: JSON.stringify({
        credentialId: b64u(new Uint8Array(32).fill(7)),
        clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0',
        authenticatorData: b64u(new Uint8Array(37)),
        signature: b64u(new Uint8Array(70)),
      }),
    });
    const badSignature = await signInWithPasskey(authenticator, { origin: 'https://evil.example' });

    expect(unknown.status).toBe(401);
    expect(JSON.stringify(unknown.body)).toBe(JSON.stringify(badSignature.body));
  });

  it.each([
    ['a missing signature', { credentialId: 'x', clientDataJSON: 'y', authenticatorData: 'z' }],
    ['an empty body', {}],
    ['a numeric credential id', { credentialId: 1, clientDataJSON: 'y', authenticatorData: 'z', signature: 's' }],
  ])('rejects %s with a 400, not a 500', async (_label, body) => {
    // A malformed request must not reach the verifier as an exception the
    // framework turns into a 500 — that reads as "the server broke" when the
    // request was simply wrong.
    const res = await call('/auth/passkey/login/finish', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    expect(res.status).toBe(400);
  });

  it('rejects garbage base64 without a 500', async () => {
    const res = await call('/auth/passkey/login/finish', {
      method: 'POST',
      body: JSON.stringify({
        credentialId: '!!!not base64!!!',
        clientDataJSON: '@@@@',
        authenticatorData: '####',
        signature: '$$$$',
      }),
    });
    expect(res.status).toBe(401);
  });
});

describe('the sign counter', () => {
  it('advances across sign-ins and is persisted', async () => {
    const { token } = await signUp('ada@example.test');
    const authenticator = await VirtualAuthenticator.create();
    await addPasskey(token, authenticator);

    // Three sign-ins in a row. Each one must be accepted, which can only
    // happen if the previous counter was written back — otherwise the second
    // would compare against 0 and look like a clone.
    for (let i = 0; i < 3; i += 1) {
      expect((await signInWithPasskey(authenticator)).status).toBe(200);
    }
  });

  it('rejects a counter that goes backwards, as a clone would', async () => {
    const { token } = await signUp('ada@example.test');
    const authenticator = await VirtualAuthenticator.create();
    await addPasskey(token, authenticator);

    // Advance the stored counter, then present a lower one.
    expect((await signInWithPasskey(authenticator, { signCount: 10 })).status).toBe(200);
    expect((await signInWithPasskey(authenticator, { signCount: 4 })).status).toBe(401);
  });

  it('rejects a repeated counter', async () => {
    const { token } = await signUp('ada@example.test');
    const authenticator = await VirtualAuthenticator.create();
    await addPasskey(token, authenticator);

    expect((await signInWithPasskey(authenticator, { signCount: 5 })).status).toBe(200);
    expect((await signInWithPasskey(authenticator, { signCount: 5 })).status).toBe(401);
  });

  it('accepts an authenticator that never implements a counter', async () => {
    // Most passkeys report 0 forever. Treating that as a clone would break
    // them all.
    const { token } = await signUp('ada@example.test');
    const authenticator = await VirtualAuthenticator.create();
    await addPasskey(token, authenticator, { flags: FLAG_UP | FLAG_UV | FLAG_AT });

    for (let i = 0; i < 3; i += 1) {
      expect((await signInWithPasskey(authenticator, { signCount: 0 })).status).toBe(200);
    }
  });
});

describe('the ceremony options the browser receives', () => {
  it('requests no attestation', async () => {
    // The package cannot verify any other format, so it never asks for one.
    const { token } = await signUp('ada@example.test');
    const start = await call('/auth/passkey/register/start', { method: 'POST', token });

    expect(start.body['attestation']).toBe('none');
  });

  it('uses the opaque user id as the handle, never the email', async () => {
    // The handle is stored on the authenticator and may be displayed by a
    // password manager, so it must carry no personal information.
    const { token, id } = await signUp('ada@example.test');
    const start = await call('/auth/passkey/register/start', { method: 'POST', token });
    const user = start.body['user'] as { id: string; name: string };

    expect(Buffer.from(user.id, 'base64url').toString()).toBe(id);
    expect(Buffer.from(user.id, 'base64url').toString()).not.toContain('@');
  });

  it('offers no credentials on the usernameless sign-in path', async () => {
    // Naming credentials here would leak which accounts exist.
    const { token } = await signUp('ada@example.test');
    await addPasskey(token, await VirtualAuthenticator.create());

    const start = await call('/auth/passkey/login/start', { method: 'POST' });
    expect(start.body['allowCredentials']).toEqual([]);
    expect(start.body['rpId']).toBe(RP_ID);
  });

  it('issues a different challenge every time', async () => {
    const seen = new Set<string>();
    for (let i = 0; i < 20; i += 1) {
      const start = await call('/auth/passkey/login/start', { method: 'POST' });
      const challenge = start.body['challenge'] as string;
      expect(seen.has(challenge)).toBe(false);
      seen.add(challenge);
    }
  });
});

describe('passkeys and password sessions coexist', () => {
  it('produces sessions that logout-all revokes together', async () => {
    const { token } = await signUp('ada@example.test');
    const authenticator = await VirtualAuthenticator.create();
    await addPasskey(token, authenticator);

    const passkeySession = await signInWithPasskey(authenticator);
    const passkeyToken = passkeySession.body['accessToken'] as string;

    expect((await call('/me', { token: passkeyToken })).status).toBe(200);
    expect((await call('/me', { token })).status).toBe(200);

    // Signing out everywhere from the password session must also end the one
    // the passkey created — they are ordinary Ninsho sessions either way.
    expect((await call('/auth/logout-all', { method: 'POST', token })).status).toBe(204);

    expect((await call('/me', { token: passkeyToken })).status).toBe(401);
    expect((await call('/me', { token })).status).toBe(401);
  });

  it('lists a passkey session alongside a password one', async () => {
    const { token } = await signUp('ada@example.test');
    const authenticator = await VirtualAuthenticator.create();
    await addPasskey(token, authenticator);
    await signInWithPasskey(authenticator);

    const sessions = await call('/auth/sessions', { token });
    expect((sessions.body['sessions'] as unknown[]).length).toBe(2);
  });
});
