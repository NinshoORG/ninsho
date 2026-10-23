import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { randomBytes } from 'node:crypto';
import { createProof, generateDpopKey } from '@ninshorg/client';
import { openDatabase, type Database } from './db.js';
import { createJwtSigner, createNinshoSide, type NinshoSide } from './auth.js';
import { createApp } from './app.js';

// Every claim the page makes about the two sides, checked against the real
// Postgres and Redis named in .env. Skipped when either is not configured.
const configured = Boolean(process.env.DATABASE_URL && process.env.REDIS_URL);

describe('JWT vs Ninsho', { skip: !configured && 'set DATABASE_URL and REDIS_URL' }, () => {
  let db: Database;
  let ninsho: NinshoSide;
  let server: Server;
  let base: string;
  const email = `test-${randomBytes(6).toString('hex')}@jvn.test`;
  const password = 'correct horse battery';
  let userId: string | undefined;

  before(async () => {
    db = await openDatabase();
    ninsho = createNinshoSide();
    const app = createApp({ db, jwt: createJwtSigner(), ninsho });
    server = app.listen(0, '127.0.0.1');
    await new Promise((resolve) => server.once('listening', resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const res = await post('/api/signup', { name: 'Test User', email, password });
    assert.equal(res.status, 201);
    userId = (await res.json()).user.id;
  });

  after(async () => {
    if (userId) await db.deleteUser(userId);
    server?.close();
    await Promise.allSettled([ninsho?.close(), db?.close()]);
  });

  const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
    fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });

  const attacker = (side: 'jwt' | 'ninsho', token: string, proof?: string) =>
    post('/api/attacker/replay', { side, token, proof, origin: base }).then((r) => r.json() as Promise<{ status: number }>);

  /** A browser device: a DPoP key, and a proof for each request it makes. */
  async function device() {
    const key = await generateDpopKey();
    const proofFor = (method: string, path: string, accessToken?: string) =>
      createProof(key, { method, url: base + path, ...(accessToken && { accessToken }) });
    const login = await post('/api/ninsho/login', { email, password }, { dpop: await proofFor('POST', '/api/ninsho/login') });
    assert.equal(login.status, 200);
    const { accessToken } = await login.json();
    const call = async (method: string, path: string) =>
      fetch(base + path, {
        method,
        headers: { authorization: `DPoP ${accessToken}`, dpop: await proofFor(method, path, accessToken) },
      });
    return { accessToken: accessToken as string, proofFor, call };
  }

  async function jwtLogin() {
    const res = await post('/api/jwt/login', { email, password });
    assert.equal(res.status, 200);
    return (await res.json()).token as string;
  }

  it('refuses a duplicate account and a wrong password on both sides', async () => {
    assert.equal((await post('/api/signup', { name: 'Again', email, password })).status, 409);
    assert.equal((await post('/api/jwt/login', { email, password: 'wrong password' })).status, 401);
    const key = await generateDpopKey();
    const proof = await createProof(key, { method: 'POST', url: `${base}/api/ninsho/login` });
    assert.equal((await post('/api/ninsho/login', { email, password: 'wrong password' }, { dpop: proof })).status, 401);
  });

  it('scenario 1 — JWT: a token copied before sign-out still works after it', async () => {
    const token = await jwtLogin();
    assert.equal((await attacker('jwt', token)).status, 200);
    assert.equal((await post('/api/jwt/logout', {})).status, 200);
    assert.equal((await attacker('jwt', token)).status, 200);
  });

  it('scenario 1 — Ninsho: a complete request copied before sign-out is refused after it', async () => {
    const phone = await device();
    // Two copies, both signed by the real device key before sign-out.
    const before = await phone.proofFor('GET', '/api/ninsho/me', phone.accessToken);
    const afterwards = await phone.proofFor('GET', '/api/ninsho/me', phone.accessToken);
    assert.equal((await attacker('ninsho', phone.accessToken, before)).status, 200);
    assert.equal((await phone.call('POST', '/api/ninsho/logout')).status, 200);
    // Same token, an unused proof from the right key: only the sign-out differs.
    assert.equal((await attacker('ninsho', phone.accessToken, afterwards)).status, 401);
  });

  it('scenario 2 — a stolen token alone: JWT works, Ninsho needs the device key', async () => {
    const token = await jwtLogin();
    assert.equal((await attacker('jwt', token)).status, 200);

    const phone = await device();
    assert.equal((await phone.call('GET', '/api/ninsho/me')).status, 200, 'the real device still works');
    assert.equal((await attacker('ninsho', phone.accessToken)).status, 401, 'token without proof');
    const thiefKey = await generateDpopKey();
    const forged = await createProof(thiefKey, { method: 'GET', url: `${base}/api/ninsho/me`, accessToken: phone.accessToken });
    assert.equal((await attacker('ninsho', phone.accessToken, forged)).status, 401, 'proof from the thief’s own key');
  });

  it('scenario 3 — sign out everywhere: impossible for JWT, every device for Ninsho', async () => {
    const token = await jwtLogin();
    const jwtAll = await (await post('/api/jwt/logout-all', {})).json();
    assert.equal(jwtAll.possible, false);
    assert.equal((await attacker('jwt', token)).status, 200);

    const laptop = await device();
    const phone = await device();
    const listed = await (await laptop.call('GET', '/api/ninsho/sessions')).json();
    assert.ok(listed.sessions.length >= 2);
    const phoneCopy = await phone.proofFor('GET', '/api/ninsho/me', phone.accessToken);
    const all = await (await laptop.call('POST', '/api/ninsho/logout-all')).json();
    assert.equal(all.possible, true);
    assert.ok(all.sessionsEnded >= 2);
    assert.equal((await phone.call('GET', '/api/ninsho/me')).status, 401, 'the other device is signed out');
    assert.equal((await attacker('ninsho', phone.accessToken, phoneCopy)).status, 401);
  });

  it('the attacker endpoint only replays against this app', async () => {
    const res = await post('/api/attacker/replay', { side: 'jwt', token: 'x', origin: 'http://example.com' });
    assert.equal(res.status, 400);
  });
});
