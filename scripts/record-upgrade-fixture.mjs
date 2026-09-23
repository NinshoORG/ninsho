#!/usr/bin/env node
/**
 * Records the session state a released version of @ninshorg/server leaves in
 * its store, for the upgrade-compatibility test.
 *
 *   node scripts/record-upgrade-fixture.mjs --npm 0.2.0   a published release
 *   node scripts/record-upgrade-fixture.mjs <dir>         any installed copy
 *
 * Writes packages/server/src/__tests__/fixtures/upgrade/<version>.json, and
 * refuses to overwrite one that exists: a fixture is history, and rewriting it
 * would quietly move the goalposts it exists to hold still.
 *
 * ─── Why ──────────────────────────────────────────────────────────────────
 * During a rolling deploy, old and new versions share one Redis. Every
 * session a user has was written by the old version and is about to be read
 * by the new one. If the new version misreads those records, the best case is
 * that everyone is signed out; the worst is that a session revoked before the
 * upgrade reads as live after it.
 *
 * Store keys are namespaced (`ninsho:v1:`) so a deliberate schema change can
 * make old records invisible rather than misread. What nothing tested was the
 * ordinary case: a release that keeps the namespace and changes a record
 * anyway. This records real state from a real release, and
 * upgrade-compat.test.ts checks the current code still honours all of it.
 *
 * Record from the *published* package, not a local build: the published one is
 * what is actually in people's stores.
 * ──────────────────────────────────────────────────────────────────────────
 *
 * The fixture holds raw tokens and private keys. They are generated fresh by
 * this script, sign nothing outside it, and exist so the test can present
 * them. They are test material, not credentials.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUT_DIR = join(ROOT, 'packages/server/src/__tests__/fixtures/upgrade');

// ── Load the version to record ───────────────────────────────────────────────

function installFromNpm(version) {
  const dir = mkdtempSync(join(tmpdir(), 'ninsho-fixture-'));
  writeFileSync(join(dir, 'package.json'), '{"private":true}');
  console.log(`  installing @ninshorg/server@${version} from the registry…`);
  // `shell` because npm is npm.cmd on Windows; the arguments are fixed strings
  // apart from a version the maintainer typed.
  execFileSync('npm', ['install', '--no-audit', '--no-fund', `@ninshorg/server@${version}`], {
    cwd: dir,
    stdio: 'ignore',
    shell: process.platform === 'win32',
  });
  return join(dir, 'node_modules/@ninshorg/server');
}

const npmAt = process.argv.indexOf('--npm');
const pkgDir =
  npmAt !== -1 ? installFromNpm(process.argv[npmAt + 1]) : resolve(process.argv[2] ?? join(ROOT, 'packages/server'));

const manifest = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8'));
const esm = manifest.exports['.'].import;
const lib = await import(pathToFileURL(join(pkgDir, typeof esm === 'string' ? esm : esm.default)).href);

const target = join(OUT_DIR, `${manifest.version}.json`);
if (existsSync(target)) {
  console.error(`✗ ${target.slice(ROOT.length + 1)} exists. A fixture is history; it is not re-recorded.`);
  process.exit(1);
}

// ── A store that remembers which keys it was given ──────────────────────────
// Implements the twelve-method contract by delegation. The store contract has
// no way to read a key's TTL, so none is recorded; the test freezes the clock
// at recording time instead, and validity is governed by the timestamps inside
// the records, which is what an upgrade actually has to read correctly.

class Tracking {
  constructor(inner) {
    this.inner = inner;
    this.keys = new Set();
  }
  get(k) { return this.inner.get(k); }
  set(k, v, t) { this.keys.add(k); return this.inner.set(k, v, t); }
  setIfAbsent(k, v, t) { this.keys.add(k); return this.inner.setIfAbsent(k, v, t); }
  take(k) { return this.inner.take(k); }
  increment(k, t) { this.keys.add(k); return this.inner.increment(k, t); }
  delete(...ks) { return this.inner.delete(...ks); }
  exists(k) { return this.inner.exists(k); }
  sAdd(k, m, t) { this.keys.add(k); return this.inner.sAdd(k, m, t); }
  sRemove(k, ...m) { return this.inner.sRemove(k, ...m); }
  sMembers(k) { return this.inner.sMembers(k); }
  ping() { return this.inner.ping(); }
  close() { return this.inner.close(); }

  /** Every key still holding something, in a stable order. */
  async snapshot() {
    const out = [];
    for (const key of [...this.keys].sort()) {
      const value = await this.inner.get(key);
      if (value !== null) {
        out.push({ key, value });
        continue;
      }
      // Sets do not answer `get`, so a key that reads empty may still be one.
      const members = await this.inner.sMembers(key);
      if (members.length > 0) out.push({ key, members: [...members].sort() });
    }
    return out;
  }
}

const recordedAt = Date.now();
const audit = () => new lib.MemoryAuditSink();
const person = (userId) => ({ userId, roles: ['user'], scopes: ['orders:read'] });
const signals = { userAgent: 'Firefox 142 · laptop', ip: '198.51.100.7' };

// ── Opaque tokens, the default ──────────────────────────────────────────────
// Grace window 0: a replacement held for a few seconds only survives an upgrade
// that finishes inside it, so the durable records are what is worth testing —
// and with a grace window, "presenting a rotated token" means something else.
async function opaque() {
  const config = { refreshGraceSeconds: 0 };
  const store = new Tracking(new lib.MemoryStore());
  const auth = new lib.Ninsho({ store, audit: audit(), ...config });

  const live = await auth.createSession(person('u_alice'), { signals });
  const second = await auth.createSession(person('u_alice'), { signals: { ...signals, userAgent: 'Safari · phone' } });
  const before = await auth.createSession(person('u_alice'), { signals });
  const rotated = await auth.refresh(before.refreshToken, { signals });
  const doomed = await auth.createSession(person('u_alice'), { signals });
  await auth.revokeSession(doomed.sessionId, 'logout');
  const reset = await auth.oneTimeTokens.issue({ purpose: 'password-reset', subject: 'u_alice', ttlSeconds: 900 });

  const sessions = await auth.listSessions('u_alice');
  const section = {
    config,
    tokens: {
      live: { accessToken: live.accessToken, refreshToken: live.refreshToken, sessionId: live.sessionId },
      second: { accessToken: second.accessToken, sessionId: second.sessionId },
      rotated: { spentRefreshToken: before.refreshToken, accessToken: rotated.accessToken, refreshToken: rotated.refreshToken },
      revoked: { accessToken: doomed.accessToken, refreshToken: doomed.refreshToken },
      reset: reset.token,
    },
    expect: { userId: 'u_alice', liveSessions: sessions.length },
    keys: await store.snapshot(),
  };
  await auth.close();
  return section;
}

// ── PASETO v4.public ────────────────────────────────────────────────────────
async function paseto() {
  const key = lib.generateKeyPair('fixture-key-1');
  const config = {
    strategy: 'paseto',
    issuer: 'https://api.example.test',
    audience: 'https://app.example.test',
    keys: { active: key },
    refreshGraceSeconds: 0,
  };
  const store = new Tracking(new lib.MemoryStore());
  const auth = new lib.Ninsho({ store, audit: audit(), ...config });

  const live = await auth.createSession(person('u_bob'));
  const before = await auth.createSession(person('u_bob'));
  const rotated = await auth.refresh(before.refreshToken);
  const doomed = await auth.createSession(person('u_bob'));
  await auth.revokeSession(doomed.sessionId, 'logout');

  const section = {
    config,
    tokens: {
      live: { accessToken: live.accessToken, refreshToken: live.refreshToken, sessionId: live.sessionId },
      rotated: { spentRefreshToken: before.refreshToken, accessToken: rotated.accessToken },
      revoked: { accessToken: doomed.accessToken },
    },
    expect: { userId: 'u_bob' },
    keys: await store.snapshot(),
  };
  await auth.close();
  return section;
}

// ── A session bound to a DPoP key ───────────────────────────────────────────
async function dpop() {
  const key = lib.generateDpopKeyPair('ES256');
  const config = { binding: 'dpop', refreshGraceSeconds: 0 };
  const store = new Tracking(new lib.MemoryStore());
  const auth = new lib.Ninsho({ store, audit: audit(), ...config });

  const live = await auth.createSession(person('u_carol'), { confirmationKey: key.jkt });
  const section = {
    config,
    key: {
      algorithm: key.algorithm,
      jkt: key.jkt,
      publicJwk: key.publicJwk,
      privateJwk: key.privateKey.export({ format: 'jwk' }),
    },
    tokens: { live: { accessToken: live.accessToken, sessionId: live.sessionId } },
    expect: { userId: 'u_carol' },
    keys: await store.snapshot(),
  };
  await auth.close();
  return section;
}

const fixture = {
  $comment:
    'Recorded by scripts/record-upgrade-fixture.mjs from a released @ninshorg/server. ' +
    'Test material: every token and key here was generated for this file and authorises nothing. ' +
    'Never edit or re-record — see upgrade-compat.test.ts.',
  version: manifest.version,
  recordedAt,
  namespace: lib.KEYS.userSessions('_').replace(/:user:_:sess$/, ''),
  opaque: await opaque(),
  paseto: await paseto(),
  dpop: await dpop(),
};

mkdirSync(OUT_DIR, { recursive: true });
writeFileSync(target, `${JSON.stringify(fixture, null, 2)}\n`);
const count = ['opaque', 'paseto', 'dpop'].reduce((n, s) => n + fixture[s].keys.length, 0);
console.log(
  `✓ Recorded @ninshorg/server ${manifest.version}: ${count} store keys across opaque, PASETO and DPoP sessions\n` +
    `  → ${target.slice(ROOT.length + 1).replace(/\\/g, '/')}`,
);
