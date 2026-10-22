// The configurations under comparison, defined once so both benchmarks and
// the security preflight exercise exactly the same code.
//
// Ninsho configurations go through the public `Ninsho` facade and the built
// package in packages/server/dist — the code a consumer runs. Nothing here
// changes a Ninsho default except `audit`, which is replaced by a no-op sink
// for every configuration (success paths emit nothing either way).
//
// The JWT baseline uses `jose` (pinned in package.json) with Ed25519/EdDSA, the
// same signature algorithm PASETO v4.public uses, so the signature cost is the
// same primitive on both sides. Its revocation check is one Redis EXISTS on the
// token id through ioredis — the same client library, the same command and the
// same round-trip shape as Ninsho's PASETO denylist lookup.

import { randomUUID } from 'node:crypto';
import { Redis } from 'ioredis';
import { SignJWT, jwtVerify, generateKeyPair as joseKeyPair } from 'jose';
import {
  Ninsho, RedisStore, MemoryStore, PasetoEngine, KeyRing, generateKeyPair,
} from '../../../../packages/server/dist/index.js';

export const ISSUER = 'https://bench.ninsho.test';
export const AUDIENCE = 'bench-api';
export const ACCESS_TTL = 300;
export const CLOCK_TOLERANCE = 5;
const silent = { emit() {} };

/** What each protected-request configuration checks on every request. */
export const CHECKS = {
  'ninsho-opaque': 'SHA-256 of token → Redis GET of the access record (presence IS non-revocation) → record shape → expiry → DPoP binding (none here). Fail-closed 503 on store error.',
  'ninsho-paseto': 'kid from footer → Ed25519 signature (PASETO v4.public, PAE) → claim shape → iss, aud, nbf, iat, exp ± tolerance → cnf (none here) → Redis EXISTS on jti denylist. Fail-closed 503 on store error.',
  'jwt-redis': 'jose jwtVerify: header parse, alg allowlist [EdDSA], Ed25519 signature, iss, aud, nbf, iat, exp ± tolerance, required claims → claim shape (roles/scopes/sid) → Redis EXISTS on jti denylist via ioredis. Fail-closed 503 on Redis error.',
  'jwt-stateless': 'Identical to jwt-redis but WITHOUT the denylist lookup. Reference only: a revoked token is accepted until exp. Not a like-for-like comparison.',
  'no-auth': 'No authentication. Floor for Express + loopback HTTP + JSON response cost on this machine. Reference only.',
};

export const CONFIG_NAMES = Object.keys(CHECKS);
export const COMPARABLE = ['ninsho-opaque', 'ninsho-paseto', 'jwt-redis'];

const AUTH = /^(?:Bearer|DPoP)[ ]+(.+)$/i;

function jwtClaimsShapeOk(payload) {
  return typeof payload.sid === 'string' && payload.sid.length > 0 &&
    Array.isArray(payload.roles) && payload.roles.every((r) => typeof r === 'string') &&
    Array.isArray(payload.scopes) && payload.scopes.every((s) => typeof s === 'string');
}

/** Builds the JWT baseline: signer, verifier, and an Express middleware. */
export async function buildJwt(redisUrl, { revocation }) {
  const { publicKey, privateKey } = await joseKeyPair('EdDSA', { crv: 'Ed25519' });
  const kid = 'bench-jwt';
  // Same failure posture as RedisStore: no offline queue, so an outage
  // rejects immediately and the middleware answers 503 rather than queueing.
  const redis = revocation
    ? new Redis(redisUrl, { maxRetriesPerRequest: 2, enableOfflineQueue: false, lazyConnect: true })
    : null;
  if (redis) await redis.connect();
  const denyKey = (jti) => `jwtbench:revoked:${jti}`;

  async function sign(userId, { audience = AUDIENCE } = {}) {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ sid: randomUUID(), roles: ['user'], scopes: ['orders:read'] })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid })
      .setSubject(userId).setIssuer(ISSUER).setAudience(audience)
      .setIssuedAt(now).setNotBefore(now).setExpirationTime(now + ACCESS_TTL)
      .setJti(randomUUID())
      .sign(privateKey);
  }

  async function verify(token) {
    const { payload } = await jwtVerify(token, publicKey, {
      issuer: ISSUER, audience: AUDIENCE, algorithms: ['EdDSA'],
      clockTolerance: CLOCK_TOLERANCE, requiredClaims: ['jti', 'sub', 'iat', 'nbf', 'exp'],
    });
    if (!jwtClaimsShapeOk(payload)) throw Object.assign(new Error('claims malformed'), { status: 401 });
    if (redis) {
      let revoked;
      try { revoked = (await redis.exists(denyKey(payload.jti))) === 1; }
      catch { throw Object.assign(new Error('store unavailable'), { status: 503 }); }
      if (revoked) throw Object.assign(new Error('revoked'), { status: 401 });
    }
    return { userId: payload.sub, sessionId: payload.sid, tokenId: payload.jti };
  }

  async function revoke(token) {
    const { payload } = await jwtVerify(token, publicKey, { issuer: ISSUER, audience: AUDIENCE });
    await redis.set(denyKey(payload.jti), '1', 'EX', ACCESS_TTL + CLOCK_TOLERANCE + 1);
  }

  function middleware() {
    return (req, res, next) => {
      const header = req.headers.authorization;
      const match = typeof header === 'string' ? AUTH.exec(header.trim()) : null;
      if (match === null) {
        res.status(401).set('WWW-Authenticate', 'Bearer error="TOKEN_MISSING"').json({ error: { code: 'TOKEN_MISSING' } });
        return;
      }
      verify(match[1]).then((auth) => { req.auth = auth; next(); }, (error) => {
        const status = error.status === 503 ? 503 : 401;
        if (status === 401) res.set('WWW-Authenticate', 'Bearer error="TOKEN_INVALID"');
        res.status(status).json({ error: { code: status === 503 ? 'STORE_UNAVAILABLE' : 'TOKEN_INVALID' } });
      });
    };
  }

  return { sign, verify, revoke, middleware, close: async () => redis?.disconnect() };
}

/** Builds a Ninsho configuration through the public facade. */
export function buildNinsho(strategy, redisUrl, { memory = false } = {}) {
  const store = memory ? new MemoryStore() : new RedisStore(redisUrl);
  const keyPair = strategy === 'paseto' ? generateKeyPair('bench') : null;
  const auth = strategy === 'paseto'
    ? new Ninsho({
        store, strategy: 'paseto', issuer: ISSUER, audience: AUDIENCE,
        keys: { active: keyPair },
        accessTokenTtl: ACCESS_TTL, clockToleranceSeconds: CLOCK_TOLERANCE, audit: silent,
      })
    : new Ninsho({ store, accessTokenTtl: ACCESS_TTL, clockToleranceSeconds: CLOCK_TOLERANCE, audit: silent });
  return { auth, keyPair };
}

/**
 * A PASETO token signed by the right key for the wrong audience — the
 * preflight's cross-service case. Minted by a second engine sharing the key.
 */
export async function foreignPaseto(store, keyPair) {
  const engine = new PasetoEngine(store, new KeyRing({ active: keyPair }), {
    accessTokenTtl: ACCESS_TTL, clockToleranceSeconds: CLOCK_TOLERANCE, issuer: ISSUER, audience: 'another-api',
  });
  const issued = await engine.issue({
    principal: principal(9999), sessionId: randomUUID(), authenticatedAt: new Date().toISOString(),
  });
  return issued.token;
}

export const principal = (i) => ({ userId: `user_${String(i).padStart(4, '0')}`, roles: ['user'], scopes: ['orders:read'] });
