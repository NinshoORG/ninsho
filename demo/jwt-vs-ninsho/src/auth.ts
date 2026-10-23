import { SignJWT, jwtVerify, type JWTPayload } from 'jose';
import { randomBytes } from 'node:crypto';
import { Ninsho, RedisStore, RateLimiter, type HttpRequest } from '@ninshorg/server';
import type { Request } from 'express';
import type { User } from './db.js';

// ─── Side A: a plain JWT ──────────────────────────────────────────────────
// The common tutorial setup, done correctly: HS256, a short expiry, issuer and
// audience checked. It is not a straw man — it is what "stateless" means. The
// server signs a token and forgets it; from then on, anyone holding the token
// is the user until `exp`.

export const JWT_TTL_SECONDS = 15 * 60;
const ISSUER = 'jwt-vs-ninsho';
const AUDIENCE = 'jwt-vs-ninsho-api';

export interface JwtClaims extends JWTPayload {
  readonly sub: string;
  readonly email: string;
  readonly name: string;
}

export function createJwtSigner(secret = process.env.JWT_SECRET) {
  // A fresh random key per start unless one is configured: restarting the
  // server is then the only "revoke everything" a stateless setup has.
  const key = secret ? new TextEncoder().encode(secret) : randomBytes(32);
  return {
    async sign(user: User): Promise<{ token: string; expiresAt: string }> {
      const now = Math.floor(Date.now() / 1000);
      const token = await new SignJWT({ email: user.email, name: user.name })
        .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
        .setSubject(user.id)
        .setIssuer(ISSUER)
        .setAudience(AUDIENCE)
        .setIssuedAt(now)
        .setExpirationTime(now + JWT_TTL_SECONDS)
        .sign(key);
      return { token, expiresAt: new Date((now + JWT_TTL_SECONDS) * 1000).toISOString() };
    },
    async verify(token: string): Promise<JwtClaims> {
      const { payload } = await jwtVerify(token, key, {
        issuer: ISSUER,
        audience: AUDIENCE,
        algorithms: ['HS256'],
      });
      return payload as JwtClaims;
    },
  };
}

export type JwtSigner = ReturnType<typeof createJwtSigner>;

// ─── Side B: Ninsho ───────────────────────────────────────────────────────
// Opaque tokens checked against Redis on every request, and bound to a key
// the browser holds but cannot export (DPoP, RFC 9449).

export interface NinshoSide {
  readonly auth: Ninsho;
  readonly limiter: RateLimiter;
  close(): Promise<void>;
}

export const NINSHO_ACCESS_TTL_SECONDS = 5 * 60;

export function createNinshoSide(redisUrl = process.env.REDIS_URL || 'redis://127.0.0.1:6379'): NinshoSide {
  const store = new RedisStore(redisUrl, { redisOptions: { keyPrefix: 'jvn:' } });
  const auth = new Ninsho({
    store,
    binding: 'dpop',
    accessTokenTtl: NINSHO_ACCESS_TTL_SECONDS,
    onStoreError: 'closed',
  });
  // Sign-in throttling is shared by BOTH sides of the page. It is not part of
  // the comparison, so neither side gets an advantage from it.
  const limiter = new RateLimiter({ store, onStoreError: 'closed', audit: { emit: () => undefined } });
  return { auth, limiter, close: () => auth.close() };
}

/** Express request → the structural request Ninsho reads a DPoP proof from. */
export function toNinshoRequest(req: Request): HttpRequest {
  return {
    method: req.method,
    originalUrl: req.originalUrl || req.url,
    protocol: req.protocol || 'http',
    headers: req.headers as Record<string, string | string[] | undefined>,
    rawHeaders: req.rawHeaders,
    body: req.body,
  };
}
