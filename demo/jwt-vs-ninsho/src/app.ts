import express, { type NextFunction, type Request, type Response } from 'express';
import cookieParser from 'cookie-parser';
import { request as httpRequest } from 'node:http';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { getAuth, isNinshoError, toErrorResponse } from '@ninshorg/server';
import type { Database } from './db.js';
import { JWT_TTL_SECONDS, NINSHO_ACCESS_TTL_SECONDS, toNinshoRequest, type JwtSigner, type NinshoSide } from './auth.js';

const here = dirname(fileURLToPath(import.meta.url));
const REFRESH_COOKIE = 'ninsho_rt';
const REFRESH_COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: 'strict',
  path: '/api/ninsho',
  maxAge: 7 * 24 * 3600 * 1000,
} as const;

type Handler = (req: Request, res: Response) => Promise<unknown>;
const route = (fn: Handler) => (req: Request, res: Response, next: NextFunction) => {
  fn(req, res).catch(next);
};

const fail = (res: Response, status: number, code: string, message: string) =>
  res.status(status).json({ error: { code, message } });

export function createApp({ db, jwt, ninsho }: { db: Database; jwt: JwtSigner; ninsho: NinshoSide }) {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '16kb' }));
  app.use(cookieParser());
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
    );
    next();
  });

  // The browser half of Ninsho, served from the installed package.
  const clientEntry = createRequire(import.meta.url).resolve('@ninshorg/client');
  app.use('/vendor/ninsho-client', express.static(dirname(clientEntry)));
  app.use(express.static(join(here, '../public')));

  /** Same limits for both sides; sign-in throttling is not what is being compared. */
  async function throttled(req: Request, res: Response, buckets: [string, number, number][]): Promise<boolean> {
    for (const [bucket, limit, windowMs] of buckets) {
      const verdict = await ninsho.limiter.consume(bucket, limit, windowMs);
      if (!verdict.allowed) {
        res.setHeader('Retry-After', String(verdict.retryAfter));
        fail(res, 429, 'RATE_LIMITED', `Too many attempts. Try again in ${verdict.retryAfter}s.`);
        return true;
      }
    }
    return false;
  }

  const ip = (req: Request) => req.socket.remoteAddress ?? 'unknown';

  async function signInThrottled(req: Request, res: Response): Promise<boolean> {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    return throttled(req, res, [
      [`signin:ip:${ip(req)}`, 30, 5 * 60_000],
      [`signin:email:${email}`, 10, 5 * 60_000],
    ]);
  }

  // ─── Accounts (shared) ──────────────────────────────────────────────────

  app.get('/api/health', route(async (_req, res) => {
    const [dbOk, redisOk] = await Promise.all([
      db.pool.query('SELECT 1').then(() => true, () => false),
      ninsho.auth.health().catch(() => false),
    ]);
    res.status(dbOk && redisOk ? 200 : 503).json({ database: dbOk, redis: redisOk });
  }));

  app.post('/api/signup', route(async (req, res) => {
    const { name, email, password } = req.body ?? {};
    if (typeof name !== 'string' || name.trim().length < 1 || name.trim().length > 60) {
      return fail(res, 400, 'BAD_NAME', 'Enter a name (up to 60 characters).');
    }
    if (typeof email !== 'string' || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      return fail(res, 400, 'BAD_EMAIL', 'Enter a valid email address.');
    }
    if (typeof password !== 'string' || password.length < 8 || password.length > 200) {
      return fail(res, 400, 'BAD_PASSWORD', 'Use a password of at least 8 characters.');
    }
    if (await throttled(req, res, [[`signup:ip:${ip(req)}`, 10, 60 * 60_000]])) return;
    const user = await db.createUser({ name, email, password });
    if (!user) return fail(res, 409, 'EMAIL_TAKEN', 'An account with that email already exists. Sign in instead.');
    res.status(201).json({ user });
  }));

  // ─── Side A: JWT ────────────────────────────────────────────────────────

  app.post('/api/jwt/login', route(async (req, res) => {
    if (await signInThrottled(req, res)) return;
    const user = await db.checkPassword(req.body?.email, req.body?.password);
    if (!user) return fail(res, 401, 'BAD_CREDENTIALS', 'Wrong email or password.');
    const { token, expiresAt } = await jwt.sign(user);
    res.json({ token, expiresAt, user });
  }));

  app.get('/api/jwt/me', route(async (req, res) => {
    const header = req.headers.authorization ?? '';
    if (!header.startsWith('Bearer ')) return fail(res, 401, 'NO_TOKEN', 'No token was sent.');
    try {
      const claims = await jwt.verify(header.slice(7).trim());
      // Answered from the token alone: no database read, no session lookup.
      // That is the speed of a JWT, and also why nothing can switch it off.
      res.json({
        user: { id: claims.sub, email: claims.email, name: claims.name },
        expiresAt: new Date((claims.exp ?? 0) * 1000).toISOString(),
        checkedAgainst: 'the token signature and expiry only',
      });
    } catch {
      fail(res, 401, 'TOKEN_INVALID', 'The token is invalid or expired.');
    }
  }));

  app.post('/api/jwt/logout', (_req, res) => {
    // There is nothing to revoke. The server never recorded the token, so all
    // "sign out" can mean is that this browser deletes its copy.
    res.json({
      serverAction: 'none',
      explanation: 'The server keeps no record of JWTs, so it has nothing to cancel. Only this browser forgets its copy.',
    });
  });

  app.post('/api/jwt/logout-all', (_req, res) => {
    res.json({
      possible: false,
      explanation:
        'The server never stored which tokens it issued, so it cannot find or cancel them. ' +
        `Every copy keeps working until it expires (up to ${JWT_TTL_SECONDS / 60} minutes), ` +
        'unless you change the signing key, which signs out every user at once.',
    });
  });

  // ─── Side B: Ninsho ─────────────────────────────────────────────────────

  app.post('/api/ninsho/login', route(async (req, res) => {
    if (await signInThrottled(req, res)) return;
    const user = await db.checkPassword(req.body?.email, req.body?.password);
    if (!user) return fail(res, 401, 'BAD_CREDENTIALS', 'Wrong email or password.');
    // The browser signs this request with its device key; the session is
    // bound to that key's thumbprint, so the tokens only work alongside it.
    const keyThumbprint = await ninsho.auth.confirmProofOfPossession(toNinshoRequest(req));
    const pair = await ninsho.auth.createSession(
      { userId: user.id, roles: ['user'], scopes: [] },
      { confirmationKey: keyThumbprint },
    );
    res.cookie(REFRESH_COOKIE, pair.refreshToken, REFRESH_COOKIE_OPTIONS);
    res.json({ accessToken: pair.accessToken, sessionId: pair.sessionId, user });
  }));

  app.post('/api/ninsho/refresh', route(async (req, res) => {
    const refreshToken = req.cookies?.[REFRESH_COOKIE];
    if (typeof refreshToken !== 'string' || refreshToken === '') {
      return fail(res, 401, 'NO_SESSION', 'Not signed in.');
    }
    try {
      const keyThumbprint = await ninsho.auth.confirmProofOfPossession(toNinshoRequest(req));
      const pair = await ninsho.auth.refresh(refreshToken, { confirmationKey: keyThumbprint });
      res.cookie(REFRESH_COOKIE, pair.refreshToken, REFRESH_COOKIE_OPTIONS);
      res.json({ accessToken: pair.accessToken });
    } catch (err) {
      res.clearCookie(REFRESH_COOKIE, { path: REFRESH_COOKIE_OPTIONS.path });
      throw err;
    }
  }));

  const verify = ninsho.auth.verify();

  app.get('/api/ninsho/me', verify, route(async (req, res) => {
    const auth = getAuth(req);
    // Every request is checked against the live session in Redis, so the
    // answer can change the moment the session is ended.
    const user = await db.findUserById(auth.userId);
    if (!user) return fail(res, 401, 'NO_USER', 'This account no longer exists.');
    res.json({
      user,
      sessionId: auth.sessionId,
      checkedAgainst: 'the live session in Redis, plus a signature from this device’s key',
    });
  }));

  app.get('/api/ninsho/sessions', verify, route(async (req, res) => {
    const auth = getAuth(req);
    const sessions = await ninsho.auth.listSessions(auth.userId, auth.sessionId);
    res.json({
      sessions: sessions.map((s) => ({
        current: s.current,
        createdAt: s.createdAt,
        lastUsedAt: s.lastUsedAt,
        refreshes: s.generation,
      })),
    });
  }));

  // The cookie is cleared before verification, so even a refused sign-out
  // leaves no refresh credential behind in this browser.
  const clearRefresh = (_req: Request, res: Response, next: NextFunction) => {
    res.clearCookie(REFRESH_COOKIE, { path: REFRESH_COOKIE_OPTIONS.path });
    next();
  };

  app.post('/api/ninsho/logout', clearRefresh, verify, route(async (req, res) => {
    const { sessionId } = getAuth(req);
    await ninsho.auth.revokeSession(sessionId, 'logout');
    res.json({ serverAction: 'session ended', sessionId });
  }));

  app.post('/api/ninsho/logout-all', clearRefresh, verify, route(async (req, res) => {
    const { userId } = getAuth(req);
    const ended = (await ninsho.auth.listSessions(userId)).length;
    await ninsho.auth.revokeAllForUser(userId, 'logout_all');
    res.json({ possible: true, sessionsEnded: ended });
  }));

  // ─── The attacker ───────────────────────────────────────────────────────
  // Replays whatever the page says was stolen, from a separate connection: no
  // browser, no cookies, no device key — only the stolen strings. It can only
  // call this app's own /me endpoints, never an arbitrary URL.

  app.post('/api/attacker/replay', route(async (req, res) => {
    const { side, token, proof, origin } = req.body ?? {};
    if (side !== 'jwt' && side !== 'ninsho') return fail(res, 400, 'BAD_SIDE', 'side must be jwt or ninsho');
    if (typeof token !== 'string' || token.length === 0 || token.length > 4096) {
      return fail(res, 400, 'BAD_TOKEN', 'Nothing to replay.');
    }
    if (proof !== undefined && (typeof proof !== 'string' || proof.length > 4096)) {
      return fail(res, 400, 'BAD_PROOF', 'Invalid proof.');
    }
    // DPoP proofs name the exact URL they were made for, so the replay must go
    // to the same origin the page is on. Only this server's own origin passes.
    const port = req.socket.localPort;
    let host: string;
    try {
      const url = new URL(String(origin));
      if (url.protocol !== 'http:' || !['localhost', '127.0.0.1'].includes(url.hostname) || Number(url.port) !== port) {
        throw new Error('foreign origin');
      }
      host = url.host;
    } catch {
      return fail(res, 400, 'BAD_ORIGIN', 'The attacker only replays against this app.');
    }

    const headers: Record<string, string> = {
      host,
      authorization: `${side === 'jwt' ? 'Bearer' : 'DPoP'} ${token}`,
    };
    if (typeof proof === 'string') headers.dpop = proof;
    const result = await rawGet(port ?? 0, `/api/${side}/me`, headers);
    res.json(result);
  }));

  // ─── Errors ─────────────────────────────────────────────────────────────

  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (isNinshoError(err)) {
      const { status, body } = toErrorResponse(err);
      return res.status(status).json(body);
    }
    console.error(err);
    fail(res, 500, 'INTERNAL', 'Something went wrong on the server.');
  });

  return app;
}

/** A GET over a fresh connection, with exactly the headers given. */
function rawGet(port: number, path: string, headers: Record<string, string>) {
  return new Promise<{ status: number; body: unknown }>((resolve, reject) => {
    const req = httpRequest({ host: '127.0.0.1', port, path, method: 'GET', headers }, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => (text += chunk));
      res.on('end', () => {
        let body: unknown = text;
        try {
          body = JSON.parse(text);
        } catch {
          // Leave non-JSON bodies as text.
        }
        resolve({ status: res.statusCode ?? 0, body });
      });
    });
    req.on('error', reject);
    req.end();
  });
}

export { JWT_TTL_SECONDS, NINSHO_ACCESS_TTL_SECONDS };
