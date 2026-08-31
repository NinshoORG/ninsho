import express, { type Express, type Request, type Response } from 'express';
import {
  Ninsho,
  MemoryStore,
  RedisStore,
  getAuth,
  isNinshoError,
  RefreshReuseError,
  toErrorResponse,
  type NinshoStore,
} from '@ninsho/server';
import { createUser, findById, verifyCredentials } from './users.js';

/**
 * A complete, working API built on Ninsho.
 *
 * Everything here is meant to be copied. Where a decision could reasonably go
 * either way, the comment says which way and why — the aim is that following
 * this example produces a secure integration without having to have read the
 * library's source.
 */

/** Name of the cookie carrying the refresh token. */
const REFRESH_COOKIE = 'ninsho_rt';

export interface AppOptions {
  /** Defaults to an in-memory store; pass a RedisStore in production. */
  readonly store?: NinshoStore;
  /**
   * How much of `X-Forwarded-For` to trust. No default anywhere in Ninsho —
   * see the note on the login route.
   */
  readonly trustProxy?: false | number | 'all';
  /** Set false when serving over plain HTTP in local development. */
  readonly secureCookies?: boolean;
}

/**
 * Minimal cookie parsing, so this example needs no cookie-parser dependency.
 * Use a real parser in production; this one exists to keep the example's
 * dependency list to Express alone.
 */
function readCookie(req: Request, name: string): string | undefined {
  const header = req.headers.cookie;
  if (typeof header !== 'string') return undefined;

  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    if (part.slice(0, index).trim() === name) {
      return decodeURIComponent(part.slice(index + 1).trim());
    }
  }
  return undefined;
}

export function createApp(options: AppOptions = {}): { app: Express; auth: Ninsho } {
  const secureCookies = options.secureCookies ?? process.env['NODE_ENV'] === 'production';
  const trustProxy = options.trustProxy ?? false;

  // ── The entire Ninsho configuration ──────────────────────────────────────
  // No keys to generate, no algorithm to choose. The defaults are the secure
  // ones: opaque tokens, fail-closed on a store outage, five-minute access
  // tokens, refresh rotation with reuse detection.
  const auth = new Ninsho({
    store: options.store ?? new MemoryStore(),
  });

  const app = express();
  app.disable('x-powered-by');
  // Body limit before any parsing work: password verification is deliberately
  // expensive, so an unbounded body is an amplification vector.
  app.use(express.json({ limit: '16kb' }));

  /**
   * Sets the refresh cookie.
   *
   * `httpOnly` keeps it away from any script on the page, which is what makes
   * an XSS bug expensive rather than catastrophic. `sameSite: 'strict'` means
   * it is not attached to cross-site requests, so /auth/refresh cannot be
   * driven from another origin.
   */
  function setRefreshCookie(res: Response, token: string, expiresAt: string): void {
    res.cookie(REFRESH_COOKIE, token, {
      httpOnly: true,
      sameSite: 'strict',
      secure: secureCookies,
      path: '/auth',
      expires: new Date(expiresAt),
    });
  }

  function clearRefreshCookie(res: Response): void {
    res.clearCookie(REFRESH_COOKIE, {
      httpOnly: true,
      sameSite: 'strict',
      secure: secureCookies,
      path: '/auth',
    });
  }

  // ── Registration ─────────────────────────────────────────────────────────

  app.post(
    '/auth/register',
    auth.rateLimit({
      action: 'register',
      perIp: { limit: 10, windowMs: 60 * 60 * 1000 },
      trustProxy,
    }),
    async (req: Request, res: Response) => {
      const { email, password } = req.body as { email?: unknown; password?: unknown };

      if (typeof email !== 'string' || typeof password !== 'string') {
        res.status(400).json({ error: { code: 'INVALID_BODY', message: 'email and password are required' } });
        return;
      }
      if (password.length < 12) {
        // Length is the property that matters. No composition rules: they push
        // people toward predictable substitutions and are not what NIST
        // SP 800-63B asks for.
        res.status(400).json({ error: { code: 'WEAK_PASSWORD', message: 'password must be at least 12 characters' } });
        return;
      }

      try {
        const user = await createUser({ email, password });
        const pair = await auth.createSession({
          userId: user.id,
          roles: user.roles,
          scopes: user.scopes,
          tenant: user.tenant,
        });

        setRefreshCookie(res, pair.refreshToken, pair.refreshExpiresAt);
        res.status(201).json({
          accessToken: pair.accessToken,
          expiresAt: pair.accessExpiresAt,
          user: { id: user.id, email: user.email },
        });
      } catch {
        // Deliberately the same response as success would produce a conflict
        // for. Saying "already registered" turns this endpoint into the
        // account-enumeration oracle the login route works to avoid.
        res.status(202).json({ message: 'If the address is available, the account has been created.' });
      }
    },
  );

  // ── Login ────────────────────────────────────────────────────────────────

  app.post(
    '/auth/login',
    auth.rateLimit({
      action: 'login',
      // Two dimensions, because they stop different attacks. The per-IP bucket
      // stops one host hammering the endpoint. The per-account bucket stops a
      // botnet spreading attempts across thousands of addresses so no single
      // one ever approaches a limit — which a per-IP limit alone never sees.
      perIp: { limit: 20, windowMs: 15 * 60 * 1000 },
      perAccount: { limit: 5, windowMs: 15 * 60 * 1000 },
      identify: (req) => (req.body as { email?: string } | undefined)?.email,
      // No default: keying on the wrong address either locks out everyone
      // behind a shared proxy, or lets one attacker bypass the limit by
      // rotating a header. Set it to match your deployment.
      trustProxy,
    }),
    async (req: Request, res: Response) => {
      const { email, password } = req.body as { email?: unknown; password?: unknown };

      if (typeof email !== 'string' || typeof password !== 'string') {
        res.status(400).json({ error: { code: 'INVALID_BODY', message: 'email and password are required' } });
        return;
      }

      const user = await verifyCredentials(email, password);
      if (user === null) {
        // One message for "no such account" and "wrong password". Any
        // distinction here is an enumeration oracle.
        res.status(401).json({ error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password' } });
        return;
      }

      const pair = await auth.createSession({
        userId: user.id,
        roles: user.roles,
        scopes: user.scopes,
        tenant: user.tenant,
      });

      setRefreshCookie(res, pair.refreshToken, pair.refreshExpiresAt);
      // The refresh token goes in the cookie only — never in the body, where
      // application code could log it or place it in storage a script can read.
      res.json({
        accessToken: pair.accessToken,
        expiresAt: pair.accessExpiresAt,
        user: { id: user.id, email: user.email },
      });
    },
  );

  // ── Refresh ──────────────────────────────────────────────────────────────

  app.post('/auth/refresh', async (req: Request, res: Response) => {
    const token = readCookie(req, REFRESH_COOKIE);
    if (token === undefined) {
      res.status(401).json({ error: { code: 'REFRESH_INVALID', message: 'Session could not be renewed' } });
      return;
    }

    try {
      const pair = await auth.refresh(token);
      setRefreshCookie(res, pair.refreshToken, pair.refreshExpiresAt);
      res.json({ accessToken: pair.accessToken, expiresAt: pair.accessExpiresAt });
    } catch (error) {
      // Always clear the cookie on failure. Leaving a dead token in the
      // browser means the next refresh replays it, which — after a genuine
      // rotation — looks exactly like theft.
      clearRefreshCookie(res);

      if (error instanceof RefreshReuseError) {
        // The session has already been revoked by the time this is thrown.
        // This is where you would notify the account owner: a rotated refresh
        // token being presented again is the strongest signal of credential
        // theft an authentication system can observe.
        req.log?.('SECURITY: refresh token reuse detected — session revoked');
      }

      const { status, body } = toErrorResponse(error);
      res.status(status).json(body);
    }
  });

  // ── Logout ───────────────────────────────────────────────────────────────

  app.post('/auth/logout', auth.verify(), async (req: Request, res: Response) => {
    await auth.revokeSession(getAuth(req).sessionId, 'logout');
    clearRefreshCookie(res);
    res.status(204).end();
  });

  app.post('/auth/logout-all', auth.verify(), async (req: Request, res: Response) => {
    await auth.revokeAllForUser(getAuth(req).userId, 'logout_all');
    clearRefreshCookie(res);
    res.status(204).end();
  });

  // ── Sessions ─────────────────────────────────────────────────────────────

  app.get('/auth/sessions', auth.verify(), async (req: Request, res: Response) => {
    const context = getAuth(req);
    res.json({ sessions: await auth.listSessions(context.userId, context.sessionId) });
  });

  // ── Protected resources ──────────────────────────────────────────────────

  app.get('/me', auth.verify(), (req: Request, res: Response) => {
    const context = getAuth(req);
    const user = findById(context.userId);
    res.json({
      id: context.userId,
      email: user?.email,
      roles: context.roles,
      sessionId: context.sessionId,
    });
  });

  app.get(
    '/admin/reports',
    auth.verify(),
    auth.requireRole('admin'),
    (_req: Request, res: Response) => {
      res.json({ reports: [] });
    },
  );

  /**
   * The check that is most often missing.
   *
   * Without `requireOwner`, this route reads `:id` from the URL and trusts it
   * because the request was authenticated — so any signed-in user reads any
   * other user's orders by changing the value. That is OWASP API Security #1,
   * and authentication alone does nothing about it: verifying a token says who
   * is calling, not what they may address.
   */
  app.get(
    '/users/:id/orders',
    auth.verify(),
    auth.requireOwner((req) => req.params?.['id']),
    (_req: Request, res: Response) => {
      res.json({ orders: [] });
    },
  );

  // ── Health ───────────────────────────────────────────────────────────────

  app.get('/health', async (_req: Request, res: Response) => {
    const ok = await auth.health();
    res.status(ok ? 200 : 503).json({ status: ok ? 'ok' : 'degraded' });
  });

  // ── Error handling ───────────────────────────────────────────────────────
  // Last, and with four parameters, which is how Express recognises it.

  app.use((error: unknown, _req: Request, res: Response, _next: express.NextFunction) => {
    if (res.headersSent) return;

    // Ninsho's own errors already carry a status and a client-safe message.
    if (isNinshoError(error)) {
      const { status, body } = toErrorResponse(error);
      res.status(status).json(body);
      return;
    }

    // Express-convention errors — body-parser's PayloadTooLargeError, a
    // malformed-JSON SyntaxError — carry a 4xx status meaning "the client sent
    // something wrong". Collapsing those to 500 would tell a caller the server
    // broke when in fact their request was rejected, and would hide a working
    // body limit behind a misleading status.
    //
    // The status is surfaced; the message is not. Framework error text names
    // internals (`raw-body`, byte limits, parse offsets) that a client has no
    // business seeing.
    const status = (error as { status?: unknown; statusCode?: unknown }).status
      ?? (error as { statusCode?: unknown }).statusCode;

    if (typeof status === 'number' && status >= 400 && status < 500) {
      res.status(status).json({
        error: { code: 'BAD_REQUEST', message: 'Request could not be processed' },
      });
      return;
    }

    // Anything else is genuinely unexpected. Log it server-side and tell the
    // client nothing — an unrecognised value cannot be assumed safe to describe.
    console.error('[example] unhandled error', error);
    res.status(500).json({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  return { app, auth };
}

/** Convenience for the RedisStore path, used by the runnable entry point. */
export function createRedisStore(url: string): NinshoStore {
  return new RedisStore(url);
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      /** Optional hook the tests use to observe security events. */
      log?: (message: string) => void;
    }
  }
}
