/**
 * The application every walkthrough on the website was recorded from.
 *
 * ─── What this is ─────────────────────────────────────────────────────────
 * A small, complete Express app built on `@ninshorg/server`, written the way
 * an application would write it. `walkthroughs.ts` sends it real HTTP
 * requests over a real socket and records what comes back, and the website
 * replays those recordings — so every status code, store operation and audit
 * event on those pages was produced by this file and the published library.
 *
 * The website shows this source verbatim beside the traces. That is the
 * point: a visitor can read the entire program that produced what they are
 * looking at, and nothing between the two is hidden.
 *
 * ─── Two liberties, both for the recording's sake ─────────────────────────
 * 1. The refresh token and the password-reset token come back in the JSON
 *    body so the walkthrough can show them. In an application the refresh
 *    token belongs in an httpOnly cookie and the reset token in an email —
 *    `examples/express-api` does both properly.
 * 2. Passwords are compared in plain text against a two-user table. Verifying
 *    credentials is the application's job and not what this demonstrates;
 *    `examples/express-api` uses scrypt.
 * ──────────────────────────────────────────────────────────────────────────
 */
import { timingSafeEqual } from 'node:crypto';
import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import { Ninsho, getAuth, type NinshoConfig, type NinshoStore, type AuditSink } from '@ninshorg/server';

/** The origin clients believe they are talking to. See `setRequestUrlBuilder`. */
export const ORIGIN = 'https://api.example.test';

/** A stand-in for your user table. */
const USERS: Readonly<Record<string, { id: string; password: string; roles: string[] }>> = {
  'alice@example.test': { id: 'u_alice', password: 'correct horse', roles: ['user'] },
  'bob@example.test': { id: 'u_bob', password: 'battery staple', roles: ['user'] },
};

/** A stand-in for your password check. Constant-time, and nothing more. */
function checkPassword(email: unknown, password: unknown): (typeof USERS)[string] | undefined {
  if (typeof email !== 'string' || typeof password !== 'string') return undefined;
  const user = USERS[email];
  if (!user) return undefined;
  const given = Buffer.from(password);
  const stored = Buffer.from(user.password);
  return given.length === stored.length && timingSafeEqual(given, stored) ? user : undefined;
}

export interface WalkthroughAppOptions {
  readonly store: NinshoStore;
  readonly audit: AuditSink;
  /** Anything beyond the store and audit sink — `binding: 'dpop'`, for one. */
  readonly config?: Omit<Partial<NinshoConfig>, 'store' | 'audit'>;
}

export function createWalkthroughApp(options: WalkthroughAppOptions): { app: Express; auth: Ninsho } {
  const auth = new Ninsho({ store: options.store, audit: options.audit, ...options.config });

  // The app sits behind one TLS-terminating proxy, so the URL a DPoP proof
  // signs is the public one, not the socket the proxy forwards to.
  //
  // The origin comes from configuration, never from the `Host` header — an
  // attacker who controls `Host` would control both sides of the comparison.
  // And it is concatenated rather than resolved with `new URL(path, ORIGIN)`,
  // because `new URL('//elsewhere/x', ORIGIN)` is `https://elsewhere/x`: the
  // request target must contribute a path, never an authority.
  //
  // Set before any route mounts `auth.verify()`, which captures it.
  auth.setRequestUrlBuilder((req) => `${ORIGIN}${(req as unknown as Request).originalUrl}`);

  const dpop = auth.config.binding === 'dpop';
  const signals = (req: Request) => ({
    ...(typeof req.headers['user-agent'] === 'string' && { userAgent: req.headers['user-agent'] }),
    ...(typeof req.headers['x-forwarded-for'] === 'string' && { ip: req.headers['x-forwarded-for'] }),
  });

  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '16kb' }));

  // ── Sign in ──────────────────────────────────────────────────────────────
  // Two buckets. Per address alone misses a botnet that spreads its guesses;
  // per account alone lets one person lock a whole office out.
  app.post(
    '/login',
    auth.rateLimit({
      action: 'login',
      perIp: { limit: 20, windowMs: 60_000 },
      perAccount: { limit: 5, windowMs: 900_000 },
      identify: (req) => (req.body as { email?: string } | undefined)?.email,
      trustProxy: 1,
    }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const user = checkPassword(req.body?.email, req.body?.password);
        if (!user) {
          res.status(401).json({ error: { code: 'INVALID_CREDENTIALS', message: 'Email or password is incorrect' } });
          return;
        }
        // Under DPoP the session is bound to the key that signed this request.
        const confirmationKey = dpop ? await auth.confirmProofOfPossession(req) : undefined;
        const pair = await auth.createSession(
          { userId: user.id, roles: user.roles, scopes: [] },
          { signals: signals(req), ...(confirmationKey !== undefined && { confirmationKey }) },
        );
        res.json({ accessToken: pair.accessToken, refreshToken: pair.refreshToken, expiresAt: pair.accessExpiresAt });
      } catch (error) {
        next(error);
      }
    },
  );

  // ── Refresh ──────────────────────────────────────────────────────────────
  app.post('/refresh', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const pair = await auth.refresh(String(req.body?.refreshToken ?? ''), { signals: signals(req) });
      res.json({ accessToken: pair.accessToken, refreshToken: pair.refreshToken, expiresAt: pair.accessExpiresAt });
    } catch (error) {
      next(error);
    }
  });

  // ── Sign out everywhere ──────────────────────────────────────────────────
  app.post('/logout-all', auth.verify(), async (req: Request, res: Response, next: NextFunction) => {
    try {
      await auth.revokeAllForUser(getAuth(req).userId, 'logout_all');
      res.status(204).end();
    } catch (error) {
      next(error);
    }
  });

  // ── Resources ────────────────────────────────────────────────────────────
  app.get('/me', auth.verify(), (req: Request, res: Response) => {
    const { userId, roles } = getAuth(req);
    res.json({ userId, roles });
  });

  // Authenticated is not the same as entitled: without requireOwner, any
  // signed-in user reads anyone's orders by changing the id in the URL.
  app.get(
    '/users/:id/orders',
    auth.verify(),
    auth.requireOwner((req) => (req as Request).params?.['id']),
    (req: Request, res: Response) => {
      res.json({ owner: req.params['id'], orders: [] });
    },
  );

  // ── Password reset ───────────────────────────────────────────────────────
  app.post('/password-reset/request', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = USERS[String(req.body?.email ?? '')];
      if (!user) {
        // Same answer for an unknown address, so this is not an oracle.
        res.status(202).json({ status: 'If that address exists, a link is on its way' });
        return;
      }
      const issued = await auth.oneTimeTokens.issue({ purpose: 'password-reset', subject: user.id, ttlSeconds: 900 });
      // Emailed, in an application. Returned here so the walkthrough can use it.
      res.status(202).json({ status: 'If that address exists, a link is on its way', token: issued.token });
    } catch (error) {
      next(error);
    }
  });

  app.post('/password-reset/confirm', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const claim = await auth.oneTimeTokens.consume('password-reset', String(req.body?.token ?? ''));
      // Set the new password for claim.subject here — then end every session.
      await auth.revokeAllForUser(claim.subject, 'credential_changed');
      res.json({ reset: claim.subject });
    } catch (error) {
      next(error);
    }
  });

  app.get('/health', async (_req: Request, res: Response) => {
    const ok = await auth.health();
    res.status(ok ? 200 : 503).json({ status: ok ? 'ok' : 'degraded' });
  });

  // Ninsho's errors carry a client-safe message and a server-only detail; the
  // handler sends the first and never the second.
  app.use(auth.errorHandler());

  return { app, auth };
}
