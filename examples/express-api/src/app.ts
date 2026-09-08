import express, { type Express, type Request, type Response } from 'express';
import {
  Ninsho,
  MemoryStore,
  RedisStore,
  clientIp,
  getAuth,
  isNinshoError,
  RefreshReuseError,
  toErrorResponse,
  type NinshoStore,
} from '@ninshorg/server';
import { WebAuthnServer } from '@ninshorg/webauthn';
import {
  createUser,
  deliverResetLink,
  findByEmail,
  findById,
  setPassword,
  verifyCredentials,
} from './users.js';
import {
  findByCredentialId,
  fromBase64Url,
  listForUser,
  saveCredential,
  updateSignCount,
} from './credentials.js';

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
  /**
   * How recently the user must have authenticated to add a passkey. Default
   * 300 seconds.
   *
   * Exposed so the tests can exercise the expiry without waiting five minutes;
   * a real deployment would simply take the default.
   */
  readonly passkeyStepUpSeconds?: number;
  /**
   * The WebAuthn relying-party id — a registrable domain suffix of the origin.
   *
   * Credentials are scoped to it, so changing it invalidates every passkey
   * already registered. Defaults suit local development.
   */
  readonly rpId?: string;
  /** Exact origin(s) passkey ceremonies may come from. No wildcards. */
  readonly webauthnOrigin?: string | readonly string[];
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
    if (part.slice(0, index).trim() !== name) continue;

    // `decodeURIComponent` throws a `URIError` on a malformed escape — a bare
    // `%`, or a truncated `%E0%A4%`. The cookie header is attacker-supplied,
    // and an unguarded call here turned `Cookie: ninsho_rt=%` into a 500 on
    // the refresh route rather than the 401 it should be.
    //
    // A value that cannot be decoded is not a credential, so it reads as
    // absent. That is the same answer as no cookie at all, which is what a
    // caller presenting nonsense deserves.
    try {
      return decodeURIComponent(part.slice(index + 1).trim());
    } catch {
      return undefined;
    }
  }
  return undefined;
}

/**
 * Forwards a rejected async handler to the error middleware.
 *
 * ─── Kept, though Express 5 no longer needs it ────────────────────────────
 * Express 4 did not catch rejections from an `async` handler: a handler that
 * threw — a store outage, a rejected passkey ceremony — produced an unhandled
 * rejection, the request hung until the client timed out, and the error
 * middleware never ran. A dashboard saw a timeout rather than the 400 or 503
 * that actually happened.
 *
 * Express 5 forwards them itself, so on this version the wrapper is a no-op.
 * It stays for two reasons: this file is meant to be copied, and a reader who
 * pastes a route into an Express 4 application should not inherit that bug
 * silently; and it makes the forwarding visible rather than something you have
 * to know about the framework version to reason about.
 * ──────────────────────────────────────────────────────────────────────────
 */
function route(
  handler: (req: Request, res: Response) => Promise<void>,
): (req: Request, res: Response, next: express.NextFunction) => void {
  return (req, res, next) => {
    handler(req, res).catch(next);
  };
}

export function createApp(options: AppOptions = {}): { app: Express; auth: Ninsho } {
  const secureCookies = options.secureCookies ?? process.env['NODE_ENV'] === 'production';
  const trustProxy = options.trustProxy ?? false;

  // ── The entire Ninsho configuration ──────────────────────────────────────
  // No keys to generate, no algorithm to choose. The defaults are the secure
  // ones: opaque tokens, fail-closed on a store outage, five-minute access
  // tokens, refresh rotation with reuse detection.
  const store = options.store ?? new MemoryStore();
  const auth = new Ninsho({ store });

  // ── Passkeys ─────────────────────────────────────────────────────────────
  // The same store backs both. Challenges are short-lived and single-use, so
  // they belong wherever session state already lives rather than in a second
  // piece of infrastructure.
  const stepUpSeconds = options.passkeyStepUpSeconds ?? 300;
  const rpId = options.rpId ?? 'localhost';
  const webauthn = new WebAuthnServer({
    rpId,
    rpName: 'Ninsho Example',
    origin: options.webauthnOrigin ?? `https://${rpId}`,
    store,
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


  /**
   * Client signals for a request.
   *
   * Ninsho hashes these before storing them, so the raw address never reaches
   * the store. They are recorded for one purpose: when a rotated refresh token
   * is replayed, the alarm can say whether the replay came from the same
   * client as the rest of the session. Nothing branches on them — a forged
   * `User-Agent` must not be able to end anyone's session.
   */
  function signalsFor(req: Request): { userAgent?: string; ip?: string } {
    const userAgent = req.headers['user-agent'];
    return {
      ...(typeof userAgent === 'string' ? { userAgent } : {}),
      ip: clientIp(req, trustProxy),
    };
  }

  // ── Registration ─────────────────────────────────────────────────────────

  app.post(
    '/auth/register',
    auth.rateLimit({
      action: 'register',
      perIp: { limit: 10, windowMs: 60 * 60 * 1000 },
      trustProxy,
    }),
    route(async (req: Request, res: Response) => {
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
        const pair = await auth.createSession(
          {
            userId: user.id,
            roles: user.roles,
            scopes: user.scopes,
            tenant: user.tenant,
          },
          { signals: signalsFor(req) },
        );

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
    }),
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
    route(async (req: Request, res: Response) => {
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

      const pair = await auth.createSession(
        {
          userId: user.id,
          roles: user.roles,
          scopes: user.scopes,
          tenant: user.tenant,
        },
        { signals: signalsFor(req) },
      );

      setRefreshCookie(res, pair.refreshToken, pair.refreshExpiresAt);
      // The refresh token goes in the cookie only — never in the body, where
      // application code could log it or place it in storage a script can read.
      res.json({
        accessToken: pair.accessToken,
        expiresAt: pair.accessExpiresAt,
        user: { id: user.id, email: user.email },
      });
    }),
  );

  // ── Refresh ──────────────────────────────────────────────────────────────

  app.post('/auth/refresh', route(async (req: Request, res: Response) => {
    const token = readCookie(req, REFRESH_COOKIE);
    if (token === undefined) {
      res.status(401).json({ error: { code: 'REFRESH_INVALID', message: 'Session could not be renewed' } });
      return;
    }

    try {
      const pair = await auth.refresh(token, { signals: signalsFor(req) });
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
  }));

  // ── Logout ───────────────────────────────────────────────────────────────

  app.post('/auth/logout', auth.verify(), route(async (req: Request, res: Response) => {
    await auth.revokeSession(getAuth(req).sessionId, 'logout');
    clearRefreshCookie(res);
    res.status(204).end();
  }));

  app.post('/auth/logout-all', auth.verify(), route(async (req: Request, res: Response) => {
    await auth.revokeAllForUser(getAuth(req).userId, 'logout_all');
    clearRefreshCookie(res);
    res.status(204).end();
  }));

  // ── Sessions ─────────────────────────────────────────────────────────────

  app.get('/auth/sessions', auth.verify(), route(async (req: Request, res: Response) => {
    const context = getAuth(req);
    res.json({ sessions: await auth.listSessions(context.userId, context.sessionId) });
  }));

  // ── Password reset ───────────────────────────────────────────────────────
  // The flow most often got wrong, and every way of getting it wrong is a full
  // account takeover. Three things below are doing the work.

  app.post(
    '/auth/password/forgot',
    auth.rateLimit({
      // Without this the endpoint is an email-flooding tool aimed at your
      // users, and no property of the token itself helps. Two dimensions: the
      // per-address bucket stops one victim being targeted, the per-IP bucket
      // stops one attacker working through a list.
      action: 'password_forgot',
      perIp: { limit: 10, windowMs: 60 * 60 * 1000 },
      perAccount: { limit: 3, windowMs: 60 * 60 * 1000 },
      identify: (req) => (req.body as { email?: string } | undefined)?.email,
      trustProxy,
    }),
    route(async (req: Request, res: Response) => {
      const { email } = req.body as { email?: unknown };

      if (typeof email === 'string') {
        const user = findByEmail(email);
        if (user !== undefined) {
          const { token } = await auth.oneTimeTokens.issue({
            purpose: 'password-reset',
            subject: user.id,
          });
          // Where a real application sends the email. The token appears here
          // and nowhere else — never logged, never stored, never returned.
          deliverResetLink(user.email, token);
        }
      }

      // The same answer whether or not the address exists, and whether or not
      // it was even a string. Anything else turns this into the
      // account-enumeration oracle the login route works to avoid, and doing
      // it correctly here matters more: /auth/login at least demands a
      // password guess, while this endpoint needs only an address.
      res.status(202).json({
        message: 'If that address has an account, a reset link is on its way.',
      });
    }),
  );

  app.post(
    '/auth/password/reset',
    auth.rateLimit({
      action: 'password_reset',
      perIp: { limit: 20, windowMs: 60 * 60 * 1000 },
      trustProxy,
    }),
    route(async (req: Request, res: Response) => {
      const { token, password } = req.body as { token?: unknown; password?: unknown };

      if (typeof token !== 'string' || typeof password !== 'string') {
        res.status(400).json({
          error: { code: 'INVALID_BODY', message: 'token and password are required' },
        });
        return;
      }
      if (password.length < 12) {
        res.status(400).json({
          error: { code: 'WEAK_PASSWORD', message: 'password must be at least 12 characters' },
        });
        return;
      }

      // Single-use and atomic: two people clicking the same link cannot both
      // succeed. Throws a 400 for expired, already-used, never-issued and
      // wrong-purpose alike — one answer, so the endpoint says nothing about
      // which links were real.
      const claim = await auth.oneTimeTokens.consume('password-reset', token);

      await setPassword(claim.subject, password);

      // The step people forget. Whoever forced the reset may already hold a
      // session; leaving those alive means the password change accomplished
      // nothing. This is also why the reset is worth auditing — it is the
      // moment an account changes hands, legitimately or not.
      await auth.revokeAllForUser(claim.subject, 'credential_changed');
      req.log?.('SECURITY: password reset completed, all sessions revoked');

      res.status(204).end();
    }),
  );

  // ── Passkey registration ─────────────────────────────────────────────────
  // Adding a passkey requires an existing session. A passkey is a new way into
  // an account, so creating one has to be at least as protected as using one;
  // an unauthenticated "add a passkey" endpoint is account takeover with extra
  // steps.

  app.post(
    '/auth/passkey/register/start',
    auth.verify(),
    // A live session is not enough. Someone who walked up to an unlocked
    // laptop has a live session; enrolling a passkey from it would hand them
    // permanent access. `requireFreshAuth` reads when the user actually
    // authenticated, which a refresh does not reset — so a month-old session
    // that has been quietly refreshing cannot satisfy it.
    auth.requireFreshAuth(stepUpSeconds),
    route(async (req: Request, res: Response) => {
      const context = getAuth(req);
      const user = findById(context.userId);

      res.json(
        await webauthn.startRegistration({
          userId: context.userId,
          userName: user?.email ?? context.userId,
          // Passing what the user already has stops the authenticator creating
          // a second credential for the same account on the same device —
          // which produces a user with two passkeys, no way to tell them
          // apart, and no idea why one of them stopped working.
          existingCredentials: listForUser(context.userId).map((credential) => ({
            credentialId: fromBase64Url(credential.credentialId),
          })),
        }),
      );
    }),
  );

  app.post(
    '/auth/passkey/register/finish',
    auth.verify(),
    auth.requireFreshAuth(stepUpSeconds),
    route(async (req: Request, res: Response) => {
      const context = getAuth(req);
      const body = req.body as { clientDataJSON?: unknown; attestationObject?: unknown };

      if (typeof body.clientDataJSON !== 'string' || typeof body.attestationObject !== 'string') {
        res.status(400).json({
          error: {
            code: 'INVALID_BODY',
            message: 'clientDataJSON and attestationObject are required',
          },
        });
        return;
      }

      // The second argument binds the ceremony to the signed-in user. Without
      // it, a challenge issued for one account could be completed against
      // another — the response carries a valid signature either way, so
      // nothing else would notice.
      const verified = await webauthn.finishRegistration(
        {
          clientDataJSON: fromBase64Url(body.clientDataJSON),
          attestationObject: fromBase64Url(body.attestationObject),
        },
        context.userId,
      );

      const credential = saveCredential({
        credentialId: verified.credentialId,
        publicKey: verified.credentialPublicKey,
        signCount: verified.signCount,
        userId: verified.userId,
        backedUp: verified.backedUp,
      });

      res.status(201).json({
        credentialId: credential.credentialId,
        backedUp: credential.backedUp,
        createdAt: credential.createdAt,
      });
    }),
  );

  app.get('/auth/passkeys', auth.verify(), (req: Request, res: Response) => {
    res.json({
      passkeys: listForUser(getAuth(req).userId).map((credential) => ({
        credentialId: credential.credentialId,
        backedUp: credential.backedUp,
        createdAt: credential.createdAt,
        // The public key is deliberately not returned. It is not secret, but an
        // endpoint that hands out key material invites someone to trust it for
        // something it was never verified for.
      })),
    });
  });

  // ── Passkey sign-in ──────────────────────────────────────────────────────

  app.post(
    '/auth/passkey/login/start',
    auth.rateLimit({
      // Cheaper than password login — no scrypt — but still worth limiting: it
      // writes a challenge to the store on every call.
      action: 'passkey_login',
      perIp: { limit: 30, windowMs: 15 * 60 * 1000 },
      trustProxy,
    }),
    route(async (_req: Request, res: Response) => {
      // No user id and no allowCredentials: a usernameless flow, where the
      // authenticator offers whatever discoverable credentials it holds. It
      // also means this endpoint reveals nothing about which accounts exist.
      res.json(await webauthn.startAuthentication());
    }),
  );

  app.post('/auth/passkey/login/finish', route(async (req: Request, res: Response) => {
    const body = req.body as {
      credentialId?: unknown;
      clientDataJSON?: unknown;
      authenticatorData?: unknown;
      signature?: unknown;
      userHandle?: unknown;
    };

    if (
      typeof body.credentialId !== 'string' ||
      typeof body.clientDataJSON !== 'string' ||
      typeof body.authenticatorData !== 'string' ||
      typeof body.signature !== 'string'
    ) {
      res
        .status(400)
        .json({ error: { code: 'INVALID_BODY', message: 'the assertion is incomplete' } });
      return;
    }

    const stored = findByCredentialId(body.credentialId);
    if (stored === undefined) {
      // The same answer a failed verification gives below. An "unknown
      // credential" that reads differently from "bad signature" tells an
      // attacker which credential ids are real.
      res.status(401).json({
        error: { code: 'PASSKEY_REJECTED', message: 'Could not sign in with that passkey' },
      });
      return;
    }

    let result;
    try {
      result = await webauthn.finishAuthentication(
        {
          credentialId: fromBase64Url(body.credentialId),
          clientDataJSON: fromBase64Url(body.clientDataJSON),
          authenticatorData: fromBase64Url(body.authenticatorData),
          signature: fromBase64Url(body.signature),
          userHandle:
            typeof body.userHandle === 'string' ? fromBase64Url(body.userHandle) : undefined,
        },
        {
          credentialId: fromBase64Url(stored.credentialId),
          publicKey: fromBase64Url(stored.publicKey),
          signCount: stored.signCount,
          userId: stored.userId,
        },
      );
    } catch {
      // One answer for every reason a passkey did not work. The specific cause
      // is already in the error's `detail`, which belongs in the server log and
      // nowhere else.
      res.status(401).json({
        error: { code: 'PASSKEY_REJECTED', message: 'Could not sign in with that passkey' },
      });
      return;
    }

    // Write the counter back before issuing anything. Skipping this leaves the
    // stored value stale forever and clone detection quietly stops working —
    // the check still runs, always against the same number.
    updateSignCount(stored.credentialId, result.newSignCount);

    const user = findById(result.principal.userId);
    if (user === undefined) {
      // The credential outlived its account. Refusing is the only safe answer:
      // a principal with no user behind it has no roles to carry.
      res.status(401).json({
        error: { code: 'PASSKEY_REJECTED', message: 'Could not sign in with that passkey' },
      });
      return;
    }

    // WebAuthn proved *who*. Roles and scopes come from the directory — a
    // passkey says nothing about what its owner may do.
    const pair = await auth.createSession({
      ...result.principal,
      roles: user.roles,
      scopes: user.scopes,
      tenant: user.tenant,
    });

    setRefreshCookie(res, pair.refreshToken, pair.refreshExpiresAt);
    res.json({
      accessToken: pair.accessToken,
      expiresAt: pair.accessExpiresAt,
      user: { id: user.id, email: user.email },
      userVerified: result.userVerified,
    });
  }));

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

  app.get('/health', route(async (_req: Request, res: Response) => {
    const ok = await auth.health();
    res.status(ok ? 200 : 503).json({ status: ok ? 'ok' : 'degraded' });
  }));

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
