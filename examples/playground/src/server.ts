/**
 * Ninsho playground — an interactive protocol explorer.
 *
 * ─── What this is for ─────────────────────────────────────────────────────
 * The README makes claims: a raw token never reaches the store, a replayed
 * refresh token kills the whole family, a reset link works exactly once. Each
 * has a test behind it, and a test is the right evidence for a maintainer and
 * the wrong evidence for someone deciding whether to adopt the thing.
 *
 * So this runs the real library — not a mock, not a re-implementation — and
 * shows what actually happens: the bytes on the wire, the keys in the store,
 * the audit events, and the attacks failing. Every response carries a trace of
 * the store operations the request performed.
 *
 * ─── What it is not ───────────────────────────────────────────────────────
 * A production integration. It keeps one shared in-memory session for everyone
 * who opens the page, records every value that passes through the store, and
 * hands out internals over HTTP. `examples/express-api` is the one to copy.
 * ──────────────────────────────────────────────────────────────────────────
 */

import express, { type Request, type Response } from 'express';
import {
  MemoryStore,
  Ninsho,
  MemoryAuditSink,
  isNinshoError,
  toErrorResponse,
  generateKeyPair,
  generateDpopKeyPair,
  createDpopProof,
  jwkThumbprint,
  type Middleware,
  type Principal,
  type SecurityEvent,
  type SessionSummary,
  type TokenPair,
} from '@ninsho/server';
import { decodeCbor, verifyRegistration } from '@ninsho/webauthn';
import { VirtualAuthenticator, createCertificate } from '@ninsho/webauthn/testing';
import { RecordingStore, type StoreOperation } from './store-recorder.ts';
import { VisitorRegistry } from './visitors.ts';
import {
  decodeAttestationObject,
  decodeAuthenticatorData,
  decodeDpopProof,
  decodePaseto,
  describeAttestationStatement,
} from './decode.ts';

const PORT = Number(process.env['PORT'] ?? 4000);

/**
 * The origin the browser reaches this on.
 *
 * A DPoP proof is bound to the exact URI it was minted for, so the value the
 * page signs and the value the server reconstructs have to agree. Reading it
 * from configuration rather than from a request header is the same advice
 * `defaultRequestUrl` gives.
 */
const PUBLIC_ORIGIN = process.env['PUBLIC_ORIGIN'] ?? `http://localhost:${PORT}`;

const DEMO_USER: Principal = {
  userId: 'usr_demo',
  roles: ['user'],
  scopes: ['profile:read'],
};

/** One world, rebuilt on demand so a visitor can always start clean. */
interface World {
  store: RecordingStore;
  auth: Ninsho;
  audit: MemoryAuditSink;
  /** The most recent pair handed out, so the UI can act without holding state. */
  latest: { accessToken: string; refreshToken: string } | null;
  /** Refresh tokens already rotated away, kept so "replay" has something to replay. */
  spent: string[];
  /** The last single-use token issued, for the reset demo. */
  resetToken: string | null;
  /** DPoP sessions bound to a key this visitor generated in their browser. */
  bound: Map<string, { auth: Ninsho; store: RecordingStore; accessToken: string }>;
  /** Releases the stores. The registry calls this on eviction. */
  close(): Promise<void>;
}

function build(): World {
  const audit = new MemoryAuditSink();
  const store = new RecordingStore(new MemoryStore());
  const bound = new Map<string, { auth: Ninsho; store: RecordingStore; accessToken: string }>();

  return {
    store,
    audit,
    auth: new Ninsho({ store, audit, refreshGraceSeconds: 0 }),
    latest: null,
    spent: [],
    resetToken: null,
    bound,
    async close(): Promise<void> {
      await store.close();
      for (const session of bound.values()) await session.store.close();
      bound.clear();
    },
  };
}

/**
 * One world per visitor.
 *
 * Sharing a single world was fine on a laptop and wrong the moment two people
 * open the page: one visitor's session would appear in another's store trace,
 * and the replay demonstration would revoke a session someone else was midway
 * through. Worse, it would misrepresent the library — a visitor seeing keys
 * they did not create would reasonably conclude Ninsho leaks state between
 * callers, when what leaked was the demo's own variable.
 */
const worlds = new VisitorRegistry<World>({ create: build });

/** Resolves the world belonging to this request, minting one on first visit. */
async function visitor(req: Request, res: Response): Promise<World> {
  return worlds.get(worlds.identify(req, res));
}

/** Everything a response carries alongside its result. */
interface Trace {
  readonly storeOps: readonly StoreOperation[];
  readonly events: readonly SecurityEvent[];
}

/** Captures what a specific store did, for the per-visitor DPoP sessions. */
async function tracedOn<T>(
  store: RecordingStore,
  run: () => Promise<T>,
): Promise<{ result: T; trace: Trace }> {
  store.clearLog();
  const result = await run();
  return { result, trace: { storeOps: [...store.log], events: [] } };
}

/** Captures what the store and the audit sink did during one operation. */
async function traced<T>(
  world: World,
  run: () => Promise<T>,
): Promise<{ result: T; trace: Trace }> {
  world.store.clearLog();
  const before = world.audit.events.length;

  const result = await run();

  return {
    result,
    trace: {
      storeOps: [...world.store.log],
      events: world.audit.events.slice(before),
    },
  };
}

/**
 * The playground app.
 *
 * Exported so the tests can drive the real routes over a real socket. The
 * demonstrations make security claims — "the raw token is never in the store",
 * "the replay is refused" — and one that silently stopped demonstrating would
 * be a page telling visitors something untrue.
 */
export const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '64kb' }));
const localPath = (relative: string): string =>
  new URL(relative, import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');

/**
 * Headers a page served from the internet should carry.
 *
 * The CSP is strict because it can be: every script and style the page loads is
 * its own, served from this origin, with no CDN and no inline handlers. A demo
 * that had to relax its own policy to function would be a poor advertisement
 * for a security library.
 */
app.use((_req: Request, res: Response, next: express.NextFunction) => {
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'none'",
      "script-src 'self'",
      "style-src 'self'",
      "connect-src 'self'",
      "img-src 'self' data:",
      "font-src 'self'",
      "base-uri 'none'",
      "form-action 'none'",
      "frame-ancestors 'none'",
    ].join('; '),
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  next();
});

app.use(express.static(localPath('../public')));

/**
 * The browser client, served straight from the package it was built from.
 *
 * Deliberately not copied into `public/`: a vendored copy goes stale silently,
 * and the whole point of this section is that the page runs the same code an
 * application would install.
 */
app.use('/vendor', express.static(localPath('../../../packages/client/dist')));


// ─── What a public URL changes ─────────────────────────────────────────────
// Everything above this point is written for a page on a laptop. Two things
// have to be true before the same page is reachable from the internet, and
// neither is the demonstration's job to explain — they are the deployment's.
//
// The `/api/attestation` routes mint certificates and, for `android-safetynet`
// and the metadata fixtures, generate a 2048-bit RSA key per request. That is
// roughly 100ms of CPU each, unauthenticated. `/api/attack/window-boundary`
// holds a connection for about two and a half seconds by design, waiting for a
// rate-limit window to tick over. Neither is a flaw in the library; both are a
// free CPU sink on a public host.
//
// So the demo limits itself, using the limiter it demonstrates. Nothing here
// is fixture code: it is `@ninsho/server` doing the same job it would do in
// front of a login route.
// ───────────────────────────────────────────────────────────────────────────

/**
 * How much of `X-Forwarded-For` this deployment believes.
 *
 * No default beyond `false`, and the library refuses to guess for the same
 * reason: behind a proxy with `false`, every visitor shares one bucket and any
 * one of them can rate-limit everybody; trusting too many hops lets a visitor
 * mint a fresh bucket per request. Set `PLAYGROUND_TRUST_PROXY` to the number
 * of proxies in front of this process when you deploy it.
 */
const TRUST_PROXY: false | number | 'all' = (() => {
  const raw = process.env['PLAYGROUND_TRUST_PROXY'];
  if (raw === undefined || raw === 'false') return false;
  if (raw === 'all') return 'all';
  const hops = Number.parseInt(raw, 10);
  if (Number.isInteger(hops) && hops >= 0) return hops;
  throw new Error(
    `PLAYGROUND_TRUST_PROXY must be false, a non-negative integer, or 'all' — got ${raw}`,
  );
})();

/**
 * The site's own rate limiter, separate from every visitor's world.
 *
 * Per-address only: there is no account here to key a second dimension on, and
 * saying so is better than inventing an identity to make the shape look
 * symmetrical.
 */
// Replaceable, so a test can forget the counters without the limits being
// softened to accommodate it. The middleware below reads through these, so a
// replacement takes effect on the next request.
let siteStore = new RecordingStore(new MemoryStore());
let siteLimiter = new Ninsho({ store: siteStore, audit: new MemoryAuditSink() });

/** Runs the current limiter, so replacing it mid-process is picked up. */
const throughLimiter = (build: (auth: Ninsho) => Middleware): Middleware => {
  let sourced: Ninsho | undefined;
  let cached: Middleware | undefined;
  return (req, res, next) => {
    if (sourced !== siteLimiter || cached === undefined) {
      sourced = siteLimiter;
      cached = build(siteLimiter);
    }
    cached(req, res, next);
  };
};

const apiLimit = throughLimiter((auth) =>
  auth.rateLimit({
    action: 'playground-api',
    perIp: { limit: 120, windowMs: 60_000 },
    trustProxy: TRUST_PROXY,
    identify: () => undefined,
  }),
);

/**
 * A tighter allowance for the expensive routes.
 *
 * `/api/attestation` generates an RSA key per SafetyNet or metadata run;
 * `/api/attack/window-boundary` deliberately sleeps across a rate-limit
 * boundary. Both are worth demonstrating and neither is worth serving
 * thousands of times a minute to one visitor.
 */
const expensiveLimit = throughLimiter((auth) =>
  auth.rateLimit({
    action: 'playground-expensive',
    perIp: { limit: 20, windowMs: 60_000 },
    trustProxy: TRUST_PROXY,
    identify: () => undefined,
  }),
);

app.use('/api', apiLimit);
app.use('/api/attestation', expensiveLimit);
app.use('/api/attack/window-boundary', expensiveLimit);

/** Wraps an async route so a rejection becomes a response, not a hung request. */
const route =
  (handler: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: express.NextFunction): void => {
    handler(req, res).catch(next);
  };

// ─── Session lifecycle ─────────────────────────────────────────────────────

app.post(
  '/api/session/create',
  route(async (req, res) => {
    const world = await visitor(req, res);
    const { result, trace } = await traced(world, () =>
      world.auth.createSession(DEMO_USER, {
        signals: { userAgent: 'Playground/1.0', ip: '203.0.113.10' },
      }),
    );

    world.latest = { accessToken: result.accessToken, refreshToken: result.refreshToken };

    res.json({
      tokens: {
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        accessExpiresAt: result.accessExpiresAt,
        refreshExpiresAt: result.refreshExpiresAt,
      },
      note:
        'Look at the store operations: the tokens above appear nowhere in them. ' +
        'What is written is SHA-256 of each token, so a database read yields no usable credential.',
      trace,
    });
  }),
);

app.post(
  '/api/session/verify',
  route(async (req, res) => {
    const world = await visitor(req, res);
    const token = (req.body as { token?: string }).token ?? world.latest?.accessToken ?? '';

    try {
      const { result, trace } = await traced(world, () => world.auth.engine.verify(token));
      res.json({ ok: true, context: result, trace });
    } catch (error) {
      res.json({
        ok: false,
        ...describe(error),
        note: 'Verification is one store read — the only operation on every authenticated request.',
      });
    }
  }),
);

app.post(
  '/api/session/refresh',
  route(async (req, res) => {
    const world = await visitor(req, res);
    const current = world.latest?.refreshToken;
    if (current === undefined) {
      res.status(400).json({ ok: false, message: 'Create a session first.' });
      return;
    }

    try {
      const { result, trace } = await traced(world, () => world.auth.refresh(current));
      world.spent.push(current);
      world.latest = { accessToken: result.accessToken, refreshToken: result.refreshToken };

      res.json({
        ok: true,
        tokens: { accessToken: result.accessToken, refreshToken: result.refreshToken },
        note:
          'Rotation begins with an atomic take(). Of any number of callers presenting the same ' +
          'token, exactly one receives the record — no lock, no Lua script, no window where two ' +
          'callers both mint a replacement.',
        trace,
      });
    } catch (error) {
      res.json({ ok: false, ...describe(error) });
    }
  }),
);

// ─── Authorization: who may do what ────────────────────────────────────────
// Authentication answers "who is this". Authorization answers "may they do
// *this*", and it is the half applications usually write by hand at each call
// site — which is why broken object-level authorization has sat at number one
// on the OWASP API Security Top Ten for as long as the list has existed.
//
// Every check below runs a shipped guard behind the shipped `verify()`,
// against a request carrying a token this process really minted. Nothing here
// synthesises a `req.auth`: the identity being checked arrives the way it
// arrives in production — inside a signed token that has to survive
// verification before any guard sees it. A demonstration that invented the
// very thing under test would prove nothing.

/** One authorization decision, with what the client and the log each learned. */
interface AuthzCheck {
  readonly guard: string;
  readonly caller: string;
  readonly carries: string;
  readonly request: string;
  readonly expected: 'allowed' | 'refused';
  readonly allowed: boolean;
  readonly status: number;
  readonly code?: string;
  /** What the caller is told. */
  readonly clientSees?: string;
  /** What the audit trail recorded — deliberately more than the caller learns. */
  readonly auditReason?: string;
}

/** A request as a framework would hand it to the middleware. */
const asRequest = (
  accessToken: string | undefined,
  over: Record<string, unknown> = {},
): Record<string, unknown> => ({
  method: 'GET',
  url: '/',
  headers: accessToken === undefined ? {} : { authorization: `Bearer ${accessToken}` },
  ...over,
});

/** Runs one chain and records both halves of what came out of it. */
async function authzCheck(
  world: World,
  spec: {
    guard: string;
    caller: string;
    carries: string;
    request: string;
    expected: 'allowed' | 'refused';
    chain: readonly Middleware[];
    req: Record<string, unknown>;
  },
): Promise<AuthzCheck> {
  const before = world.audit.events.length;
  const outcome = await runChain(spec.chain, spec.req);

  const reason = world.audit.events
    .slice(before)
    .map((event) => (event as { reason?: string }).reason)
    .find((value): value is string => typeof value === 'string');

  return {
    guard: spec.guard,
    caller: spec.caller,
    carries: spec.carries,
    request: spec.request,
    expected: spec.expected,
    allowed: outcome.allowed,
    status: outcome.status,
    ...(outcome.code !== undefined && { code: outcome.code }),
    ...(outcome.message !== undefined && { clientSees: outcome.message }),
    ...(reason !== undefined && { auditReason: reason }),
  };
}

/**
 * Whether every check landed where the route asked it to.
 *
 * Stated as a claim the page can be wrong about rather than as prose. A guard
 * that stopped guarding would otherwise render as a tidy table of the wrong
 * answers.
 */
function authzVerdict(checks: readonly AuthzCheck[]): { text: string; holds: boolean } {
  const wrong = checks.filter((check) => (check.allowed ? 'allowed' : 'refused') !== check.expected);
  return {
    text:
      wrong.length === 0
        ? `All ${checks.length} decisions landed the way the route asked`
        : `${wrong.length} of ${checks.length} decisions did not match the route — that is a bug`,
    holds: wrong.length === 0,
  };
}

/** Renders a principal the way the table column reads. */
const carriedBy = (principal: Principal): string =>
  [
    `roles: ${principal.roles.length > 0 ? principal.roles.join(', ') : '—'}`,
    `scopes: ${principal.scopes.length > 0 ? principal.scopes.join(', ') : '—'}`,
    ...(principal.tenant !== undefined ? [`tenant: ${principal.tenant}`] : []),
  ].join(' · ');

app.post(
  '/api/authz/roles',
  route(async (req, res) => {
    const world = await visitor(req, res);

    const staff: Principal = { userId: 'usr_alice', roles: ['user'], scopes: ['profile:read'] };
    const root: Principal = {
      userId: 'usr_root',
      roles: ['admin', 'support'],
      scopes: ['profile:read'],
    };

    const checks: AuthzCheck[] = [];
    const { trace } = await traced(world, async () => {
      const staffSession = await world.auth.createSession(staff);
      const rootSession = await world.auth.createSession(root);

      checks.push(
        await authzCheck(world, {
          guard: "verify() + requireRole('admin')",
          caller: root.userId,
          carries: carriedBy(root),
          request: 'GET /admin/users',
          expected: 'allowed',
          chain: [world.auth.verify(), world.auth.requireRole('admin')],
          req: asRequest(rootSession.accessToken),
        }),
        await authzCheck(world, {
          guard: "verify() + requireRole('admin')",
          caller: staff.userId,
          carries: carriedBy(staff),
          request: 'GET /admin/users',
          expected: 'refused',
          chain: [world.auth.verify(), world.auth.requireRole('admin')],
          req: asRequest(staffSession.accessToken),
        }),
        await authzCheck(world, {
          guard: "requireRole(['admin', 'support']) — any of",
          caller: root.userId,
          carries: carriedBy(root),
          request: 'GET /tickets',
          expected: 'allowed',
          chain: [world.auth.verify(), world.auth.requireRole(['admin', 'support'])],
          req: asRequest(rootSession.accessToken),
        }),
        // The distinction the two names exist for. `requireRole` is a union;
        // `requireAllRoles` is an intersection, and reaching for the wrong one
        // is the kind of mistake that reads correctly at the call site.
        await authzCheck(world, {
          guard: "requireAllRoles(['admin', 'security-officer']) — all of",
          caller: root.userId,
          carries: carriedBy(root),
          request: 'POST /admin/keys/rotate',
          expected: 'refused',
          chain: [world.auth.verify(), world.auth.requireAllRoles(['admin', 'security-officer'])],
          req: asRequest(rootSession.accessToken),
        }),
        // Not authorization at all, and shown next to it deliberately: an
        // anonymous request never reaches the guard, and 401 and 403 are
        // different answers to different questions.
        await authzCheck(world, {
          guard: "verify() + requireRole('admin')",
          caller: 'anonymous',
          carries: 'no token',
          request: 'GET /admin/users',
          expected: 'refused',
          chain: [world.auth.verify(), world.auth.requireRole('admin')],
          req: asRequest(undefined),
        }),
      );
    });

    res.json({
      summary: 'Coarse-grained roles, checked by the shipped middleware.',
      note:
        'Two guards, because "any of these roles" and "all of these roles" are different questions ' +
        'and a call site that reaches for the wrong one still reads correctly. Note the last row: ' +
        'a request with no token is refused by verify() with 401 before any guard runs — 401 says ' +
        'the server does not know who you are, 403 says it knows and the answer is still no. An ' +
        'empty role list is refused at construction rather than permitting everyone.',
      claim: authzVerdict(checks),
      checks,
      trace,
    });
  }),
);

app.post(
  '/api/authz/scopes',
  route(async (req, res) => {
    const world = await visitor(req, res);

    const reader: Principal = { userId: 'usr_alice', roles: ['user'], scopes: ['orders:read'] };
    const writer: Principal = {
      userId: 'usr_bob',
      roles: ['user'],
      scopes: ['orders:read', 'orders:write'],
    };
    // Deliberately an administrator with no order scopes at all.
    const root: Principal = { userId: 'usr_root', roles: ['admin'], scopes: [] };

    const checks: AuthzCheck[] = [];
    const { trace } = await traced(world, async () => {
      const readerSession = await world.auth.createSession(reader);
      const writerSession = await world.auth.createSession(writer);
      const rootSession = await world.auth.createSession(root);

      checks.push(
        await authzCheck(world, {
          guard: "requireScope('orders:read')",
          caller: reader.userId,
          carries: carriedBy(reader),
          request: 'GET /orders',
          expected: 'allowed',
          chain: [world.auth.verify(), world.auth.requireScope('orders:read')],
          req: asRequest(readerSession.accessToken),
        }),
        await authzCheck(world, {
          guard: "requireScope('orders:write')",
          caller: reader.userId,
          carries: carriedBy(reader),
          request: 'POST /orders',
          expected: 'refused',
          chain: [world.auth.verify(), world.auth.requireScope('orders:write')],
          req: asRequest(readerSession.accessToken),
        }),
        await authzCheck(world, {
          guard: "requireScope('orders:write')",
          caller: writer.userId,
          carries: carriedBy(writer),
          request: 'POST /orders',
          expected: 'allowed',
          chain: [world.auth.verify(), world.auth.requireScope('orders:write')],
          req: asRequest(writerSession.accessToken),
        }),
        // The row worth pausing on. Roles and scopes are independent axes, and
        // an administrator holding no order scope is refused an order write —
        // which is what "least privilege" means when it is enforced rather
        // than asserted.
        await authzCheck(world, {
          guard: "requireScope('orders:write')",
          caller: root.userId,
          carries: carriedBy(root),
          request: 'POST /orders',
          expected: 'refused',
          chain: [world.auth.verify(), world.auth.requireScope('orders:write')],
          req: asRequest(rootSession.accessToken),
        }),
      );
    });

    res.json({
      summary: 'Fine-grained scopes, on an axis of their own.',
      note:
        'A role is who someone is; a scope is what this credential may do. They do not imply one ' +
        'another, and the fourth row is the reason: an administrator whose token carries no ' +
        'orders:write scope is refused an order write. A scope check that quietly waved through ' +
        'anyone holding an admin role would turn every delegated token into a full one.',
      claim: authzVerdict(checks),
      checks,
      trace,
    });
  }),
);

app.post(
  '/api/authz/ownership',
  route(async (req, res) => {
    const world = await visitor(req, res);

    const alice: Principal = { userId: 'usr_alice', roles: ['user'], scopes: ['orders:read'] };
    const owner = world.auth.requireOwner((r) => (r.params as { id?: string })?.id);

    const checks: AuthzCheck[] = [];
    const { trace } = await traced(world, async () => {
      const session = await world.auth.createSession(alice);
      const token = session.accessToken;

      checks.push(
        await authzCheck(world, {
          guard: 'requireOwner(req => req.params.id)',
          caller: alice.userId,
          carries: carriedBy(alice),
          request: 'GET /accounts/usr_alice/statements',
          expected: 'allowed',
          chain: [world.auth.verify(), owner],
          req: asRequest(token, { params: { id: 'usr_alice' } }),
        }),
        // The attack. Every credential is valid; the request is simply for
        // somebody else's data, and nothing about the token says so.
        await authzCheck(world, {
          guard: 'requireOwner(req => req.params.id)',
          caller: alice.userId,
          carries: carriedBy(alice),
          request: 'GET /accounts/usr_bob/statements',
          expected: 'refused',
          chain: [world.auth.verify(), owner],
          req: asRequest(token, { params: { id: 'usr_bob' } }),
        }),
        // A selector pointing at a parameter the route no longer has. Absent
        // is refused rather than skipped: treating "could not tell" as "allow"
        // would silently disable the check across every route sharing the
        // selector, and it would keep passing its tests.
        await authzCheck(world, {
          guard: 'requireOwner — selector finds nothing',
          caller: alice.userId,
          carries: carriedBy(alice),
          request: 'GET /accounts//statements',
          expected: 'refused',
          chain: [world.auth.verify(), owner],
          req: asRequest(token, { params: {} }),
        }),
        // Express 5 route parameters can be repeatable, so a selector really
        // can return several matched segments. Several segments are not one
        // owner, and picking one would be inventing an answer.
        await authzCheck(world, {
          guard: 'requireOwner — repeatable route parameter',
          caller: alice.userId,
          carries: carriedBy(alice),
          request: 'GET /accounts/usr_alice/usr_bob/statements',
          expected: 'refused',
          chain: [world.auth.verify(), owner],
          req: asRequest(token, { params: { id: ['usr_alice', 'usr_bob'] } }),
        }),
        // A selector that throws is not permission either.
        await authzCheck(world, {
          guard: 'requireOwner — selector throws',
          caller: alice.userId,
          carries: carriedBy(alice),
          request: 'GET /accounts/.../statements',
          expected: 'refused',
          chain: [
            world.auth.verify(),
            world.auth.requireOwner(() => {
              throw new Error('the selector blew up');
            }),
          ],
          req: asRequest(token, { params: { id: 'usr_alice' } }),
        }),
      );
    });

    const refusal = checks.find((check) => check.allowed === false);

    res.json({
      summary: 'Object-level authorization — OWASP API Security #1.',
      note:
        'Every request in this table carries a valid, unexpired, unrevoked token. That is the ' +
        'whole difficulty: authentication cannot answer this, because nothing is wrong with the ' +
        'credential — the request is simply for somebody else’s data. Read the last three ' +
        'rows together: absent, repeated and thrown are all refusals, because the only safe ' +
        'reading of "I could not determine the owner" is "no".',
      secondNote:
        'Compare the two values below. The caller is told "forbidden" and nothing else — naming ' +
        'the owner would confirm the record exists and belongs to someone, which is an ' +
        'enumeration oracle. The audit trail keeps the reason.',
      claim: authzVerdict(checks),
      clientSees: refusal?.clientSees ?? '—',
      auditRecords: refusal?.auditReason ?? '—',
      checks,
      trace,
    });
  }),
);

app.post(
  '/api/authz/tenant',
  route(async (req, res) => {
    const world = await visitor(req, res);

    const acme: Principal = {
      userId: 'usr_alice',
      roles: ['admin'],
      scopes: ['orders:read'],
      tenant: 'acme',
    };
    const globex: Principal = {
      userId: 'usr_carol',
      roles: ['user'],
      scopes: ['orders:read'],
      tenant: 'globex',
    };
    // Issued before the deployment had tenants, or by a path that forgot to
    // set one. Either way it has no business reaching tenant-scoped data.
    const untenanted: Principal = { userId: 'usr_dave', roles: ['admin'], scopes: [] };

    const tenant = world.auth.requireTenant((r) => (r.params as { tenant?: string })?.tenant);

    const checks: AuthzCheck[] = [];
    const { trace } = await traced(world, async () => {
      const acmeSession = await world.auth.createSession(acme);
      const globexSession = await world.auth.createSession(globex);
      const untenantedSession = await world.auth.createSession(untenanted);

      checks.push(
        await authzCheck(world, {
          guard: 'requireTenant(req => req.params.tenant)',
          caller: acme.userId,
          carries: carriedBy(acme),
          request: 'GET /t/acme/orders',
          expected: 'allowed',
          chain: [world.auth.verify(), tenant],
          req: asRequest(acmeSession.accessToken, { params: { tenant: 'acme' } }),
        }),
        // An administrator — of the wrong organisation. The role is real and
        // irrelevant.
        await authzCheck(world, {
          guard: 'requireTenant(req => req.params.tenant)',
          caller: acme.userId,
          carries: carriedBy(acme),
          request: 'GET /t/globex/orders',
          expected: 'refused',
          chain: [world.auth.verify(), tenant],
          req: asRequest(acmeSession.accessToken, { params: { tenant: 'globex' } }),
        }),
        await authzCheck(world, {
          guard: 'requireTenant(req => req.params.tenant)',
          caller: globex.userId,
          carries: carriedBy(globex),
          request: 'GET /t/globex/orders',
          expected: 'allowed',
          chain: [world.auth.verify(), tenant],
          req: asRequest(globexSession.accessToken, { params: { tenant: 'globex' } }),
        }),
        // A token with no tenant claim never passes, on any path.
        await authzCheck(world, {
          guard: 'requireTenant — token carries no tenant',
          caller: untenanted.userId,
          carries: carriedBy(untenanted),
          request: 'GET /t/acme/orders',
          expected: 'refused',
          chain: [world.auth.verify(), tenant],
          req: asRequest(untenantedSession.accessToken, { params: { tenant: 'acme' } }),
        }),
      );
    });

    res.json({
      summary: 'Tenant isolation — a role from the wrong organisation is still the wrong one.',
      note:
        'The second row is the interesting one: usr_alice is a genuine admin, and being an admin ' +
        'of acme grants nothing at globex. The fourth is the fail-closed case — a token with no ' +
        'tenant claim is refused rather than treated as universal, because in a tenanted ' +
        'deployment an absent tenant means the token predates tenanting or was minted by a ' +
        'misconfigured path, and neither should reach tenant-scoped data.',
      claim: authzVerdict(checks),
      checks,
      trace,
    });
  }),
);

app.post(
  '/api/authz/step-up',
  route(async (req, res) => {
    const world = await visitor(req, res);
    const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

    const alice: Principal = { userId: 'usr_alice', roles: ['user'], scopes: ['profile:write'] };

    // A one-second window, and a real wait — the same shape as the rate-limit
    // boundary demonstration. Faking the clock here would demonstrate the fake
    // clock. In an application this number is minutes; the pause you are about
    // to sit through is that compressed into something a page can show.
    const WINDOW_SECONDS = 1;

    const checks: AuthzCheck[] = [];
    const timeline: string[] = [];
    let authenticatedAt = '';
    let issuedAtBefore = '';
    let issuedAtAfter = '';

    const { trace } = await traced(world, async () => {
      const session = await world.auth.createSession(alice);
      const context = await world.auth.engine.verify(session.accessToken);
      authenticatedAt = context.authenticatedAt;
      issuedAtBefore = context.issuedAt;
      timeline.push('signed in — authentication is 0s old');

      checks.push(
        await authzCheck(world, {
          guard: `requireFreshAuth(${WINDOW_SECONDS})`,
          caller: alice.userId,
          carries: carriedBy(alice),
          request: 'POST /account/email — immediately after signing in',
          expected: 'allowed',
          chain: [world.auth.verify(), world.auth.requireFreshAuth(WINDOW_SECONDS)],
          req: asRequest(session.accessToken),
        }),
      );

      await sleep(WINDOW_SECONDS * 1000 + 300);
      timeline.push(
        `waited past the ${WINDOW_SECONDS}s window — the session is still perfectly valid`,
      );

      checks.push(
        await authzCheck(world, {
          guard: `requireFreshAuth(${WINDOW_SECONDS})`,
          caller: alice.userId,
          carries: carriedBy(alice),
          request: 'POST /account/email — after the window',
          expected: 'refused',
          chain: [world.auth.verify(), world.auth.requireFreshAuth(WINDOW_SECONDS)],
          req: asRequest(session.accessToken),
        }),
        // Still allowed on an ordinary route: the session did not end, it just
        // stopped being fresh enough for this one operation.
        await authzCheck(world, {
          guard: "verify() + requireScope('profile:write')",
          caller: alice.userId,
          carries: carriedBy(alice),
          request: 'POST /profile — an ordinary route, same moment',
          expected: 'allowed',
          chain: [world.auth.verify(), world.auth.requireScope('profile:write')],
          req: asRequest(session.accessToken),
        }),
      );

      // ─── The row this whole panel exists for ────────────────────────────
      // Rotating the refresh token mints a brand-new access token with a new
      // `issuedAt`. If the freshness check read the token's age, that would
      // silently satisfy it — and a stolen refresh token would buy an attacker
      // a step-up they never passed. It reads `authenticatedAt`, which a
      // refresh does not move.
      const rotated = await world.auth.refresh(session.refreshToken);
      const after = await world.auth.engine.verify(rotated.accessToken);
      issuedAtAfter = after.issuedAt;
      timeline.push('refreshed — a brand-new access token, minted this second');

      checks.push(
        await authzCheck(world, {
          guard: `requireFreshAuth(${WINDOW_SECONDS}) — with the freshly minted token`,
          caller: alice.userId,
          carries: carriedBy(alice),
          request: 'POST /account/email — after refreshing',
          expected: 'refused',
          chain: [world.auth.verify(), world.auth.requireFreshAuth(WINDOW_SECONDS)],
          req: asRequest(rotated.accessToken),
        }),
      );
    });

    res.json({
      summary: 'Step-up — being signed in is not always enough.',
      note:
        'Some operations should need more than a live session: changing an email address, adding ' +
        'a passkey, moving money. requireFreshAuth reads when the user *authenticated*, not when ' +
        'the token was issued — and the last row is why that distinction is the whole mechanism. ' +
        'Refreshing mints a token issued this second, and the check still refuses, because ' +
        'rotating a credential is not re-proving who you are. Only signing in again is.',
      secondNote:
        'The third row matters just as much: the session was not ended, and ordinary routes keep ' +
        'working. A step-up failure that signed the user out would be a denial of service wearing ' +
        'a security feature’s clothes.',
      claim: authzVerdict(checks),
      windowSeconds: WINDOW_SECONDS,
      authenticatedAt,
      issuedAtBeforeRefresh: issuedAtBefore,
      issuedAtAfterRefresh: issuedAtAfter,
      timeline,
      checks,
      trace,
    });
  }),
);

// ─── Sessions, devices, and ending them ────────────────────────────────────
// The feature every account settings page has — "you are signed in on three
// devices, sign the others out" — and the one a stateless token cannot
// actually provide. A self-contained JWT is valid until it expires because
// nothing is consulted when it is presented; the honest versions of this
// feature keep a denylist, and the dishonest ones shorten the expiry and hope.
//
// Ninsho consults the store on every request. That is the one read the README
// admits to, and this is what it buys.

/** The devices a demonstration signs in from. */
const DEVICES = [
  { label: 'laptop', userAgent: 'Ninsho/1.0 (laptop)', ip: '203.0.113.10' },
  { label: 'phone', userAgent: 'Ninsho/1.0 (phone)', ip: '198.51.100.22' },
  { label: 'tablet', userAgent: 'Ninsho/1.0 (tablet)', ip: '192.0.2.44' },
] as const;

const DEVICE_USER: Principal = {
  userId: 'usr_alice',
  roles: ['user'],
  scopes: ['orders:read'],
};

/** Signs in from each device and hands back the pairs, in order. */
async function signInEverywhere(world: World): Promise<TokenPair[]> {
  const pairs: TokenPair[] = [];
  for (const device of DEVICES) {
    pairs.push(
      await world.auth.createSession(DEVICE_USER, {
        signals: { userAgent: device.userAgent, ip: device.ip },
      }),
    );
  }
  return pairs;
}

/**
 * Presents each device's access token and reports what the server decided.
 *
 * Written as the same row shape the authorization panel uses, because it is
 * the same question asked at a different moment: this is `verify()` on an
 * ordinary request, which is exactly where a revoked session has to die.
 */
async function presentEach(
  world: World,
  pairs: readonly TokenPair[],
  expected: readonly ('allowed' | 'refused')[],
  when: string,
): Promise<AuthzCheck[]> {
  const rows: AuthzCheck[] = [];
  for (const [index, pair] of pairs.entries()) {
    rows.push(
      await authzCheck(world, {
        guard: 'verify()',
        caller: DEVICE_USER.userId,
        carries: `${DEVICES[index]?.label ?? 'device'} · session ${pair.sessionId}`,
        request: `GET /orders — from the ${DEVICES[index]?.label ?? 'device'}, ${when}`,
        expected: expected[index] ?? 'allowed',
        chain: [world.auth.verify()],
        req: asRequest(pair.accessToken),
      }),
    );
  }
  return rows;
}

app.post(
  '/api/sessions/list',
  route(async (req, res) => {
    const world = await visitor(req, res);

    let sessions: SessionSummary[] = [];
    const { trace } = await traced(world, async () => {
      const pairs = await signInEverywhere(world);
      // The second device is "this" one, the way an account page marks the
      // session doing the asking so a visitor does not sign themselves out.
      sessions = await world.auth.listSessions(DEVICE_USER.userId, pairs[1]?.sessionId);
    });

    res.json({
      summary: 'Three devices, one account — what an account settings page can show.',
      note:
        'Look at what a summary contains, and more importantly what it does not: no token, no ' +
        'hash a token could be recognised from, no user agent string and no IP address. The ' +
        'signals are truncated hashes, which is enough to group sessions or highlight the odd one ' +
        'out and not enough to render "Chrome on macOS" — if you want that shown to a user, keep ' +
        'your own record of it. A session list is a page users are encouraged to visit when they ' +
        'are worried, and it should not be the place a stolen database learns where they live.',
      sessions,
      trace,
    });
  }),
);

app.post(
  '/api/sessions/revoke-one',
  route(async (req, res) => {
    const world = await visitor(req, res);

    const checks: AuthzCheck[] = [];
    let revokedSession = '';
    let revokedTokenExpiresAt = '';

    const { trace } = await traced(world, async () => {
      const pairs = await signInEverywhere(world);
      revokedSession = pairs[1]?.sessionId ?? '';
      revokedTokenExpiresAt = pairs[1]?.accessExpiresAt ?? '';

      checks.push(...(await presentEach(world, pairs, ['allowed', 'allowed', 'allowed'], 'before')));

      // "Sign out this device." One session ends; the others are untouched.
      await world.auth.revokeSession(revokedSession, 'logout');

      checks.push(...(await presentEach(world, pairs, ['allowed', 'refused', 'allowed'], 'after')));
    });

    res.json({
      summary: 'Signing one device out, and only that one.',
      note:
        'The refused token in the second half has not expired — its expiry is below, and it is in ' +
        'the future. It is still perfectly well-formed and its signature still verifies. It is ' +
        'refused because the session it belongs to is gone, and the server looks. That lookup is ' +
        'the one store read on every authenticated request, and this is the entire reason it is ' +
        'there: a token nothing consults is valid until it expires, whatever the account settings ' +
        'page claims.',
      secondNote:
        'The other two devices keep working, which is the half that is easy to get wrong in the ' +
        'other direction. Revocation that reaches further than asked is its own outage.',
      claim: authzVerdict(checks),
      revokedSession,
      revokedTokenExpiresAt,
      checkedAt: new Date().toISOString(),
      checks,
      trace,
    });
  }),
);

app.post(
  '/api/sessions/revoke-all',
  route(async (req, res) => {
    const world = await visitor(req, res);

    const checks: AuthzCheck[] = [];
    let refreshRejected = '';

    const { trace } = await traced(world, async () => {
      const pairs = await signInEverywhere(world);
      checks.push(...(await presentEach(world, pairs, ['allowed', 'allowed', 'allowed'], 'before')));

      // The operation a password change must perform. `credential_changed`
      // rather than `logout_all` because an incident review looks for it
      // specifically: whoever forced the reset may already hold a session, and
      // a password change that left those alive accomplished nothing.
      await world.auth.revokeAllForUser(DEVICE_USER.userId, 'credential_changed');

      checks.push(...(await presentEach(world, pairs, ['refused', 'refused', 'refused'], 'after')));

      // The refresh token has to die with it. A revocation that ended the
      // access tokens and left the families alive would sign everyone back in
      // within the access token's lifetime — minutes, silently.
      const outcome = await world.auth
        .refresh(pairs[0]?.refreshToken ?? '')
        .then(() => 'accepted — that is a bug')
        .catch((error: unknown) => describe(error).code);
      refreshRejected = outcome;
    });

    res.json({
      summary: 'Changing a password ends every session, on every device.',
      note:
        'The reason recorded is credential_changed rather than a generic sign-out, because an ' +
        'incident review looks for exactly that: whoever forced the reset may already be holding ' +
        'a session, and a password change that left those alive accomplished nothing at all.',
      secondNote:
        'The line below is the half that is easy to forget. Ending the access tokens is not ' +
        'enough — if the refresh families survived, every device would quietly sign itself back ' +
        'in within minutes, and the user would be told they were signed out while they were not.',
      claim: authzVerdict(checks),
      refreshAfterRevocation: refreshRejected,
      checks,
      trace,
    });
  }),
);

// ─── Attacks ───────────────────────────────────────────────────────────────

app.post(
  '/api/attack/replay-refresh',
  route(async (req, res) => {
    const world = await visitor(req, res);
    const stolen = world.spent[world.spent.length - 1];
    if (stolen === undefined) {
      res.status(400).json({
        ok: false,
        message: 'Refresh at least once first, so there is a rotated token to replay.',
      });
      return;
    }

    // The thief presents the already-rotated token from a different client.
    const { result, trace } = await traced(world, async () => {
      try {
        await world.auth.refresh(stolen, {
          signals: { userAgent: 'curl/8.4.0', ip: '198.51.100.7' },
        });
        return { rejected: false as const };
      } catch (error) {
        return { rejected: true as const, ...describe(error) };
      }
    });

    // The family is gone, so the legitimate user's live token is dead too.
    let liveTokenStillWorks = true;
    try {
      await world.auth.engine.verify(world.latest?.accessToken ?? '');
    } catch {
      liveTokenStillWorks = false;
    }

    res.json({
      ...result,
      liveTokenStillWorks,
      note:
        'RFC 9700 §4.14.2. A rotated token presented again is the strongest signal of theft an ' +
        'auth system can observe, and one of the two holders is an attacker with no way to tell ' +
        'which — so the session ends for both. Note signalMatch on the event: the replay came ' +
        'from a different client, which is close to certain theft rather than a retry.',
      trace,
    });
  }),
);

app.post(
  '/api/attack/tamper-token',
  route(async (req, res) => {
    const world = await visitor(req, res);
    const original = world.latest?.accessToken;
    if (original === undefined) {
      res.status(400).json({ ok: false, message: 'Create a session first.' });
      return;
    }

    // Flip one character. An opaque token is a lookup key, so a mutation
    // simply finds nothing — there is no signature to forge because there is
    // no signature at all.
    const flipped = `${original.slice(0, -1)}${original.endsWith('A') ? 'B' : 'A'}`;

    const { result, trace } = await traced(world, async () => {
      try {
        await world.auth.engine.verify(flipped);
        return { rejected: false as const };
      } catch (error) {
        return { rejected: true as const, ...describe(error) };
      }
    });

    res.json({
      ...result,
      original,
      tampered: flipped,
      note:
        'The store is keyed by SHA-256 of the token, so a single changed character lands on a ' +
        'different key and finds nothing. The rejection says only "invalid" — never whether the ' +
        'token was expired, revoked, or never existed, because those three answers are three ' +
        'hints to someone probing.',
      trace,
    });
  }),
);

app.post(
  '/api/attack/replay-reset-link',
  route(async (req, res) => {
    const world = await visitor(req, res);
    const { result, trace } = await traced(world, async () => {
      const issued = await world.auth.oneTimeTokens.issue({
        purpose: 'password-reset',
        subject: DEMO_USER.userId,
      });
      world.resetToken = issued.token;

      const first = await world.auth.oneTimeTokens
        .consume('password-reset', issued.token)
        .then(() => 'accepted' as const, (e: unknown) => describe(e).code);
      const second = await world.auth.oneTimeTokens
        .consume('password-reset', issued.token)
        .then(() => 'accepted' as const, (e: unknown) => describe(e).code);

      return { token: issued.token, first, second };
    });

    res.json({
      ...result,
      note:
        'Consumption goes through the store’s atomic take(), so a forwarded reset email — or a ' +
        'corporate mail scanner that pre-fetches the link — cannot be redeemed twice. The record ' +
        'is keyed by the hash, so the store never held the link you would click.',
      trace,
    });
  }),
);

app.post(
  '/api/attack/race-reset-links',
  route(async (req, res) => {
    const world = await visitor(req, res);
    const { result, trace } = await traced(world, async () => {
      // Two reset requests racing. Both used to survive; an atomic generation
      // counter now supersedes the older one.
      const [a, b] = await Promise.all([
        world.auth.oneTimeTokens.issue({ purpose: 'password-reset', subject: 'usr_race' }),
        world.auth.oneTimeTokens.issue({ purpose: 'password-reset', subject: 'usr_race' }),
      ]);

      const outcomes = await Promise.all(
        [a, b].map((one, index) =>
          world.auth.oneTimeTokens
            .consume('password-reset', one.token)
            .then(() => `link ${index + 1}: accepted`, () => `link ${index + 1}: refused`),
        ),
      );

      return { outcomes, survivors: outcomes.filter((o) => o.endsWith('accepted')).length };
    });

    res.json({
      ...result,
      note:
        'Requesting a second reset email must invalidate the first. An index of outstanding ' +
        'tokens could not guarantee that under concurrency — both reads happened before either ' +
        'write, and 80 of 80 raced tokens survived. An atomic increment fixes it: the two issues ' +
        'get distinct generations and the older link stops matching.',
      trace,
    });
  }),
);

// ─── Live DPoP, with the key in the visitor's own browser ──────────────────
// The one demonstration that cannot be faked from the server side: the private
// key is generated in the page, marked non-extractable, and never leaves. What
// arrives here is a signature, verified by the shipped verifier.

app.post(
  '/api/dpop/bind',
  route(async (req, res) => {
    const world = await visitor(req, res);
    const { thumbprint } = req.body as { thumbprint?: unknown };
    if (typeof thumbprint !== 'string' || thumbprint.length === 0) {
      res.status(400).json({ ok: false, message: 'thumbprint is required' });
      return;
    }

    // One deployment per visitor, so two people on the page cannot see each
    // other's session — and so the store trace shown is theirs alone.
    const previous = world.bound.get(thumbprint);
    if (previous) await previous.store.close();

    const store = new RecordingStore(new MemoryStore());
    const auth = new Ninsho({ store, binding: 'dpop' });

    const { result, trace } = await tracedOn(store, () =>
      auth.createSession(DEMO_USER, { confirmationKey: thumbprint }),
    );

    world.bound.set(thumbprint, { auth, store, accessToken: result.accessToken });
    if (world.bound.size > 50) {
      // Bounded, since anyone can open the page.
      const oldest = world.bound.keys().next().value;
      if (oldest !== undefined && oldest !== thumbprint) {
        await world.bound.get(oldest)?.store.close();
        world.bound.delete(oldest);
      }
    }

    res.json({
      ok: true,
      accessToken: result.accessToken,
      thumbprint,
      note:
        'The token now carries a cnf.jkt claim — the thumbprint of the key sitting in your ' +
        'browser. It is no longer a bearer credential: presenting it requires a signature from a ' +
        'private key that cannot leave the page it was created in.',
      trace,
    });
  }),
);

app.post(
  '/api/dpop/call',
  route(async (req, res) => {
    const world = await visitor(req, res);
    const { thumbprint, proof, omitProof } = req.body as {
      thumbprint?: unknown;
      proof?: unknown;
      omitProof?: unknown;
    };

    if (typeof thumbprint !== 'string') {
      res.status(400).json({ ok: false, message: 'thumbprint is required' });
      return;
    }
    const session = world.bound.get(thumbprint);
    if (session === undefined) {
      res.status(400).json({ ok: false, message: 'Bind a key first.' });
      return;
    }

    // Shaped like the request the middleware would receive. Omitting the proof
    // is the interesting case: it is what a thief holding only the token has.
    // Every field the middleware reads, because a proof is bound to the method
    // and the URI as well as the key. Leaving `method` off makes the middleware
    // read GET, and the proof — minted for POST — is refused on `htm`. That is
    // the binding working; it is also a misleading demonstration, so the shape
    // here matches what Express would actually hand it.
    const request = {
      method: 'POST',
      headers: {
        authorization: `DPoP ${session.accessToken}`,
        ...(omitProof === true ? {} : { dpop: String(proof ?? '') }),
        host: new URL(PUBLIC_ORIGIN).host,
      },
      protocol: new URL(PUBLIC_ORIGIN).protocol.replace(':', ''),
      originalUrl: '/api/dpop/call',
    };

    const { result, trace } = await tracedOn(session.store, async () => {
      try {
        const confirmationKey = await session.auth.confirmProofOfPossession(
          request as never,
          session.accessToken,
        );
        const context = await session.auth.engine.verify(session.accessToken, {
          confirmationKey,
        });
        return { accepted: true as const, context };
      } catch (error) {
        return { accepted: false as const, ...describe(error) };
      }
    });

    res.json({
      ...result,
      note:
        omitProof === true
          ? 'This is exactly what an attacker who stole the token has: the token, and no key. ' +
            'The request is refused, which is the whole point of proof-of-possession.'
          : 'The signature was produced in your browser by a key this server has never seen and ' +
            'cannot obtain. Send the same proof again and the replay guard refuses it.',
      trace,
    });
  }),
);

// ─── Anatomy: real bytes, annotated ────────────────────────────────────────
// Each of these generates a genuine artefact with the shipped code, then
// annotates it. Nothing here is a hand-written sample — a decoder shown bytes
// the library never produced would teach the wrong thing.

app.post(
  '/api/anatomy/webauthn',
  route(async (_req, res) => {
    const device = await VirtualAuthenticator.create();
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);

    // A real ceremony: real key pair, real signature over real client data.
    const registration = await device.register({
      challenge,
      origin: 'https://example.com',
      rpId: 'example.com',
    });

    const attestation = decodeAttestationObject(registration.attestationObject);
    const inner = decodeCbor(registration.attestationObject) as Map<string, unknown>;
    const authData = inner.get('authData') as Uint8Array;

    const assertion = await device.authenticate({
      challenge,
      origin: 'https://example.com',
      rpId: 'example.com',
    });

    res.json({
      summary: 'A complete passkey registration, signed by a real key pair.',
      note:
        'The virtual authenticator holds an actual P-256 key and signs actual data — the same ' +
        'one the test suite uses. Everything below was parsed by the shipped parsers, so what ' +
        'you are reading is what the verifier saw.',
      clientDataJSON: new TextDecoder().decode(registration.clientDataJSON),
      decodes: [
        { title: 'attestationObject (CBOR wrapper)', ...attestation },
        { title: 'authenticatorData — registration', ...decodeAuthenticatorData(authData) },
        {
          title: 'authenticatorData — a later assertion',
          ...decodeAuthenticatorData(assertion.authenticatorData),
        },
      ],
    });
  }),
);

app.post(
  '/api/anatomy/paseto',
  route(async (_req, res) => {
    // A separate deployment, because the strategy is fixed at construction —
    // which is itself the point: there is no request-time algorithm to choose.
    const keys = generateKeyPair('demo-key-1');
    const store = new RecordingStore(new MemoryStore());
    const stateless = new Ninsho({
      store,
      strategy: 'paseto',
      issuer: 'https://playground.ninsho.dev',
      audience: 'playground-api',
      keys: { active: keys },
    });

    const pair = await stateless.createSession(DEMO_USER);
    const context = await stateless.engine.verify(pair.accessToken);
    await store.close();

    res.json({
      summary: 'A PASETO v4.public access token.',
      note:
        'Note what is missing: there is no `alg` header. The version and purpose are part of the ' +
        'token string, and `v4.public` means Ed25519 and nothing else — so the whole ' +
        'algorithm-confusion family, including `alg: none`, has nothing to attack.',
      token: pair.accessToken,
      verified: context,
      decodes: [{ title: 'PASETO v4.public', ...decodePaseto(pair.accessToken) }],
    });
  }),
);

app.post(
  '/api/anatomy/dpop',
  route(async (_req, res) => {
    const keyPair = generateDpopKeyPair('ES256');
    const thumbprint = jwkThumbprint(keyPair.publicJwk);

    const store = new RecordingStore(new MemoryStore());
    const bound = new Ninsho({ store, binding: 'dpop' });
    const pair = await bound.createSession(DEMO_USER, { confirmationKey: thumbprint });

    const proof = createDpopProof(keyPair, {
      method: 'GET',
      url: 'https://api.example.com/me',
      accessToken: pair.accessToken,
    });

    // Presented twice through the public surface, so the replay guard is seen
    // refusing the second exactly as it would on a real request.
    const present = async (): Promise<string> => {
      // Shaped like the Express request the middleware would see, so the URI
      // it reconstructs matches the one the proof was signed for. Getting this
      // wrong is itself instructive: an `htu` mismatch is a refusal, which is
      // the binding doing its job.
      const request = {
        headers: {
          authorization: `DPoP ${pair.accessToken}`,
          dpop: proof,
          host: 'api.example.com',
        },
        protocol: 'https',
        originalUrl: '/me',
      };
      try {
        await bound.confirmProofOfPossession(request as never, pair.accessToken);
        return 'accepted';
      } catch (error) {
        return `refused — ${describe(error).detail ?? describe(error).code}`;
      }
    };

    const first = await present();
    const second = await present();
    await store.close();

    res.json({
      summary: 'A DPoP proof, and the same proof replayed.',
      note:
        'The access token carries a `cnf.jkt` — the thumbprint of this key. Presenting the token ' +
        'without a matching proof is refused, so a stolen token alone is useless. The proof ' +
        'itself is single-use: the second claim on the same `jti` loses.',
      thumbprint,
      accessToken: pair.accessToken,
      firstUse: first,
      replay: second,
      decodes: [{ title: 'DPoP proof', ...decodeDpopProof(proof) }],
    });
  }),
);

// ─── Inspection ────────────────────────────────────────────────────────────



// ─── Rate limiting: two dimensions, and why one is not enough ──────────────
// Each of these runs the real middleware against synthesised requests, so what
// the page reports is the limiter's own verdict rather than this file's.

/** What a middleware chain decided about one request. */
interface ChainOutcome {
  readonly allowed: boolean;
  readonly status: number;
  readonly code?: string;
  /** The message the client is given — deliberately less than the server knows. */
  readonly message?: string;
}

/**
 * Drives one request through a chain of real middleware, as a route would.
 *
 * The chain matters rather than the individual middleware: an authorization
 * guard reads `req.auth`, which only exists because `verify()` ran first and
 * put it there. Running the guard alone would mean synthesising an identity —
 * and a demonstration that invents the very thing being checked proves
 * nothing. So the same request object is threaded through every middleware in
 * order, exactly as Express threads it, and the first one that declines to
 * call `next()` ends it.
 */
async function runChain(
  chain: readonly Middleware[],
  req: Record<string, unknown>,
): Promise<ChainOutcome> {
  let status = 200;
  let code: string | undefined;
  let message: string | undefined;

  for (const middleware of chain) {
    let advanced = false;

    const res = {
      status(value: number) {
        status = value;
        return res;
      },
      json(body: unknown) {
        const error = (body as { error?: { code?: string; message?: string } })?.error;
        code = error?.code;
        message = error?.message;
        return body;
      },
      setHeader() {
        return res;
      },
    };

    await new Promise<void>((resolve) => {
      let settled = false;
      const finish = (): void => {
        if (!settled) {
          settled = true;
          resolve();
        }
      };
      const originalJson = res.json.bind(res);
      res.json = (body: unknown) => {
        const out = originalJson(body);
        finish();
        return out;
      };
      void Promise.resolve(
        middleware(req as never, res as never, () => {
          advanced = true;
          finish();
        }),
      ).catch(finish);
    });

    if (!advanced) {
      return {
        allowed: false,
        status,
        ...(code !== undefined && { code }),
        ...(message !== undefined && { message }),
      };
    }
  }

  return { allowed: true, status: 200 };
}

/** Drives one request through a single middleware and reports what it decided. */
async function callMiddleware(
  middleware: Middleware,
  req: Record<string, unknown>,
): Promise<ChainOutcome> {
  return runChain([middleware], req);
}

/** A login attempt from one address for one account. */
const loginAttempt = (ip: string, email: string, forwarded?: string) => ({
  headers: forwarded === undefined ? {} : { 'x-forwarded-for': forwarded },
  socket: { remoteAddress: ip },
  body: { email },
});

app.post(
  '/api/attack/credential-stuffing',
  route(async (req, res) => {
    const world = await visitor(req, res);

    // Deliberately generous per-IP, tight per-account: the shape a botnet is
    // built to slip through.
    const limiter = world.auth.rateLimit({
      action: 'stuffing-demo',
      perIp: { limit: 100, windowMs: 60_000 },
      perAccount: { limit: 5, windowMs: 60_000 },
      identify: (r) => (r.body as { email?: string })?.email,
      trustProxy: false,
    });

    const attempts: { ip: string; allowed: boolean; code?: string }[] = [];
    const { trace } = await traced(world, async () => {
      for (let i = 0; i < 12; i += 1) {
        // A different address every time — no per-IP bucket gets near 100.
        const ip = `203.0.113.${i + 1}`;
        const outcome = await callMiddleware(limiter, loginAttempt(ip, 'victim@example.com'));
        attempts.push({ ip, allowed: outcome.allowed, ...(outcome.code && { code: outcome.code }) });
      }
    });

    const blocked = attempts.filter((a) => !a.allowed).length;

    res.json({
      summary: 'One account, twelve addresses, five allowed.',
      note:
        'A per-IP limit alone does not stop credential stuffing: the attacker spreads attempts so ' +
        'no single address approaches it. Every request here comes from a different address and ' +
        'none exceeds the per-IP allowance of 100 — what stops the twelfth is the per-account ' +
        'bucket, which is the half the predecessor lacked.',
      rejected: blocked > 0,
      distinctAddresses: attempts.length,
      perIpLimit: 100,
      perAccountLimit: 5,
      allowedAttempts: attempts.length - blocked,
      blockedAttempts: blocked,
      attempts,
      trace,
    });
  }),
);

app.post(
  '/api/attack/nat-bystander',
  route(async (req, res) => {
    const world = await visitor(req, res);

    const limiter = world.auth.rateLimit({
      action: 'nat-demo',
      perIp: { limit: 50, windowMs: 60_000 },
      perAccount: { limit: 3, windowMs: 60_000 },
      identify: (r) => (r.body as { email?: string })?.email,
      trustProxy: false,
    });

    const office = '198.51.100.7';
    const outcomes: string[] = [];

    const { trace } = await traced(world, async () => {
      // One colleague forgets their password repeatedly.
      for (let i = 0; i < 5; i += 1) {
        const outcome = await callMiddleware(limiter, loginAttempt(office, 'forgetful@example.com'));
        outcomes.push(`forgetful@example.com attempt ${i + 1}: ${outcome.allowed ? 'allowed' : 'refused'}`);
      }
      // Someone else on the same NAT signs in for the first time.
      const bystander = await callMiddleware(limiter, loginAttempt(office, 'bystander@example.com'));
      outcomes.push(
        `bystander@example.com first attempt: ${bystander.allowed ? 'allowed' : 'refused — that would be a bug'}`,
      );
    });

    const bystanderAllowed = outcomes[outcomes.length - 1]?.includes('allowed') === true;

    res.json({
      summary: 'One office address, two people, only one of them locked out.',
      note:
        'The reverse of credential stuffing, and the reason the two buckets are separate rather ' +
        'than combined. A per-IP limit alone punishes shared NAT: an office or a carrier trips a ' +
        'limit no individual caused, and everyone behind it is signed out by a colleague’s bad ' +
        'memory.',
      // Not an attack, so `rejected` would be the wrong word for it: the
      // claim is that a bystander keeps working, and the panel says whether
      // that held.
      claim: {
        text: bystanderAllowed
          ? 'The colleague was limited; the bystander signed in normally'
          : 'The bystander was locked out by someone else\u2019s failures — that is a bug',
        holds: bystanderAllowed,
      },
      sharedAddress: office,
      outcomes,
      trace,
    });
  }),
);

app.post(
  '/api/attack/forged-forwarded-for',
  route(async (req, res) => {
    const world = await visitor(req, res);

    // One proxy hop, which is the deployment this setting describes.
    const limiter = world.auth.rateLimit({
      action: 'xff-demo',
      perIp: { limit: 3, windowMs: 60_000 },
      trustProxy: 1,
      identify: () => undefined,
    });

    const proxy = '198.51.100.1';
    const attacker = '203.0.113.99';
    const attempts: { forwarded: string; allowed: boolean }[] = [];

    const { trace } = await traced(world, async () => {
      for (let i = 0; i < 5; i += 1) {
        // Each attempt prepends more invented hops, trying to make the
        // resolved address look new and win a fresh bucket.
        const forged = Array.from({ length: i }, (_, n) => `10.0.0.${n + 1}`);
        const forwarded = [...forged, attacker].join(', ');
        const outcome = await callMiddleware(
          limiter,
          loginAttempt(proxy, 'anyone@example.com', forwarded),
        );
        attempts.push({ forwarded, allowed: outcome.allowed });
      }
    });

    const blocked = attempts.filter((a) => !a.allowed).length;

    res.json({
      summary: 'Five attempts, five different X-Forwarded-For chains, one bucket.',
      note:
        'The address is counted from the trusted end of the chain inwards, by hop count — never ' +
        'by taking the leftmost entry. Anything the client prepends sits beyond the hop it is ' +
        'entitled to, so inventing hops cannot mint a fresh bucket. `trustProxy` has no default ' +
        'and must be stated, because guessing it wrong in either direction is a security bug: too ' +
        'high trusts a forged header, too low rate-limits your own load balancer.',
      rejected: blocked > 0,
      trustProxy: 1,
      perIpLimit: 3,
      resolvedTo: attacker,
      blockedAttempts: blocked,
      attempts,
      trace,
    });
  }),
);

app.post(
  '/api/attack/window-boundary',
  route(async (req, res) => {
    const world = await visitor(req, res);

    const windowMs = 2_000;
    const limit = 4;

    const limiter = world.auth.rateLimit({
      action: `boundary-demo-${Date.now()}`,
      perIp: { limit, windowMs },
      trustProxy: false,
      identify: () => undefined,
    });

    const ip = '203.0.113.50';
    const timeline: string[] = [];
    let allowedTotal = 0;
    const sleep = (ms: number): Promise<void> =>
      new Promise((resolve) => setTimeout(resolve, ms));

    // ─── Why this waits for the boundary rather than sleeping past one ──────
    // Windows are aligned to absolute time, so the *only* moment a fixed-window
    // counter can be robbed is the tick itself: spend the allowance in the last
    // moments of one window, then again in the first moments of the next.
    //
    // Sleeping a whole window between bursts would demonstrate nothing — after
    // a full window the earlier requests have legitimately aged out, and
    // allowing four more is correct behaviour rather than a flaw. Getting that
    // wrong is what made an earlier version of this panel intermittently report
    // that the attack had succeeded.
    const msToBoundary = windowMs - (Date.now() % windowMs);
    await sleep(Math.max(0, msToBoundary - 400));

    const { trace } = await traced(world, async () => {
      for (let i = 0; i < limit; i += 1) {
        const outcome = await callMiddleware(limiter, loginAttempt(ip, 'anyone@example.com'));
        if (outcome.allowed) allowedTotal += 1;
        timeline.push(
          `just before the boundary, request ${i + 1}: ${outcome.allowed ? 'allowed' : 'refused'}`,
        );
      }

      // Over the tick, and straight back at it.
      await sleep(500);

      for (let i = 0; i < limit; i += 1) {
        const outcome = await callMiddleware(limiter, loginAttempt(ip, 'anyone@example.com'));
        if (outcome.allowed) allowedTotal += 1;
        timeline.push(
          `just after the boundary, request ${i + 1}: ${outcome.allowed ? 'allowed' : 'refused'}`,
        );
      }
    });

    res.json({
      summary: `${allowedTotal} of ${limit * 2} requests allowed across a window boundary.`,
      note:
        'A fixed-window counter resets to zero on the tick, so an attacker who spends the ' +
        'allowance in the last moments of one window and again in the first moments of the next ' +
        'gets twice the limit in a couple of seconds. This is a sliding window: the previous ' +
        'window still weighs on the decision, in proportion to how much of it remains in view — ' +
        'so immediately after a boundary it counts for almost everything.',
      rejected: allowedTotal < limit * 2,
      perIpLimit: limit,
      windowMs,
      requestsSent: limit * 2,
      allowedTotal,
      timeline,
      trace,
    });
  }),
);

// ─── Attestation: what the hardware proves, and what it does not ───────────
// Every format below runs a genuine ceremony through the shipped verifier.
// The certificates are generated here rather than shipped, which is the honest
// arrangement for a demo — and it is also the reason the "no roots" scenario
// matters: a chain checked against a root the same process invented proves
// exactly nothing, and the verifier says so instead of reporting success.

/** Formats the page offers, with what each one actually is. */
const ATTESTATION_FORMATS: Record<
  string,
  { label: string; hardware: string; verified: boolean }
> = {
  none: {
    label: 'none',
    hardware: 'Nothing. The browser substitutes this whenever the relying party asks for `none`.',
    verified: true,
  },
  packed: {
    label: 'packed',
    hardware: 'Most security keys, the YubiKey line included.',
    verified: true,
  },
  apple: {
    label: 'apple',
    hardware: 'Touch ID and Face ID.',
    verified: true,
  },
  tpm: {
    label: 'tpm',
    hardware: 'Windows Hello, through the machine’s TPM.',
    verified: true,
  },
  'fido-u2f': {
    label: 'fido-u2f',
    hardware: 'CTAP1 security keys — the generation before CTAP2.',
    verified: true,
  },
  'android-key': {
    label: 'android-key',
    hardware: 'Android platform authenticators.',
    verified: true,
  },
  'android-safetynet': {
    label: 'android-safetynet',
    hardware:
      'Older Android devices. Google vouches for the phone rather than for the key, and has ' +
      'deprecated the API behind it.',
    verified: true,
  },
  appattest: {
    label: 'appattest',
    hardware: 'Nothing here — Apple’s App Attest is a real format, and not one WebAuthn defines.',
    verified: false,
  },
};

/** What each scenario does to an otherwise genuine ceremony. */
const ATTESTATION_SCENARIOS: Record<string, string> = {
  genuine: 'A real ceremony, verified against the root that issued the chain.',
  'no-anchors': 'The same ceremony, with no trust anchors configured.',
  'wrong-root': 'The same ceremony, checked against a root that did not issue it.',
  tampered: 'The same ceremony with one byte of the attestation signature flipped.',
};

app.post(
  '/api/attestation',
  route(async (req, res) => {
    const body = (req.body ?? {}) as { format?: unknown; scenario?: unknown };
    const format = typeof body.format === 'string' ? body.format : 'packed';
    const scenario = typeof body.scenario === 'string' ? body.scenario : 'genuine';

    const meta = ATTESTATION_FORMATS[format];
    if (meta === undefined || ATTESTATION_SCENARIOS[scenario] === undefined) {
      res.status(400).json({ error: 'unknown format or scenario' });
      return;
    }

    const device = await VirtualAuthenticator.create();
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);

    const rpId = 'example.com';
    const origin = 'https://example.com';
    const tampered = scenario === 'tampered';

    // The root that really issues the chain, and one that does not. Both are
    // minted here; which is why the "no anchors" answer is the interesting one.
    const root = createCertificate({ subject: `${meta.label} Vendor Root`, isCa: true });
    const decoy = createCertificate({ subject: 'Unrelated CA', isCa: true });

    const common = {
      challenge,
      origin,
      rpId,
      ...(tampered ? { breakAttestationSignature: true } : {}),
    };

    let registration;
    if (format === 'packed') {
      // The AAGUID in the certificate has to match the one in the
      // authenticator data, or the model the chain vouches for is not the
      // model that signed.
      const leaf = createCertificate({
        subject: 'Playground Authenticator',
        issuer: root,
        aaguid: device.aaguid,
      });
      registration = await device.register({ ...common, attestationChain: { root, leaf } });
    } else if (format === 'apple') {
      registration = await device.register({ ...common, appleAttestation: { root } });
    } else if (format === 'tpm') {
      registration = await device.register({ ...common, tpmAttestation: { root } });
    } else if (format === 'fido-u2f') {
      registration = await device.register({ ...common, u2fAttestation: { root } });
    } else if (format === 'android-key') {
      registration = await device.register({ ...common, androidKeyAttestation: { root } });
    } else if (format === 'android-safetynet') {
      registration = await device.register({ ...common, safetyNetAttestation: { root } });
    } else if (format === 'appattest') {
      // Nothing to build: the point is that allowlisting a format the library
      // does not know still fails closed.
      registration = await device.register({ ...common, attestationFormat: 'appattest' });
    } else {
      registration = await device.register({ challenge, origin, rpId });
    }

    const trustAnchors =
      scenario === 'no-anchors' ? [] : scenario === 'wrong-root' ? [decoy.der] : [root.der];

    const expectations = {
      rpId,
      origin,
      challenge: Buffer.from(challenge).toString('base64url'),
      attestation: {
        formats: [format],
        ...(trustAnchors.length > 0 ? { trustAnchors } : {}),
      },
    };

    let verdict;
    try {
      const verified = await verifyRegistration(registration, expectations);
      verdict = {
        accepted: true,
        format: verified.attestationFormat,
        type: verified.attestationType,
        aaguid: Buffer.from(verified.aaguid).toString('hex'),
        aaguidVerified: verified.aaguidVerified,
        subject: verified.attestationSubject ?? null,
      };
    } catch (error) {
      verdict = {
        accepted: false,
        detail: isNinshoError(error) ? error.detail : String(error),
      };
    }

    const inner = decodeCbor(registration.attestationObject) as Map<string, unknown>;
    const statement = inner.get('attStmt');
    const authData = inner.get('authData') as Uint8Array;

    // Stated before the verdict is read, so the page reports whether reality
    // matched the claim rather than narrating whatever happened as correct.
    const expected = scenario === 'genuine' && meta.verified ? 'accepted' : 'refused';

    res.json({
      summary: `${meta.label} — ${ATTESTATION_SCENARIOS[scenario] as string}`,
      expected,
      note:
        meta.verified === false
          ? 'Ninsho does not verify this format. Allowlisting it does not change that: there is ' +
            'deliberately no arrangement of options that turns an unverified attestation into a ' +
            'verified one.'
          : 'The ceremony, the key pair, the certificates and the signature are all real, and the ' +
            'verdict below came from the shipped verifier rather than from this page.',
      format,
      hardware: meta.hardware,
      scenario,
      verdict,
      statement: describeAttestationStatement(format, statement),
      decodes: [
        {
          title: 'attestationObject (CBOR wrapper)',
          ...decodeAttestationObject(registration.attestationObject),
        },
        { title: 'authenticatorData', ...decodeAuthenticatorData(authData) },
      ],
    });
  }),
);

/**
 * Liveness, for a container orchestrator.
 *
 * Outside `/api` so a probe every few seconds does not spend the rate-limit
 * allowance, and deliberately not calling `visitor()` — a health check should
 * not create a world, or the sweeper would spend its life clearing up after
 * the load balancer.
 */
app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', worlds: worlds.size });
});

app.get(
  '/api/store',
  route(async (req, res) => {
    const world = await visitor(req, res);
    res.json({
      keys: await world.store.keyspace(),
      note:
        'Every key is namespaced ninsho:v1: and versioned, so a future schema change runs ' +
        'alongside this one rather than being misread. Search these values for any token the ' +
        'page has shown you — they are not there.',
    });
  }),
);

app.get(
  '/api/events',
  route(async (req, res) => {
    const world = await visitor(req, res);
    res.json({ events: world.audit.events.slice(-50) });
  }),
);

app.post(
  '/api/reset',
  route(async (req, res) => {
    // Drops only this visitor's world; everyone else's is untouched.
    await worlds.reset(worlds.identify(req, res));
    res.json({ ok: true });
  }),
);

// ─── Error handling ────────────────────────────────────────────────────────

/** Reduces an unknown throw to something safe to show. */
function describe(error: unknown): { code: string; message: string; detail?: string } {
  if (isNinshoError(error)) {
    const { body } = toErrorResponse(error);
    return {
      code: body.error.code,
      message: body.error.message,
      // The playground shows `detail` precisely because a real deployment does
      // not: seeing what the server knows, next to what the client is told, is
      // the clearest way to make that separation concrete.
      ...(error.detail !== undefined && { detail: error.detail }),
    };
  }
  return { code: 'UNKNOWN', message: 'Something went wrong' };
}

app.use((error: unknown, _req: Request, res: Response, _next: express.NextFunction) => {
  if (res.headersSent) return;
  console.error('[playground]', error);
  res.status(500).json({ ok: false, ...describe(error) });
});

/** Discards every visitor's world. Used by the tests between cases. */
export async function resetWorld(): Promise<void> {
  await worlds.clear();
  // The site limiter is process-wide and its window is a minute, so without
  // this one test that deliberately exhausts an allowance would starve every
  // test after it. Resetting between tests keeps the production limits real
  // rather than loosening them to make a suite pass.
  await resetSiteLimits();
}

/** Forgets every rate-limit counter this process has recorded. */
export async function resetSiteLimits(): Promise<void> {
  await siteStore.close();
  siteStore = new RecordingStore(new MemoryStore());
  siteLimiter = new Ninsho({ store: siteStore, audit: new MemoryAuditSink() });
}

// Guarded so importing this module for a test does not bind a port.
if (process.env['PLAYGROUND_NO_LISTEN'] !== '1') {
  app.listen(PORT, () => {
    console.log(`
  Ninsho playground → http://localhost:${PORT}
`);
  });
}
