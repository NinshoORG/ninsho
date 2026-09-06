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

/** Drives one request through a middleware and reports what it decided. */
async function callMiddleware(
  middleware: Middleware,
  req: Record<string, unknown>,
): Promise<{ allowed: boolean; status: number; code?: string }> {
  let status = 200;
  let code: string | undefined;
  let allowed = false;

  const res = {
    status(value: number) {
      status = value;
      return res;
    },
    json(body: unknown) {
      code = (body as { error?: { code?: string } })?.error?.code;
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
        allowed = true;
        finish();
      }),
    ).catch(finish);
  });

  return { allowed, status, ...(code !== undefined && { code }) };
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
