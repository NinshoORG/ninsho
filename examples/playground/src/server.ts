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
  type Principal,
  type SecurityEvent,
} from '@ninsho/server';
import { decodeCbor } from '@ninsho/webauthn';
import { VirtualAuthenticator } from '@ninsho/webauthn/testing';
import { RecordingStore, type StoreOperation } from './store-recorder.ts';
import {
  decodeAttestationObject,
  decodeAuthenticatorData,
  decodeDpopProof,
  decodePaseto,
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
}

function build(): World {
  const audit = new MemoryAuditSink();
  const store = new RecordingStore(new MemoryStore());
  return {
    store,
    audit,
    auth: new Ninsho({ store, audit, refreshGraceSeconds: 0 }),
    latest: null,
    spent: [],
    resetToken: null,
  };
}

let world = build();

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
async function traced<T>(run: () => Promise<T>): Promise<{ result: T; trace: Trace }> {
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

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '64kb' }));
const localPath = (relative: string): string =>
  new URL(relative, import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');

app.use(express.static(localPath('../public')));

/**
 * The browser client, served straight from the package it was built from.
 *
 * Deliberately not copied into `public/`: a vendored copy goes stale silently,
 * and the whole point of this section is that the page runs the same code an
 * application would install.
 */
app.use('/vendor', express.static(localPath('../../../packages/client/dist')));

/** Wraps an async route so a rejection becomes a response, not a hung request. */
const route =
  (handler: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: express.NextFunction): void => {
    handler(req, res).catch(next);
  };

// ─── Session lifecycle ─────────────────────────────────────────────────────

app.post(
  '/api/session/create',
  route(async (_req, res) => {
    const { result, trace } = await traced(() =>
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
    const token = (req.body as { token?: string }).token ?? world.latest?.accessToken ?? '';

    try {
      const { result, trace } = await traced(() => world.auth.engine.verify(token));
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
  route(async (_req, res) => {
    const current = world.latest?.refreshToken;
    if (current === undefined) {
      res.status(400).json({ ok: false, message: 'Create a session first.' });
      return;
    }

    try {
      const { result, trace } = await traced(() => world.auth.refresh(current));
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
  route(async (_req, res) => {
    const stolen = world.spent[world.spent.length - 1];
    if (stolen === undefined) {
      res.status(400).json({
        ok: false,
        message: 'Refresh at least once first, so there is a rotated token to replay.',
      });
      return;
    }

    // The thief presents the already-rotated token from a different client.
    const { result, trace } = await traced(async () => {
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
  route(async (_req, res) => {
    const original = world.latest?.accessToken;
    if (original === undefined) {
      res.status(400).json({ ok: false, message: 'Create a session first.' });
      return;
    }

    // Flip one character. An opaque token is a lookup key, so a mutation
    // simply finds nothing — there is no signature to forge because there is
    // no signature at all.
    const flipped = `${original.slice(0, -1)}${original.endsWith('A') ? 'B' : 'A'}`;

    const { result, trace } = await traced(async () => {
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
  route(async (_req, res) => {
    const { result, trace } = await traced(async () => {
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
  route(async (_req, res) => {
    const { result, trace } = await traced(async () => {
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

/** A bound session, keyed by the thumbprint the browser reported. */
const boundSessions = new Map<
  string,
  { auth: Ninsho; store: RecordingStore; accessToken: string }
>();

app.post(
  '/api/dpop/bind',
  route(async (req, res) => {
    const { thumbprint } = req.body as { thumbprint?: unknown };
    if (typeof thumbprint !== 'string' || thumbprint.length === 0) {
      res.status(400).json({ ok: false, message: 'thumbprint is required' });
      return;
    }

    // One deployment per visitor, so two people on the page cannot see each
    // other's session — and so the store trace shown is theirs alone.
    const previous = boundSessions.get(thumbprint);
    if (previous) await previous.store.close();

    const store = new RecordingStore(new MemoryStore());
    const auth = new Ninsho({ store, binding: 'dpop' });

    const { result, trace } = await tracedOn(store, () =>
      auth.createSession(DEMO_USER, { confirmationKey: thumbprint }),
    );

    boundSessions.set(thumbprint, { auth, store, accessToken: result.accessToken });
    if (boundSessions.size > 50) {
      // Bounded, since anyone can open the page.
      const oldest = boundSessions.keys().next().value;
      if (oldest !== undefined && oldest !== thumbprint) {
        await boundSessions.get(oldest)?.store.close();
        boundSessions.delete(oldest);
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
    const { thumbprint, proof, omitProof } = req.body as {
      thumbprint?: unknown;
      proof?: unknown;
      omitProof?: unknown;
    };

    if (typeof thumbprint !== 'string') {
      res.status(400).json({ ok: false, message: 'thumbprint is required' });
      return;
    }
    const session = boundSessions.get(thumbprint);
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

app.get(
  '/api/store',
  route(async (_req, res) => {
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
  route(async (_req, res) => {
    res.json({ events: world.audit.events.slice(-50) });
  }),
);

app.post(
  '/api/reset',
  route(async (_req, res) => {
    await world.store.close();
    world = build();
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

app.listen(PORT, () => {
  console.log(`\n  Ninsho playground → http://localhost:${PORT}\n`);
});
