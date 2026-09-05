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
  type Principal,
  type SecurityEvent,
} from '@ninsho/server';
import { RecordingStore, type StoreOperation } from './store-recorder.ts';

const PORT = Number(process.env['PORT'] ?? 4000);

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
app.use(express.static(new URL('../public', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')));

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
