/**
 * Records the website's walkthroughs from the real library.
 *
 *   npm run walkthroughs         re-record → website/assets/walkthroughs.js
 *   npm run walkthroughs:check   re-record in memory; fail if behaviour drifted
 *
 * ─── Why recordings, and why they can be trusted ──────────────────────────
 * The playground runs the library live, but only for someone who clones the
 * repository. The website has to work for someone who has not, which means
 * showing recordings — and a recording is exactly the kind of artefact that
 * quietly stops matching the thing it depicts. This project was founded on
 * an attack suite that tested a reimplementation instead of the shipped code.
 *
 * So three things hold every recording to the library as it is today:
 *
 *  1. **Every frame is real.** Each scenario starts `walkthrough-app.ts` on a
 *     real socket, backed by a real MemoryStore wrapped in the playground's
 *     RecordingStore, and sends it real HTTP requests. Nothing is typed in.
 *
 *  2. **Every step says in advance what should happen.** A step declares its
 *     expected status before it runs, and the recorder refuses to write a
 *     trace where the library disagreed. A walkthrough cannot publish "the
 *     attacker was refused" over a response that was a 200.
 *
 *  3. **CI re-records on every push.** `--check` records again and compares
 *     the behaviour — statuses, store operations, audit events — against the
 *     committed file, ignoring only values that are random by design. It also
 *     confirms every test a step cites still exists, and that the app source
 *     shown on the page is the source that ran.
 * ──────────────────────────────────────────────────────────────────────────
 */
import { readFileSync, writeFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MemoryStore,
  MemoryAuditSink,
  Ninsho,
  createDpopProof,
  generateDpopKeyPair,
  type DpopKeyPair,
  type NinshoConfig,
  type SecurityEvent,
} from '@ninshorg/server';
import { RecordingStore, type StoreOperation } from './store-recorder.ts';
import { createWalkthroughApp, ORIGIN } from './walkthrough-app.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../..');
const OUTPUT = join(REPO, 'website/assets/walkthroughs.js');
const APP_SOURCE_PATH = join(HERE, 'walkthrough-app.ts');
const PREFIX = 'window.NINSHO_WALKTHROUGHS = ';

// ── The recorded shape ──────────────────────────────────────────────────────

interface Cite {
  readonly file: string;
  readonly test: string;
}

interface Exchange {
  readonly method: string;
  readonly path: string;
  readonly headers: Record<string, string>;
  readonly body?: unknown;
  readonly status: number;
  readonly responseHeaders: Record<string, string>;
  readonly response?: unknown;
}

interface Step {
  readonly actor: string;
  readonly role: 'user' | 'attacker' | 'system';
  readonly title: string;
  readonly expected: string;
  readonly exchanges: readonly Exchange[];
  readonly storeOps: readonly { op: string; key: string; value?: string; ttlSeconds?: number; outcome?: string }[];
  readonly events: readonly { type: string; reason?: string; signalMatch?: string; userId?: string }[];
  readonly note: string;
  readonly cite?: readonly Cite[];
}

interface Scenario {
  readonly id: string;
  readonly title: string;
  readonly lede: string;
  readonly config: string;
  /** Tests behind a claim the lede makes. Verified like any step's. */
  readonly cite?: readonly Cite[];
  readonly steps: Step[];
}

// ── Redaction for display ───────────────────────────────────────────────────
// The recording holds real tokens from a throwaway store in a process that has
// exited, so nothing here is a live credential. They are still shortened: the
// page is about the shape of what happened, and a full token invites copying.

const short = (value: string): string => (value.length > 16 ? `${value.slice(0, 10)}…` : value);

/** High-entropy runs — tokens, hashes, ids — shortened wherever they appear. */
const shortenEntropy = (text: string): string => text.replace(/[A-Za-z0-9_-]{24,}/g, (m) => short(m));

const SECRET_FIELDS = new Set(['accessToken', 'refreshToken', 'token']);

function redactBody(body: unknown): unknown {
  if (body === null || typeof body !== 'object') return body;
  if (Array.isArray(body)) return body.map(redactBody);
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(body)) {
    if (key === 'password') out[key] = '••••••••';
    else if (SECRET_FIELDS.has(key) && typeof value === 'string') out[key] = short(value);
    else out[key] = redactBody(value);
  }
  return out;
}

function redactOp(op: StoreOperation): Step['storeOps'][number] {
  const value =
    op.value === undefined || op.value === null
      ? undefined
      : (() => {
          const text = shortenEntropy(op.value);
          return text.length > 140 ? `${text.slice(0, 139)}…` : text;
        })();
  return {
    op: op.op,
    key: shortenEntropy(op.key),
    ...(value !== undefined && { value }),
    ...(op.ttlSeconds !== undefined && { ttlSeconds: op.ttlSeconds }),
    ...(op.outcome !== undefined && { outcome: op.outcome }),
  };
}

function redactEvent(e: SecurityEvent): Step['events'][number] {
  return {
    type: e.type,
    ...(e.reason !== undefined && { reason: e.reason }),
    ...(e.signalMatch !== undefined && { signalMatch: e.signalMatch }),
    ...(e.userId !== undefined && { userId: e.userId }),
  };
}

// ── The harness ─────────────────────────────────────────────────────────────

interface Request {
  readonly method: 'GET' | 'POST';
  readonly path: string;
  /** Sent as `Authorization: <scheme> <token>`. */
  readonly token?: string;
  readonly scheme?: 'Bearer' | 'DPoP';
  /** Sent as the `DPoP` header. */
  readonly proof?: string;
  readonly body?: Record<string, unknown>;
  readonly headers?: Record<string, string>;
}

type Expectation =
  | number
  | { readonly describe: string; readonly holds: (statuses: readonly number[]) => boolean };

interface StepInput {
  readonly actor: string;
  readonly role: Step['role'];
  readonly title: string;
  readonly request?: Request | readonly Request[];
  /** Run requests together rather than one after another — a real race. */
  readonly concurrent?: boolean;
  readonly expect?: Expectation;
  /**
   * Audit events this step must emit — `type`, or `type:reason`, or
   * `type:signalMatch`. Any note that makes a claim about an event asserts it
   * here, because status codes alone let a note say something the library
   * did not do. (That happened: a draft of the refresh-reuse note claimed
   * `signalMatch: different`. The library said `same`, and was right.)
   */
  readonly events?: readonly string[];
  readonly note: string;
  readonly cite?: readonly Cite[];
  /** A change to the world with no request — the store going down. */
  readonly action?: () => Promise<void>;
}

/** Every raw token any response has handed out, to prove none reaches the store. */
const issuedTokens = new Set<string>();
/** How many raw store operations that proof was run against. */
let rawOpsChecked = 0;

/**
 * Refuses to record if a raw token reached the store.
 *
 * Runs on the store's own log, before anything is shortened for display. An
 * earlier draft ran it on the displayed operations — where every long token
 * had already been cut to ten characters, so it could not have found a leak if
 * there was one. A check that cannot fail is not evidence of anything.
 */
function assertNoRawTokens(scenario: string, title: string, log: readonly StoreOperation[]): void {
  for (const op of log) {
    rawOpsChecked += 1;
    for (const token of issuedTokens) {
      if (op.key.includes(token) || (op.value ?? '').includes(token)) {
        throw new Error(
          `[${scenario}] "${title}": a raw token reached the store in \`${op.op} ${op.key}\`. ` +
            'The walkthroughs show the store holding hashes; refusing to record one that does not.',
        );
      }
    }
  }
}

class Harness {
  readonly store: RecordingStore;
  readonly audit = new MemoryAuditSink();
  readonly auth: Ninsho;
  readonly #base: string;
  readonly #close: () => Promise<void>;

  private constructor(store: RecordingStore, auth: Ninsho, base: string, close: () => Promise<void>) {
    this.store = store;
    this.auth = auth;
    this.#base = base;
    this.#close = close;
  }

  static async start(config?: Omit<Partial<NinshoConfig>, 'store' | 'audit'>): Promise<Harness> {
    const store = new RecordingStore(new MemoryStore());
    const audit = new MemoryAuditSink();
    const { app, auth } = createWalkthroughApp({ store, audit, ...(config && { config }) });
    const server = app.listen(0, '127.0.0.1');
    await new Promise<void>((ready) => server.once('listening', ready));
    const { port } = server.address() as AddressInfo;
    const harness = new Harness(store, auth, `http://127.0.0.1:${port}`, async () => {
      await new Promise<void>((done) => server.close(() => done()));
      await auth.close().catch(() => undefined);
    });
    // The sink the app was built with is the one to read from.
    Object.defineProperty(harness, 'audit', { value: audit });
    return harness;
  }

  async #send(req: Request): Promise<Exchange> {
    const headers: Record<string, string> = { ...req.headers };
    if (req.token !== undefined) headers['authorization'] = `${req.scheme ?? 'Bearer'} ${req.token}`;
    if (req.proof !== undefined) headers['dpop'] = req.proof;
    if (req.body !== undefined) headers['content-type'] = 'application/json';

    const res = await fetch(`${this.#base}${req.path}`, {
      method: req.method,
      headers,
      ...(req.body !== undefined && { body: JSON.stringify(req.body) }),
    });
    const text = await res.text();
    let response: unknown;
    try {
      response = text.length > 0 ? JSON.parse(text) : undefined;
    } catch {
      response = text;
    }
    for (const field of ['accessToken', 'refreshToken', 'token'] as const) {
      const value = (response as Record<string, unknown> | undefined)?.[field];
      if (typeof value === 'string') issuedTokens.add(value);
    }

    const responseHeaders: Record<string, string> = {};
    for (const name of ['www-authenticate', 'retry-after']) {
      const value = res.headers.get(name);
      if (value !== null) responseHeaders[name] = value;
    }

    // What the page shows — tokens shortened, the password masked.
    const shown: Record<string, string> = {};
    for (const [name, value] of Object.entries(headers)) {
      if (name === 'content-type') continue;
      shown[name] = name === 'authorization' ? `${req.scheme ?? 'Bearer'} ${short(req.token ?? '')}` : shortenEntropy(value);
    }
    return {
      method: req.method,
      path: req.path,
      headers: shown,
      ...(req.body !== undefined && { body: redactBody(req.body) }),
      status: res.status,
      responseHeaders,
      ...(response !== undefined && { response }),
    };
  }

  /** Runs one step, and refuses to record it if the library disagreed. */
  async step(scenario: Scenario, input: StepInput): Promise<Exchange[]> {
    this.store.clearLog();
    const before = this.audit.events.length;

    if (input.action) await input.action();

    const requests = input.request === undefined ? [] : Array.isArray(input.request) ? input.request : [input.request as Request];
    const exchanges = input.concurrent
      ? await Promise.all(requests.map((r) => this.#send(r)))
      : await requests.reduce<Promise<Exchange[]>>(async (acc, r) => [...(await acc), await this.#send(r)], Promise.resolve([]));

    const statuses = exchanges.map((x) => x.status);
    let expected = '';
    if (input.expect !== undefined) {
      const ok =
        typeof input.expect === 'number'
          ? statuses.length > 0 && statuses.every((s) => s === input.expect)
          : input.expect.holds(statuses);
      expected = typeof input.expect === 'number' ? String(input.expect) : input.expect.describe;
      if (!ok) {
        throw new Error(
          `[${scenario.id}] "${input.title}" expected ${expected}, got ${statuses.join(', ')}.\n` +
            `  Responses: ${JSON.stringify(exchanges.map((x) => x.response))}\n` +
            'The walkthrough says one thing and the library did another. Refusing to record it.',
        );
      }
    }

    const emitted = this.audit.events.slice(before);
    for (const want of input.events ?? []) {
      const found = emitted.some((e) =>
        [e.type, `${e.type}:${e.reason ?? ''}`, `${e.type}:${e.signalMatch ?? ''}`].includes(want),
      );
      if (!found) {
        throw new Error(
          `[${scenario.id}] "${input.title}" should emit ${want}; emitted ` +
            `${emitted.map((e) => [e.type, e.reason, e.signalMatch].filter(Boolean).join(':')).join(', ') || 'nothing'}.`,
        );
      }
    }

    // Tokens this step's responses carried are already in the set, so a token
    // stored in the same step it was issued is caught too.
    assertNoRawTokens(scenario.id, input.title, this.store.log);

    scenario.steps.push({
      actor: input.actor,
      role: input.role,
      title: input.title,
      expected,
      exchanges: exchanges.map((x) => ({ ...x, ...(x.response !== undefined && { response: redactBody(x.response) }) })),
      storeOps: this.store.log.map(redactOp),
      events: this.audit.events.slice(before).map(redactEvent),
      note: input.note,
      ...(input.cite && { cite: input.cite }),
    });
    return exchanges;
  }

  close(): Promise<void> {
    return this.#close();
  }
}

const field = (x: Exchange | undefined, name: string): string => {
  const value = (x?.response as Record<string, unknown> | undefined)?.[name];
  if (typeof value !== 'string') throw new Error(`response has no ${name}: ${JSON.stringify(x?.response)}`);
  return value;
};

const ALICE = { email: 'alice@example.test', password: 'correct horse' };
const BOB = { email: 'bob@example.test', password: 'battery staple' };
const refused = (s: number): boolean => s >= 400 && s < 500;

// ── The scenarios ───────────────────────────────────────────────────────────

async function revocation(): Promise<Scenario> {
  const s: Scenario = {
    id: 'revocation',
    title: 'Sign out everywhere — and mean it',
    lede:
      'Alice is signed in on her laptop and her phone. She sees a session she does not recognise and ' +
      'signs out everywhere. The question that matters is what happens to an access token that has ' +
      'not expired yet.',
    config: 'new Ninsho({ store })',
    steps: [],
  };
  const h = await Harness.start();
  try {
    const [laptop] = await h.step(s, {
      actor: 'Alice · laptop', role: 'user', title: 'Signs in',
      request: { method: 'POST', path: '/login', body: ALICE, headers: { 'user-agent': 'Firefox · laptop' } },
      expect: 200,
      note:
        'The access token is 256 random bits whose meaning lives in the store. Look at the store keys: ' +
        'they hold a hash of the token, never the token itself.',
      cite: [{ file: 'opaque-engine.test.ts', test: 'never stores the raw token' }],
    });
    const [phone] = await h.step(s, {
      actor: 'Alice · phone', role: 'user', title: 'Signs in on a second device',
      request: { method: 'POST', path: '/login', body: ALICE, headers: { 'user-agent': 'Safari · phone' } },
      expect: 200,
      note: 'A second, independent session for the same user.',
    });
    await h.step(s, {
      actor: 'Alice · phone', role: 'user', title: 'Uses the app',
      request: { method: 'GET', path: '/me', token: field(phone, 'accessToken') },
      expect: 200,
      note: '`verify()` reads the store on every request. That single read is the whole architecture.',
    });
    await h.step(s, {
      actor: 'Alice · laptop', role: 'user', title: 'Signs out everywhere',
      request: { method: 'POST', path: '/logout-all', token: field(laptop, 'accessToken') },
      expect: 204,
      events: ['session.revoked_all:logout_all'],
      note:
        'Every session for the user is revoked. A tombstone is written before the records are enumerated, ' +
        'so a rotation racing the sign-out cannot resurrect one.',
      cite: [
        { file: 'session.test.ts', test: 'revokeAllForUser' },
        { file: 'session.test.ts', test: 'leaves nothing usable behind — only the markers that keep it that way' },
      ],
    });
    await h.step(s, {
      actor: 'Alice · phone', role: 'user', title: 'Tries again with a token that has not expired',
      request: { method: 'GET', path: '/me', token: field(phone, 'accessToken') },
      expect: 401,
      note:
        'Refused on this request, not at expiry. A self-contained token that nothing reads would still ' +
        'answer 200 here, whatever the settings page claimed. The refusal is also indistinguishable from ' +
        'one for a token that never existed — an attacker learns nothing from the difference.',
      cite: [{ file: 'opaque-engine.test.ts', test: 'does not reveal, through the error, whether a token ever existed' }],
    });
  } finally {
    await h.close();
  }
  return s;
}

async function refreshReuse(): Promise<Scenario> {
  const grace = new Ninsho({ store: new MemoryStore() }).config.refreshGraceSeconds;
  const s: Scenario = {
    id: 'refresh-reuse',
    title: 'A stolen refresh token burns the whole family',
    lede:
      'An attacker copies Alice’s refresh token and redeems it before she does. RFC 9700 §4.14.2: when a ' +
      'rotated token is presented again, one of the two holders is a thief and the server cannot tell ' +
      `which — so both lose the session. (Recorded with the grace window at 0 so the replay is ` +
      `unambiguous. The default is ${grace} seconds, which keeps two tabs refreshing at once from ` +
      'looking like theft.)',
    config: 'new Ninsho({ store, refreshGraceSeconds: 0 })',
    cite: [{ file: 'session.test.ts', test: 'stores the raw replacement only for the grace period, not the token lifetime' }],
    steps: [],
  };
  const h = await Harness.start({ refreshGraceSeconds: 0 });
  try {
    const [login] = await h.step(s, {
      actor: 'Alice · laptop', role: 'user', title: 'Signs in',
      request: {
        method: 'POST', path: '/login', body: ALICE,
        headers: { 'user-agent': 'Firefox · laptop', 'x-forwarded-for': '198.51.100.7' },
      },
      expect: 200,
      note: 'She now holds a refresh token. So, without her knowing, does an attacker.',
    });
    const [stolen] = await h.step(s, {
      actor: 'Attacker', role: 'attacker', title: 'Redeems the stolen refresh token first',
      request: {
        method: 'POST', path: '/refresh', body: { refreshToken: field(login, 'refreshToken') },
        headers: { 'user-agent': 'curl/8.9', 'x-forwarded-for': '203.0.113.66' },
      },
      expect: 200,
      note:
        'From the server’s side this is an ordinary rotation: the old token is consumed atomically and ' +
        'a new pair issued. The attacker is now holding a valid session.',
    });
    await h.step(s, {
      actor: 'Alice · laptop', role: 'user', title: 'Refreshes with the token she was given',
      request: {
        method: 'POST', path: '/refresh', body: { refreshToken: field(login, 'refreshToken') },
        headers: { 'user-agent': 'Firefox · laptop', 'x-forwarded-for': '198.51.100.7' },
      },
      expect: 401,
      events: ['refresh.reuse_detected:same', 'session.revoked:reuse_detected'],
      note:
        'That token was already rotated — by the attacker. Seeing it again means two parties hold it, so the ' +
        'entire token family is revoked and `refresh.reuse_detected` is raised. Note `signalMatch: same`: the ' +
        'replay came from Alice, whose browser matches the session, because the attacker redeemed first. The ' +
        'signal cannot name the thief when the thief wins the race — which is exactly why Ninsho revokes both ' +
        'holders instead of trying to pick one. Most libraries return a 401 here and leave the attacker’s ' +
        'chain alive.',
      cite: [
        { file: 'session.test.ts', test: 'ends the session for both parties when a stolen token is redeemed first' },
        { file: 'session.test.ts', test: 'emits refresh.reuse_detected with the replayed generation' },
      ],
    });
    await h.step(s, {
      actor: 'Attacker', role: 'attacker', title: 'Uses the access token they were issued',
      request: { method: 'GET', path: '/me', token: field(stolen, 'accessToken') },
      expect: 401,
      note: 'Dead — it belonged to the revoked family.',
    });
    await h.step(s, {
      actor: 'Attacker', role: 'attacker', title: 'Tries to refresh again',
      request: {
        method: 'POST', path: '/refresh', body: { refreshToken: field(stolen, 'refreshToken') },
        headers: { 'user-agent': 'curl/8.9', 'x-forwarded-for': '203.0.113.66' },
      },
      expect: 401,
      note: 'Their refresh chain is gone too. The theft cost the attacker the session they stole.',
    });
  } finally {
    await h.close();
  }
  return s;
}

async function ownership(): Promise<Scenario> {
  const s: Scenario = {
    id: 'ownership',
    title: 'Authenticated is not the same as entitled',
    lede:
      'Alice is signed in, legitimately. She changes the id in a URL. This is OWASP API Security #1 — ' +
      'broken object-level authorization — and authentication does nothing about it, because the token ' +
      'is perfectly valid.',
    config: "app.get('/users/:id/orders', auth.verify(), auth.requireOwner((req) => req.params.id), …)",
    steps: [],
  };
  const h = await Harness.start();
  try {
    const [login] = await h.step(s, {
      actor: 'Alice', role: 'user', title: 'Signs in',
      request: { method: 'POST', path: '/login', body: ALICE },
      expect: 200,
      note: 'Her principal is `u_alice`.',
    });
    const token = field(login, 'accessToken');
    await h.step(s, {
      actor: 'Alice', role: 'user', title: 'Reads her own orders',
      request: { method: 'GET', path: '/users/u_alice/orders', token },
      expect: 200,
      note: 'The owner selector reads `u_alice` from the route and it matches the caller.',
    });
    await h.step(s, {
      actor: 'Alice', role: 'attacker', title: 'Changes the id to Bob’s',
      request: { method: 'GET', path: '/users/u_bob/orders', token },
      expect: 403,
      events: ['authz.denied'],
      note:
        'Same valid token, refused anyway. `authz.denied` is emitted so the attempt is visible. An owner ' +
        'that cannot be determined at all is refused too, rather than treated as no restriction.',
      cite: [
        { file: 'middleware.test.ts', test: 'requireOwner' },
        { file: 'middleware.test.ts', test: 'refuses when the owner cannot be determined' },
      ],
    });
  } finally {
    await h.close();
  }
  return s;
}

/** `perAccount.windowMs` in walkthrough-app.ts. */
const ACCOUNT_WINDOW_MS = 900_000;

/**
 * The one scenario whose outcome depends on the clock, retried for that
 * reason and no other.
 *
 * The limiter is a sliding window: its estimate is the current window's count
 * plus the previous window's, weighted by how much of it still overlaps. If a
 * recording happens to cross a 15-minute boundary, the six attempts split
 * across two windows, and the estimate at the sixth lands a hair under 5 —
 * so it is allowed, and the step expecting 429 fails. The attempts take a few
 * hundred milliseconds, so this is roughly one run in several thousand.
 *
 * Not "cannot happen", then — so it is handled, narrowly. A failure is retried
 * once, and only if the window index actually changed while the scenario ran.
 * Any other failure is rethrown untouched: a retry that swallowed everything
 * would hide the regression the recorder exists to catch.
 */
async function stuffing(): Promise<Scenario> {
  const windowAt = (): number => Math.floor(Date.now() / ACCOUNT_WINDOW_MS);
  const started = windowAt();
  try {
    return await stuffingOnce();
  } catch (error) {
    if (windowAt() === started) throw error;
    console.warn('  (stuffing crossed a rate-limit window boundary mid-recording; recording it again)');
    return stuffingOnce();
  }
}

async function stuffingOnce(): Promise<Scenario> {
  const s: Scenario = {
    id: 'stuffing',
    title: 'Credential stuffing from many addresses',
    lede:
      'A botnet guesses Alice’s password, one attempt per address, so no single address comes near a ' +
      'per-address limit. Rate limiting by IP alone never notices. Ninsho keeps a second bucket per account.',
    config:
      "auth.rateLimit({ action: 'login', perIp: { limit: 20, windowMs: 60_000 },\n" +
      '                perAccount: { limit: 5, windowMs: 900_000 }, identify: (req) => req.body.email,\n' +
      '                trustProxy: 1 })',
    steps: [],
  };
  const h = await Harness.start();
  try {
    await h.step(s, {
      actor: 'Botnet · 5 addresses', role: 'attacker', title: 'One wrong guess from each of five addresses',
      request: [1, 2, 3, 4, 5].map((n) => ({
        method: 'POST' as const, path: '/login',
        body: { email: ALICE.email, password: `guess-${n}` },
        headers: { 'x-forwarded-for': `203.0.113.${n}` },
      })),
      expect: 401,
      note:
        'Each address has made one attempt, against a per-address limit of 20. Every one of them was ' +
        'also counted against alice@example.test.',
    });
    await h.step(s, {
      actor: 'Botnet · a sixth address', role: 'attacker', title: 'A first attempt from a fresh address',
      request: {
        method: 'POST', path: '/login',
        body: { email: ALICE.email, password: 'guess-6' },
        headers: { 'x-forwarded-for': '203.0.113.6' },
      },
      expect: 429,
      events: ['ratelimit.exceeded:login'],
      note:
        'Refused before the password is even checked. This address has never been seen — the account ' +
        'bucket is what closed. `trustProxy: 1` has no default: the library refuses to guess how many ' +
        'proxies to trust, because a wrong guess either trusts a forged header or puts every visitor in one bucket.',
      cite: [{ file: 'ratelimit.test.ts', test: 'stops distributed credential stuffing against one account' }],
    });
    await h.step(s, {
      actor: 'Bob · shared office NAT', role: 'user', title: 'Signs in from one of the same addresses',
      request: {
        method: 'POST', path: '/login', body: BOB,
        headers: { 'x-forwarded-for': '203.0.113.3' },
      },
      expect: 200,
      note:
        'Bob shares an address with one of the attacking hosts. His account’s bucket is untouched and ' +
        'that address is far under its own limit, so he signs in. The attack on Alice cost Bob nothing.',
      cite: [{ file: 'ratelimit.test.ts', test: 'does not punish other accounts from the same address' }],
    });
  } finally {
    await h.close();
  }
  return s;
}

async function resetRace(): Promise<Scenario> {
  const s: Scenario = {
    id: 'reset-race',
    title: 'A password-reset link works exactly once',
    lede:
      'The reset email is forwarded, or opened in five tabs at once. Read-then-delete — check the token ' +
      'exists, then remove it — lets several of those through. Ninsho consumes it with one atomic `take()`.',
    config: "auth.oneTimeTokens.consume('password-reset', token)",
    steps: [],
  };
  const h = await Harness.start();
  try {
    await h.step(s, {
      actor: 'Alice', role: 'user', title: 'Signs in on her laptop',
      request: { method: 'POST', path: '/login', body: ALICE },
      expect: 200,
      note: 'A live session — which the reset should end.',
    });
    const [issued] = await h.step(s, {
      actor: 'Alice', role: 'user', title: 'Asks for a reset link',
      request: { method: 'POST', path: '/password-reset/request', body: { email: ALICE.email } },
      expect: 202,
      note:
        'The token is hashed before it is stored, and its purpose is part of the key — a reset token cannot ' +
        'be redeemed at an email-verification endpoint. An unknown address gets the same 202, so this is not ' +
        'an oracle for which accounts exist.',
    });
    const token = field(issued, 'token');
    await h.step(s, {
      actor: 'Five tabs at once', role: 'user', title: 'All redeem the same link simultaneously',
      request: Array.from({ length: 5 }, () => ({ method: 'POST' as const, path: '/password-reset/confirm', body: { token } })),
      concurrent: true,
      expect: {
        describe: 'exactly one 200',
        holds: (st) => st.filter((x) => x === 200).length === 1 && st.every((x) => x === 200 || refused(x)),
      },
      events: ['onetime.consumed:password-reset', 'session.revoked_all:credential_changed'],
      note:
        'Five requests in flight together, and exactly one wins: `take()` reads and deletes in one indivisible ' +
        'step, so only one caller ever receives the record. The winner also ends every session Alice had — a ' +
        'password reset that left the attacker signed in would have fixed nothing.',
      cite: [{ file: 'one-time-token.test.ts', test: 'lets exactly one of many simultaneous clicks win' }],
    });
    await h.step(s, {
      actor: 'Whoever else has the email', role: 'attacker', title: 'Tries the link later',
      request: { method: 'POST', path: '/password-reset/confirm', body: { token } },
      expect: { describe: 'refused', holds: (st) => st.every(refused) },
      note: 'Already consumed. There is nothing left in the store to redeem.',
    });
  } finally {
    await h.close();
  }
  return s;
}

async function dpop(): Promise<Scenario> {
  const s: Scenario = {
    id: 'dpop',
    title: 'A stolen access token is inert without the key',
    lede:
      'Script injected into a page reads the access token and sends it elsewhere. A bearer token is just a ' +
      'string: it works for whoever holds it, from anywhere, until it expires. Under DPoP (RFC 9449) every ' +
      'request also carries a proof signed by a key the page itself cannot export.',
    config: "new Ninsho({ store, binding: 'dpop' })",
    steps: [],
  };
  const h = await Harness.start({ binding: 'dpop' });
  // In a browser, @ninshorg/client generates this as a non-extractable WebCrypto
  // key. Here in Node, the server package's helper stands in for it.
  const aliceKey: DpopKeyPair = generateDpopKeyPair('ES256');
  const attackerKey: DpopKeyPair = generateDpopKeyPair('ES256');
  const proof = (key: DpopKeyPair, method: string, path: string, accessToken?: string): string =>
    createDpopProof(key, { method, url: `${ORIGIN}${path}`, ...(accessToken !== undefined && { accessToken }) });

  try {
    const [login] = await h.step(s, {
      actor: 'Alice · browser', role: 'user', title: 'Signs in with a proof',
      request: { method: 'POST', path: '/login', body: ALICE, proof: proof(aliceKey, 'POST', '/login') },
      expect: 200,
      note: 'The session is bound to the thumbprint of the key that signed this request’s proof.',
    });
    const token = field(login, 'accessToken');
    const aliceProof = proof(aliceKey, 'GET', '/me', token);
    await h.step(s, {
      actor: 'Alice · browser', role: 'user', title: 'Calls the API — token plus a fresh proof',
      request: { method: 'GET', path: '/me', token, scheme: 'DPoP', proof: aliceProof },
      expect: 200,
      note:
        'The proof names this method and URL, hashes this token, and carries a single-use id. Its `jti` is ' +
        'claimed in the store so it can never be presented twice.',
    });
    await h.step(s, {
      actor: 'Attacker · XSS', role: 'attacker', title: 'Uses the stolen token on its own',
      request: { method: 'GET', path: '/me', token, scheme: 'DPoP' },
      expect: 401,
      note: 'A bearer token would have worked here. This one needs a proof, and the attacker has none.',
      cite: [{ file: 'dpop-integration.test.ts', test: 'a stolen token is useless without the key' }],
    });
    await h.step(s, {
      actor: 'Attacker · XSS', role: 'attacker', title: 'Signs a proof with their own key',
      request: { method: 'GET', path: '/me', token, scheme: 'DPoP', proof: proof(attackerKey, 'GET', '/me', token) },
      expect: 401,
      note: 'A well-formed proof, from the wrong key. Its thumbprint is not the one the session is bound to.',
    });
    await h.step(s, {
      actor: 'Attacker · XSS', role: 'attacker', title: 'Replays Alice’s own proof',
      request: { method: 'GET', path: '/me', token, scheme: 'DPoP', proof: aliceProof },
      expect: 401,
      events: ['token.rejected:dpop_proof_replayed'],
      note:
        'The right key, the right token, the right URL — and already used. The replay guard claimed that ' +
        '`jti` the first time, atomically.',
      cite: [{ file: 'dpop-integration.test.ts', test: 'refuses a captured proof replayed with the token it came from' }],
    });
  } finally {
    await h.close();
  }
  return s;
}

async function outage(): Promise<Scenario> {
  const s: Scenario = {
    id: 'outage',
    title: 'The store goes down mid-attack',
    lede:
      'An attacker holds a copy of a token Alice has already revoked, and waits for the session store to ' +
      'become unreachable. A library that fails open would have to guess whether the token is still good.',
    config: "new Ninsho({ store })   // onStoreError defaults to 'closed'",
    steps: [],
  };
  const h = await Harness.start();
  try {
    const [login] = await h.step(s, {
      actor: 'Alice', role: 'user', title: 'Signs in',
      request: { method: 'POST', path: '/login', body: ALICE },
      expect: 200,
      note: 'Unknown to her, an attacker copies this access token.',
    });
    const token = field(login, 'accessToken');
    await h.step(s, {
      actor: 'Alice', role: 'user', title: 'Signs out everywhere',
      request: { method: 'POST', path: '/logout-all', token },
      expect: 204,
      note: 'The copied token is now revoked.',
    });
    await h.step(s, {
      actor: 'Attacker', role: 'attacker', title: 'Tries the copied token',
      request: { method: 'GET', path: '/me', token },
      expect: 401,
      note: 'The store says revoked. Refused, as it should be.',
    });
    await h.step(s, {
      actor: 'Infrastructure', role: 'system', title: 'The session store becomes unreachable',
      action: () => h.store.close(),
      note:
        'Not simulated: the MemoryStore behind this app is really closed, and every call to it now throws. ' +
        'The test suite does the same against a genuinely dead Redis.',
    });
    await h.step(s, {
      actor: 'Attacker', role: 'attacker', title: 'Tries the copied token again',
      request: { method: 'GET', path: '/me', token },
      expect: 503,
      events: ['store.unavailable'],
      note:
        'Revocation cannot be checked, so the request is refused. Fail-open would have answered 200 — to a ' +
        'token revoked moments ago. The body says the service is unavailable and nothing about why: no ' +
        'hostname, no stack trace, nothing an attacker could use.',
      cite: [
        { file: 'middleware.test.ts', test: 'store outage behaviour' },
        { file: 'store-invariants.test.ts', test: 'fail-closed when Redis is unreachable' },
      ],
    });
    await h.step(s, {
      actor: 'Monitoring', role: 'system', title: 'Checks the health endpoint',
      request: { method: 'GET', path: '/health' },
      expect: 503,
      note: 'The outage is visible to the people who can fix it, not only to the people it is refusing.',
    });
  } finally {
    await h.close();
  }
  return s;
}

// ── Recording and checking ──────────────────────────────────────────────────

interface Walkthroughs {
  readonly library: string;
  /**
   * Library defaults the page states in its own prose, read from a real
   * instance at record time so the website never repeats a number from memory.
   */
  readonly defaults: { readonly refreshGraceSeconds: number };
  readonly appSource: string;
  readonly rawTokensChecked: number;
  readonly storeOpsChecked: number;
  readonly scenarios: readonly Scenario[];
}

async function record(): Promise<Walkthroughs> {
  issuedTokens.clear();
  rawOpsChecked = 0;
  const scenarios: Scenario[] = [];
  for (const run of [revocation, refreshReuse, ownership, stuffing, resetRace, dpop, outage]) {
    scenarios.push(await run());
  }

  const server = JSON.parse(readFileSync(join(REPO, 'packages/server/package.json'), 'utf8')) as { version: string };
  const probe = new Ninsho({ store: new MemoryStore() });
  const defaults = { refreshGraceSeconds: probe.config.refreshGraceSeconds };
  await probe.close();
  return {
    library: server.version,
    defaults,
    appSource: readFileSync(APP_SOURCE_PATH, 'utf8').replace(/\r\n/g, '\n'),
    rawTokensChecked: issuedTokens.size,
    storeOpsChecked: rawOpsChecked,
    scenarios,
  };
}

/**
 * Behaviour, with the values that are random by design removed. Operations
 * and events are compared as sets per step: `revokeAllForUser` fans out
 * concurrently, so their order within one step can legitimately vary.
 */
function behaviour(w: Walkthroughs): unknown {
  // Two kinds of value are random by design: tokens, hashes and ids (long
  // runs), and rate-limit window indices — `rl:login:ip:127.0.0.1:29835744`
  // is minutes since the epoch. A first draft masked only the first kind, and
  // passed every check run within a minute of recording and failed every one
  // after; CI would have been red on almost every push.
  const mask = (text: string): string => text.replace(/[A-Za-z0-9_-]{10,}…?/g, '*').replace(/\b\d{6,}\b/g, '#');
  return w.scenarios.map((sc) => ({
    id: sc.id,
    steps: sc.steps.map((st) => ({
      actor: st.actor,
      expected: st.expected,
      requests: st.exchanges.map((x) => `${x.method} ${x.path} → ${x.status}`).sort(),
      ops: st.storeOps.map((o) => `${o.op} ${mask(o.key)} ${o.outcome ?? ''}`.trim()).sort(),
      events: st.events.map((e) => [e.type, e.reason, e.signalMatch].filter(Boolean).join(':')).sort(),
    })),
  }));
}

function firstDifference(a: unknown, b: unknown, path = ''): string | undefined {
  if (JSON.stringify(a) === JSON.stringify(b)) return undefined;
  if (Array.isArray(a) && Array.isArray(b)) {
    for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
      const d = firstDifference(a[i], b[i], `${path}[${i}]`);
      if (d) return d;
    }
  } else if (a && b && typeof a === 'object' && typeof b === 'object') {
    for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) {
      const d = firstDifference((a as Record<string, unknown>)[key], (b as Record<string, unknown>)[key], `${path}.${key}`);
      if (d) return d;
    }
  }
  return `${path}\n    recorded: ${JSON.stringify(a)}\n    now:      ${JSON.stringify(b)}`;
}

/** Every test a step cites must exist, by quoted name, in a file of that name. */
function missingCitations(w: Walkthroughs): string[] {
  const files = new Map<string, string[]>();
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      if (name === 'node_modules' || name === 'dist') continue;
      const full = join(dir, name);
      if (statSync(full).isDirectory()) walk(full);
      else if (name.endsWith('.test.ts')) files.set(name, [...(files.get(name) ?? []), full]);
    }
  };
  walk(join(REPO, 'packages'));
  walk(join(REPO, 'examples'));

  const missing: string[] = [];
  for (const sc of w.scenarios) {
    for (const st of [{ cite: sc.cite }, ...sc.steps]) {
      for (const cite of st.cite ?? []) {
        const candidates = files.get(cite.file) ?? [];
        // Quoted, so `describe.runIf(...)(\n  'name'` and `it.each` both count,
        // and a name that merely appears inside a comment does not.
        const found = candidates.find((path) => {
          const text = readFileSync(path, 'utf8');
          return [`'${cite.test}'`, `"${cite.test}"`, `\`${cite.test}\``].some((q) => text.includes(q));
        });
        if (found) {
          // Where it was found, so the page can link to the file itself.
          (cite as { path?: string }).path = found.slice(REPO.length + 1).replace(/\\/g, '/');
        } else {
          missing.push(`${sc.id}: ${cite.file} › ${cite.test}`);
        }
      }
    }
  }
  return missing;
}

function serialise(w: Walkthroughs): string {
  return (
    '/* Generated by `npm run walkthroughs` from examples/playground/src/walkthroughs.ts.\n' +
    '   Do not edit. CI records these again on every push and fails if the library’s\n' +
    '   behaviour no longer matches — see the header of that file. */\n' +
    `${PREFIX}${JSON.stringify(w, null, 1)};\n`
  );
}

async function main(): Promise<void> {
  const check = process.argv.includes('--check');
  const fresh = await record();

  // Raw-token leaks were already refused step by step, on the unshortened
  // store log, inside Harness.step — a leak would have thrown before here.
  const missing = missingCitations(fresh);
  let failed = false;
  if (missing.length > 0) {
    console.error(`✗ Cited tests that do not exist:\n  ${missing.join('\n  ')}`);
    failed = true;
  }

  const steps = fresh.scenarios.reduce((n, sc) => n + sc.steps.length, 0);

  if (!check) {
    if (failed) process.exit(1);
    writeFileSync(OUTPUT, serialise(fresh));
    console.log(
      `✓ Recorded ${fresh.scenarios.length} walkthroughs, ${steps} steps, against @ninshorg/server ${fresh.library}\n` +
        `  ${fresh.storeOpsChecked} store operations, none holding any of the ${fresh.rawTokensChecked} tokens issued\n` +
        `  → ${OUTPUT.slice(REPO.length + 1).replace(/\\/g, '/')}`,
    );
    return;
  }

  if (!existsSync(OUTPUT)) {
    console.error('✗ website/assets/walkthroughs.js is missing. Run `npm run walkthroughs`.');
    process.exit(1);
  }
  const text = readFileSync(OUTPUT, 'utf8');
  const committed = JSON.parse(text.slice(text.indexOf(PREFIX) + PREFIX.length).trim().replace(/;$/, '')) as Walkthroughs;

  const drift = firstDifference(behaviour(committed), behaviour(fresh));
  if (drift) {
    console.error(`✗ The library no longer behaves as the website shows:\n  at ${drift}`);
    failed = true;
  }
  if (committed.appSource !== fresh.appSource) {
    console.error('✗ The app source shown on the website is not the source that ran. Run `npm run walkthroughs`.');
    failed = true;
  }
  if (failed) {
    console.error('\nIf the change in behaviour is intended, re-record with `npm run walkthroughs` and say why.');
    process.exit(1);
  }
  console.log(
    `✓ ${fresh.scenarios.length} walkthroughs, ${steps} steps: the library still behaves as the website shows\n` +
      `✓ every cited test exists; no raw token in any of ${fresh.storeOpsChecked} store operations`,
  );
}

await main();
