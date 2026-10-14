import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryStore, Ninsho } from '@ninshorg/server';
import { NinshoClient, type NinshoClientOptions } from './client.js';
import { MemoryKeyStore } from './storage.js';

const baseUrl = 'https://api.example.test';
const json = (status: number, body: unknown = {}) => new Response(JSON.stringify(body), { status });
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(r => { resolve = r; });
  return { promise, resolve };
}

// Explicit delivery gates model BroadcastChannel's asynchronous delivery. No
// sleeps: a test decides exactly when a notification overtakes a response.
class Channel {
  static instances: Channel[] = [];
  static queue: Array<() => void> = [];
  static messages: unknown[] = [];
  onmessage: ((event: MessageEvent) => void) | null = null;
  closed = false;
  constructor(readonly name: string) { Channel.instances.push(this); }
  postMessage(data: unknown) {
    Channel.messages.push(structuredClone(data));
    for (const peer of Channel.instances) {
      if (peer !== this && peer.name === this.name && !peer.closed) {
        Channel.queue.push(() => peer.deliver(data));
      }
    }
  }
  deliver(data: unknown) { if (!this.closed) this.onmessage?.({ data } as MessageEvent); }
  close() { this.closed = true; }
  static flush() { for (const deliver of this.queue.splice(0)) deliver(); }
  static resetTraffic() { this.queue = []; this.messages = []; }
}

function client(context = 'shop', extra: Partial<NinshoClientOptions> = {}) {
  return new NinshoClient({ baseUrl, sessionSync: { context }, fetch: async () => json(200), ...extra });
}
function seed(...clients: NinshoClient[]) {
  for (const c of clients) c.setAccessToken('old-access');
  // Establish fixture state; tests below explicitly deliver every event under test.
  Channel.resetTraffic();
}
const notice = (type = 'logout', extra: Record<string, unknown> = {}) => ({
  version: 1, context: 'shop', type, id: '00000000-0000-4000-8000-000000000001', ...extra,
});

beforeEach(() => { Channel.instances = []; Channel.resetTraffic(); vi.stubGlobal('BroadcastChannel', Channel); });
afterEach(() => vi.unstubAllGlobals());

describe('cross-tab lifecycle boundaries', () => {
  it('invalidates a peer only after confirmed logout and leaves other contexts alone', async () => {
    const entered = deferred<void>(), reply = deferred<Response>();
    const a = client('shop', { fetch: async () => { entered.resolve(); return reply.promise; } });
    const b = client(), other = client('admin'); seed(a, b, other);
    const pending = a.signOut(); await entered.promise; Channel.flush();
    expect(b.isAuthenticated).toBe(true);
    reply.resolve(json(200)); await pending; Channel.flush();
    expect(b.accessToken).toBeNull(); expect(other.isAuthenticated).toBe(true);
    expect(await b.refresh()).toBe(false);
    await expect(b.fetch('/orders')).rejects.toThrow(/identity/);
  });

  it.each([401, 500, 503])('does not advertise failed logout HTTP %s', async status => {
    const a = client('shop', { fetch: async () => json(status) }), b = client(); seed(a, b);
    expect((await a.signOut())?.status).toBe(status); Channel.flush();
    expect(b.isAuthenticated).toBe(true); expect(Channel.messages).toEqual([]);
  });

  it('does not advertise a network failure or a tokenless local logout', async () => {
    const a = client('shop', { fetch: async () => { throw new Error('offline'); } }), b = client(); seed(a, b);
    expect(await a.signOut()).toBeNull(); await a.signOut(); Channel.flush();
    expect(b.isAuthenticated).toBe(true); expect(Channel.messages).toEqual([]);
  });

  it('sends only versioned lifecycle metadata, never credentials or key material', async () => {
    const a = client('shop', { fetch: async () => json(200, { accessToken: 'secret-access' }) });
    await a.signIn('/login', { password: 'secret-password', refreshToken: 'secret-refresh' });
    await a.signOut();
    expect(Channel.messages).toHaveLength(2);
    for (const message of Channel.messages) {
      expect(Object.keys(message as object).sort()).toEqual(['context', 'id', 'type', 'version']);
      expect(message).toMatchObject({ version: 1, context: 'shop' });
      expect(JSON.stringify(message)).not.toMatch(/secret|proof|jwk|privateKey|accessToken|refreshToken/);
    }
  });

  it('ignores malformed, unknown-version and irrelevant messages', () => {
    const a = client(); seed(a);
    const receiver = Channel.instances[0]; expect(receiver).toBeDefined();
    for (const data of [null, [], 'logout', {}, notice('refresh'), notice('logout', { version: 2 }),
      notice('logout', { context: 'other' }), notice('logout', { id: 5 }),
      notice('logout', { id: '' }), notice('logout', { token: 'injected' })]) {
      receiver?.deliver(data); expect(a.accessToken).toBe('old-access');
    }
  });

  it('does not let a duplicate logout erase an explicitly established newer identity', () => {
    const a = client(); seed(a); const receiver = Channel.instances[0];
    receiver?.deliver(notice()); expect(a.accessToken).toBeNull();
    a.setAccessToken('new-identity'); receiver?.deliver(notice());
    expect(a.accessToken).toBe('new-identity');
  });

  it.each([200, 401])('does not restore an old refresh after peer logout (%s)', async status => {
    // REGRESSION: the existing generation guard must also advance on peer events.
    const entered = deferred<void>(), reply = deferred<Response>();
    const a = client(), b = client('shop', { fetch: async () => { entered.resolve(); return reply.promise; } });
    seed(a, b); const refresh = b.refresh(); await entered.promise;
    await a.signOut(); Channel.flush(); reply.resolve(json(status, { accessToken: 'late' }));
    expect(await refresh).toBe(false); expect(b.accessToken).toBeNull();
  });

  it('does not let a delayed sign-in overwrite a newer peer identity', async () => {
    const entered = deferred<void>(), reply = deferred<Response>();
    const a = client(), b = client('shop', { fetch: async () => { entered.resolve(); return reply.promise; } });
    seed(a, b); const login = b.signIn('/login', { password: 'old-user' }); await entered.promise;
    a.setAccessToken('new-user'); Channel.flush(); reply.resolve(json(200, { accessToken: 'old-user' }));
    await login; expect(b.accessToken).toBeNull(); expect(a.accessToken).toBe('new-user');
    expect(Channel.messages).toHaveLength(1);
  });

  it('invalidates peers on successful sign-in without transferring the new identity', async () => {
    const a = client('shop', { fetch: async () => json(200, { accessToken: 'new-user' }) }), b = client();
    seed(a, b); await a.signIn('/login', {}); Channel.flush();
    expect(a.accessToken).toBe('new-user'); expect(b.accessToken).toBeNull();
  });

  it('keeps failed sign-in and transient refresh errors local', async () => {
    const a = client('shop', { fetch: async () => json(503) }), b = client(); seed(a, b);
    await a.signIn('/login', {}); expect(await a.refresh()).toBe(false); Channel.flush();
    expect(b.accessToken).toBe('old-access'); expect(Channel.messages).toEqual([]);
  });

  it('does not let an old response body restore identity after notification', async () => {
    const entered = deferred<void>(), body = deferred<unknown>();
    const response = json(200);
    vi.spyOn(response, 'json').mockImplementation(async () => { entered.resolve(); return body.promise; });
    const a = client(), b = client('shop', { fetch: async () => response }); seed(a, b);
    const pending = b.refresh(); await entered.promise;
    await a.signOut(); Channel.flush(); body.resolve({ accessToken: 'late-body' });
    expect(await pending).toBe(false); expect(b.accessToken).toBeNull();
  });

  it('does not launch a refresh when an old request returns 401 after notification', async () => {
    const entered = deferred<void>(), reply = deferred<Response>(); let calls = 0;
    const a = client(), b = client('shop', { fetch: async () => { calls++; entered.resolve(); return reply.promise; } });
    seed(a, b); const pending = b.fetch('/orders'); await entered.promise;
    await a.signOut(); Channel.flush(); reply.resolve(json(401));
    expect((await pending).status).toBe(401); expect(calls).toBe(1); expect(b.accessToken).toBeNull();
  });

  it('does not let an older local sign-in overwrite an explicit newer identity', async () => {
    const entered = deferred<void>(), reply = deferred<Response>();
    const a = client('shop', { fetch: async () => { entered.resolve(); return reply.promise; } });
    const pending = a.signIn('/login', {}); await entered.promise;
    a.setAccessToken('new-user'); reply.resolve(json(200, { accessToken: 'old-user' })); await pending;
    expect(a.accessToken).toBe('new-user'); expect(Channel.messages).toHaveLength(1);
  });

  it('does not publish an old logout over a newly observed peer identity', async () => {
    const entered = deferred<void>(), reply = deferred<Response>();
    const a = client('shop', { fetch: async () => { entered.resolve(); return reply.promise; } }), b = client();
    seed(a, b); const pending = a.signOut(); await entered.promise;
    b.setAccessToken('new-user'); Channel.flush(); reply.resolve(json(200)); await pending; Channel.flush();
    expect(b.accessToken).toBe('new-user'); expect(Channel.messages).toHaveLength(1);
  });

  it('retains the shared key when either tab signs out', async () => {
    const keyStore = new MemoryKeyStore(), clear = vi.spyOn(keyStore, 'clear');
    const a = client('shop', { keyStore }), b = client('shop', { keyStore }); seed(a, b);
    const key = await b.getThumbprint(); await a.signOut(); Channel.flush();
    expect(clear).not.toHaveBeenCalled(); expect((await keyStore.load())?.thumbprint).toBe(key);
  });

  it('preserves single-flight per tab and the real server rotation grace across tabs', async () => {
    const auth = new Ninsho({ store: new MemoryStore(), binding: 'dpop' });
    const keyStore = new MemoryKeyStore();
    const a = client('shop', { keyStore }), b = client('shop', { keyStore });
    const jkt = await a.getThumbprint();
    expect(await b.getThumbprint()).toBe(jkt);
    const pair = await auth.createSession({ userId: 'alice', roles: [], scopes: [] }, { confirmationKey: jkt });
    const both = deferred<void>(); let calls = 0;
    const fetch: typeof globalThis.fetch = async () => {
      if (++calls === 2) both.resolve(); await both.promise;
      const rotated = await auth.refresh(pair.refreshToken, { confirmationKey: jkt });
      return json(200, { accessToken: rotated.accessToken });
    };
    const x = client('shop', { keyStore, fetch }), y = client('shop', { keyStore, fetch }); seed(x, y);
    expect(await Promise.all([x.refresh(), x.refresh(), y.refresh(), y.refresh()])).toEqual([true, true, true, true]);
    expect(calls).toBe(2); expect(Channel.messages).toEqual([]);
    expect(x.isAuthenticated && y.isAuthenticated).toBe(true);
  });

  it('continues operating without BroadcastChannel', async () => {
    vi.stubGlobal('BroadcastChannel', undefined);
    const a = client('shop', { fetch: async () => json(200, { accessToken: 'new' }) });
    await a.signIn('/login', {}); expect(await a.refresh()).toBe(true);
    await a.signOut(); expect(a.accessToken).toBeNull();
  });

  it('does not open a channel unless explicitly opted in', () => {
    new NinshoClient({ baseUrl }); expect(Channel.instances).toEqual([]);
  });

  it('tolerates hosts that deny channel construction or message delivery', async () => {
    vi.stubGlobal('BroadcastChannel', class { constructor() { throw new Error('denied'); } });
    const a = client(); a.setAccessToken('old'); expect((await a.signOut())?.ok).toBe(true);
    vi.stubGlobal('BroadcastChannel', Channel);
    const b = client(); vi.spyOn(Channel.prototype, 'postMessage').mockImplementationOnce(() => { throw new Error('closed'); });
    b.setAccessToken('new'); expect(b.accessToken).toBe('new'); b.dispose();
  });

  it.each(['', '   ', 'x'.repeat(129)])('rejects ambiguous or unbounded context configuration', context => {
    expect(() => client(context)).toThrow(/context/);
  });

  it('closes channels once and prevents handling or stale completion after disposal', async () => {
    const entered = deferred<void>(), reply = deferred<Response>();
    const a = client('shop', { fetch: async () => { entered.resolve(); return reply.promise; } }); seed(a);
    const pending = a.refresh(); await entered.promise;
    const receiver = Channel.instances[0];
    a.dispose(); a.dispose(); receiver?.deliver(notice());
    reply.resolve(json(200, { accessToken: 'late' })); expect(await pending).toBe(false);
    expect(receiver?.closed).toBe(true); expect(receiver?.onmessage).toBeNull();
    expect(a.accessToken).toBeNull(); expect(() => a.setAccessToken('late')).toThrow(/disposed/);
    await expect(a.signIn('/login', {})).rejects.toThrow(/disposed/);
  });
});
