import { describe, expect, it } from 'vitest';
import { NinshoClient } from './client.js';
import { MemoryKeyStore } from './storage.js';
const origin = 'https://api.example.test';
const json = (status: number, body: unknown = {}) => new Response(JSON.stringify(body), { status });
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(r => { resolve = r; });
  return { promise, resolve };
}
describe('session lifecycle regressions', () => {
  it.each([200, 401])('ignores a late refresh response after logout (%s)', async status => {
    const entered = deferred<void>(), reply = deferred<Response>();
    const client = new NinshoClient({ baseUrl: origin, fetch: async input => {
      if (String(input).endsWith('/refresh')) { entered.resolve(); return reply.promise; }
      return json(200);
    }});
    client.setAccessToken('old');
    const pending = client.refresh(); await entered.promise;
    await client.signOut();
    reply.resolve(json(status, { accessToken: 'late' }));
    expect(await pending).toBe(false);
    expect(client.accessToken).toBeNull();
  });
  it('does not let an older refresh clear a newer identity', async () => {
    const entered = deferred<void>(), reply = deferred<Response>();
    const client = new NinshoClient({ baseUrl: origin, fetch: async () => {
      entered.resolve(); return reply.promise;
    }});
    client.setAccessToken('old'); const pending = client.refresh(); await entered.promise;
    client.setAccessToken('new-user'); reply.resolve(json(401)); await pending;
    expect(client.accessToken).toBe('new-user');
  });
  it('does not let a late sign-in restore a logged-out identity', async () => {
    const entered = deferred<void>(), reply = deferred<Response>();
    const client = new NinshoClient({ baseUrl: origin, fetch: async () => {
      entered.resolve(); return reply.promise;
    }});
    const pending = client.signIn('/login', {}); await entered.promise;
    await client.signOut(); reply.resolve(json(200, { accessToken: 'late' })); await pending;
    expect(client.accessToken).toBeNull();
  });
  it.each([429, 500, 503])('preserves recovery state after transient refresh HTTP %s', async status => {
    let calls = 0;
    const client = new NinshoClient({ baseUrl: origin, fetch: async () =>
      ++calls === 1 ? json(status) : json(200, { accessToken: 'recovered' }) });
    client.setAccessToken('old'); expect(await client.refresh()).toBe(false);
    expect(client.accessToken).toBe('old'); expect(await client.refresh()).toBe(true);
    expect(client.accessToken).toBe('recovered');
  });
  it('gives independent clients sharing storage the same winning key', async () => {
    const keyStore = new MemoryKeyStore();
    const clients = Array.from({ length: 8 }, () => new NinshoClient({ baseUrl: origin, keyStore }));
    const keys = await Promise.all(clients.map(c => c.getThumbprint()));
    expect(new Set(keys).size).toBe(1);
    expect((await keyStore.load())?.thumbprint).toBe(keys[0]);
  });
});

it('waits for an already-started key write before clearing persistent state', async () => {
  const entered = deferred<void>(), resume = deferred<void>();
  const store = new MemoryKeyStore();
  const keyStore = {
    load: () => store.load(),
    save: async (key: Awaited<ReturnType<MemoryKeyStore['load']>>) => {
      entered.resolve(); await resume.promise;
      if (key !== null) await store.save(key);
    },
    clear: () => store.clear(),
  };
  const client = new NinshoClient({ baseUrl: origin, keyStore });
  const pending = client.getKey().then(() => 'restored', () => 'cancelled');
  await entered.promise;
  const logout = client.signOut(); resume.resolve(); await logout;
  expect(await pending).toBe('cancelled');
  expect(await store.load()).toBeNull();
  expect(client.accessToken).toBeNull();
});

it('serializes sign-in after pending logout key deletion', async () => {
  const entered = deferred<void>(), resume = deferred<void>();
  const store = new MemoryKeyStore();
  const client = new NinshoClient({ baseUrl: origin, keyStore: {
    load: () => store.load(), save: key => store.save(key),
    clear: async () => { entered.resolve(); await resume.promise; await store.clear(); },
  }, fetch: async () => json(200, { accessToken: 'new-user' }) });
  await client.getKey();
  const logout = client.signOut(); await entered.promise;
  const login = client.signIn('/login', {});
  resume.resolve(); await logout; await login;
  expect(client.accessToken).toBe('new-user');
  expect((await store.load())?.thumbprint).toBe(await client.getThumbprint());
});
