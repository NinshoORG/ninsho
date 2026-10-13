import { afterEach, describe, expect, it, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { IDBObjectStore } from 'fake-indexeddb';
import { NinshoClient } from './client.js';
import { IndexedDbKeyStore } from './storage.js';
import { generateDpopKey } from './keys.js';

afterEach(() => vi.restoreAllMocks());
describe('atomic persistent key initialization', () => {
  it('converges independent store connections on one key and keeps it after reload', async () => {
    // REGRESSION: two tabs can both load null before either persists its key.
    const name = `ninsho-test-${crypto.randomUUID()}`;
    const stores = [new IndexedDbKeyStore(name), new IndexedDbKeyStore(name)];
    let loaded = 0;
    let release!: () => void;
    const bothLoaded = new Promise<void>(resolve => { release = resolve; });
    for (const store of stores) {
      const load = store.load.bind(store);
      vi.spyOn(store, 'load').mockImplementation(async () => {
        const value = await load();
        if (++loaded === 2) release();
        await bothLoaded;
        return value;
      });
    }
    const clients = stores.map(keyStore => new NinshoClient({ baseUrl: 'https://api.example.test', keyStore }));
    const keys = await Promise.all(clients.map(client => client.getThumbprint()));
    expect(keys[0]).toBe(keys[1]);
    const reloaded = new IndexedDbKeyStore(name);
    expect((await reloaded.load())?.thumbprint).toBe(keys[0]);
    expect((await reloaded.load())?.privateKey.extractable).toBe(false);
    await reloaded.clear();
  });

  it('rejects an aborted insertion rather than reporting a persisted key', async () => {
    const store = new IndexedDbKeyStore(`ninsho-abort-${crypto.randomUUID()}`);
    const put = IDBObjectStore.prototype.put;
    vi.spyOn(IDBObjectStore.prototype, 'put').mockImplementation(function (this: IDBObjectStore, ...args) {
      const request = put.apply(this, args);
      this.transaction.abort();
      return request;
    });
    await expect(store.getOrCreate(await generateDpopKey())).rejects.toThrow();
    expect(await store.load()).toBeNull();
  });
});
