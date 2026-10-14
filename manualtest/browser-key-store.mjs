// Real-browser regression. See docs/browser-regressions.md for setup.
import assert from 'node:assert/strict';
import { runBrowserRegression } from './browser-harness.mjs';

await runBrowserRegression(async ({ pages, base, browserName, version }) => {
  await Promise.all(pages.map(page => page.evaluate(async baseUrl => {
    const { NinshoClient, IndexedDbKeyStore } = await import('/client.js');
    const store = new IndexedDbKeyStore('review-shared');
    const load = store.load.bind(store);
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    window.release = release;
    // Both tabs must observe an empty store before either generates/persists.
    store.load = async () => {
      const old = await load();
      window.loaded = true;
      await gate;
      return old;
    };
    window.client = new NinshoClient({ baseUrl, keyStore: store });
    window.pending = window.client.getThumbprint();
  }, base)));
  await Promise.all(pages.map(page => page.waitForFunction(() => window.loaded === true)));
  await Promise.all(pages.map(page => page.evaluate(() => window.release())));
  const keys = await Promise.all(pages.map(page => page.evaluate(() => window.pending)));
  assert.equal(keys[0], keys[1]);

  await pages[0].reload();
  const persisted = await pages[0].evaluate(async () => {
    const { IndexedDbKeyStore } = await import('/client.js');
    const key = await new IndexedDbKeyStore('review-shared').load();
    return { thumbprint: key.thumbprint, extractable: key.privateKey.extractable };
  });
  assert.equal(persisted.thumbprint, keys[0]);
  assert.equal(persisted.extractable, false);
  console.log(`PASS ${browserName} ${version}: concurrent pages converge; reload retains non-extractable key`);
});
