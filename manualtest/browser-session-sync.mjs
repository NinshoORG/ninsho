// Real-browser regression. See docs/browser-regressions.md for setup.
// The fetch stub tests browser state/transport, not server revocation or HTTP cookies.
import assert from 'node:assert/strict';
import { runBrowserRegression } from './browser-harness.mjs';

await runBrowserRegression(async ({ pages, base, browserName, version }) => {
  await Promise.all(pages.map(page => page.evaluate(async baseUrl => {
    const { NinshoClient, IndexedDbKeyStore } = await import('/client.js');
    window.store = new IndexedDbKeyStore('sync-browser-test');
    window.client = new NinshoClient({
      baseUrl, keyStore: window.store, sessionSync: { context: 'browser-test' },
      fetch: async () => {
        if (window.delayResponse) {
          window.requestEntered = true;
          await new Promise(resolve => { window.releaseResponse = resolve; });
        }
        return new Response(JSON.stringify({ accessToken: 'browser-fixture-token' }), { status: 200 });
      },
    });
    // Initial cookie recovery does not emit identity-change notifications.
    await window.client.refresh();
  }, base)));
  const keys = await Promise.all(pages.map(page => page.evaluate(() => window.client.getThumbprint())));
  assert.equal(keys[0], keys[1]);
  await pages[1].evaluate(() => {
    window.delayResponse = true;
    window.pending = window.client.refresh();
  });
  await pages[1].waitForFunction(() => window.requestEntered === true);
  assert.equal(await pages[0].evaluate(async () => (await window.client.signOut()).ok), true);
  await pages[1].waitForFunction(() => window.client.isAuthenticated === false);
  await pages[1].evaluate(() => window.releaseResponse());
  assert.equal(await pages[1].evaluate(() => window.pending), false);
  assert.equal(await pages[1].evaluate(() => window.client.accessToken), null);
  assert.equal(await pages[0].evaluate(async () => (await window.store.load()).thumbprint), keys[0]);

  // A sign-in that began before the other tab's identity change cannot install
  // its delayed token. Native BroadcastChannel delivery is the ordering gate.
  await pages[0].evaluate(() => {
    window.delayResponse = true;
    window.pending = window.client.signIn('/login', {});
    window.observer = new BroadcastChannel('ninsho:session:v1:browser-test');
    window.observer.onmessage = event => { window.receivedIdentity = event.data.type === 'identity-change'; };
  });
  await pages[0].waitForFunction(() => window.requestEntered === true);
  await pages[1].evaluate(async () => { window.delayResponse = false; await window.client.signIn('/login', {}); });
  await pages[0].waitForFunction(() => window.receivedIdentity === true);
  await pages[0].evaluate(async () => { window.releaseResponse(); await window.pending; });
  assert.equal(await pages[0].evaluate(() => window.client.accessToken), null);
  assert.equal(await pages[1].evaluate(() => window.client.isAuthenticated), true);
  await Promise.all(pages.map(page => page.evaluate(() => { window.observer?.close(); window.client.dispose(); })));
  console.log(`PASS ${browserName} ${version}: peer logout, stale refresh/sign-in, shared key retention`);
});
