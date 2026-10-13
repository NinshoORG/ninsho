// Optional real-browser regression. See docs/review-remediation.md for setup.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';

const bundle = await readFile(new URL('../packages/client/dist/index.js', import.meta.url));
const server = createServer((req, res) => {
  if (req.url === '/client.js') {
    res.setHeader('Content-Type', 'text/javascript');
    res.end(bundle);
  } else {
    res.setHeader('Content-Type', 'text/html');
    res.end('<!doctype html><title>Ninsho storage test</title>');
  }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;
let browser;
try {
  browser = await chromium.launch({
    headless: true,
    ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}),
  });
  const context = await browser.newContext();
  const pages = await Promise.all([context.newPage(), context.newPage()]);
  await Promise.all(pages.map(page => page.goto(base)));
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
  console.log(`PASS Chromium ${await browser.version()}: concurrent pages converge; reload retains non-extractable key`);
} finally {
  await browser?.close();
  await new Promise(resolve => server.close(resolve));
}
