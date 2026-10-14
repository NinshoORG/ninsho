// Test-only tooling stays outside published workspaces. Keep the CI install
// pin in sync; refuse a mismatched local install rather than claiming the same run.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const playwrightVersion = '1.64.1';

export async function runBrowserRegression(scenario) {
  const browserName = process.env.BROWSER ?? 'chromium';
  if (!['chromium', 'firefox', 'webkit'].includes(browserName)) {
    throw new Error(`Unsupported BROWSER=${browserName}; expected chromium, firefox or webkit`);
  }
  const installed = require('playwright/package.json').version;
  if (installed !== playwrightVersion) {
    throw new Error(`Expected playwright@${playwrightVersion}, found ${installed}; see docs/browser-regressions.md`);
  }
  const playwright = require('playwright');
  const bundle = await readFile(new URL('../packages/client/dist/index.js', import.meta.url));
  const server = createServer((req, res) => {
    res.setHeader('Content-Type', req.url === '/client.js' ? 'text/javascript' : 'text/html');
    res.end(req.url === '/client.js' ? bundle : '<!doctype html><title>Ninsho browser regression</title>');
  });
  let browser;
  let context;
  let deadline;
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); });
    });
    const base = `http://127.0.0.1:${server.address().port}`;
    browser = await playwright[browserName].launch({
      headless: true,
      ...(browserName === 'chromium' && process.env.CHROMIUM_PATH
        ? { executablePath: process.env.CHROMIUM_PATH } : {}),
    });
    context = await browser.newContext();
    const pages = await Promise.all([context.newPage(), context.newPage()]);
    await Promise.all(pages.map(page => page.goto(base)));
    // A deadline reports broken synchronization; it never advances a scenario.
    // Closing the context in finally also releases evaluations awaiting gates.
    await Promise.race([
      scenario({ pages, base, browserName, version: browser.version() }),
      new Promise((_, reject) => {
        deadline = setTimeout(() => reject(new Error(`${browserName}: regression exceeded 90 seconds`)), 90_000);
      }),
    ]);
  } finally {
    clearTimeout(deadline);
    // Nested finally blocks guarantee server cleanup even if browser teardown
    // fails. Closing the context destroys page channels and pending operations.
    try {
      await context?.close();
    } finally {
      try {
        await browser?.close();
      } finally {
        server.closeAllConnections();
        if (server.listening) await new Promise((resolve, reject) => {
          server.close(error => error ? reject(error) : resolve());
        });
      }
    }
  }
}
