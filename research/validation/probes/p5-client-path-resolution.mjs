// Probe P5 — NinshoClient path resolution.
//
// `#resolve` treats a path as absolute if it matches a scheme OR contains `//`
// ANYWHERE (the alternation in /^[a-zA-Z][a-zA-Z0-9+.-]*:|\/\// is unanchored
// on its second branch). A same-origin relative path with an empty segment is
// therefore parsed as an absolute URL, fails, and is refused. It fails safe —
// credentials are never sent elsewhere — so this is a functional defect only.
//
// Run: node research/validation/probes/p5-client-path-resolution.mjs
// Requires: npm run build.

import { NinshoClient } from '../../../packages/client/dist/index.js';

const seen = [];
const client = new NinshoClient({
  baseUrl: 'https://api.example.test',
  fetch: async (url) => { seen.push(url); return new Response('{}', { status: 200 }); },
});
for (const p of ['/files/a', '/files//a', 'https://evil.example/x', '//evil.example/x']) {
  try {
    await client.fetch(p);
    console.log(`${p.padEnd(24)} → sent to ${seen.at(-1)}`);
  } catch (e) {
    console.log(`${p.padEnd(24)} → refused: ${e.message.slice(0, 90)}`);
  }
}
