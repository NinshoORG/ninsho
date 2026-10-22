// Probe P1 — one DPoP key, several RFC 7638 thumbprints.
//
// `parseJwk` checks only the base64url character set of `x`/`y`; `importPublicKey`
// decodes them leniently. A 32-byte coordinate is 43 base64url characters
// (258 bits), so the final character carries 2 bits Node ignores. Each of the
// four spellings imports the same public key, but `jwkThumbprint` hashes the
// string, so each yields a different `jkt`.
//
// Run: node research/validation/probes/p1-jwk-thumbprint-malleability.mjs
// Requires: npm run build (imports packages/server/dist).

import { generateKeyPairSync, sign, randomUUID } from 'node:crypto';
import { verifyDpopProof } from '../../../packages/server/dist/index.js';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const b64u = (buf) => Buffer.from(buf).toString('base64url');

const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const jwk = publicKey.export({ format: 'jwk' });

function spellings(coordinate) {
  const last = ALPHABET.indexOf(coordinate.at(-1));
  const base = last & ~0b11;
  return [0, 1, 2, 3].map((low) => coordinate.slice(0, -1) + ALPHABET[base + low]);
}

function proofWith(x) {
  const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: { kty: 'EC', crv: 'P-256', x, y: jwk.y } };
  const payload = { jti: randomUUID(), htm: 'GET', htu: 'https://api.example.test/orders', iat: Math.floor(Date.now() / 1000) };
  const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  const sig = sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return `${input}.${b64u(sig)}`;
}

const results = [];
for (const x of spellings(jwk.x)) {
  try {
    const v = verifyDpopProof(proofWith(x), {
      method: 'GET', url: 'https://api.example.test/orders', maxAgeSeconds: 60, clockToleranceSeconds: 5,
    });
    results.push({ x_suffix: x.slice(-3), canonical: x === jwk.x, accepted: true, jkt: v.jkt });
  } catch (e) {
    results.push({ x_suffix: x.slice(-3), canonical: x === jwk.x, accepted: false, error: e.message });
  }
}
console.table(results);
const distinct = new Set(results.filter((r) => r.accepted).map((r) => r.jkt)).size;
console.log(`accepted spellings: ${results.filter((r) => r.accepted).length}/4, distinct thumbprints for ONE key: ${distinct}`);
console.log(distinct > 1 ? 'RESULT: REPRODUCED (thumbprint is not unique per key)' : 'RESULT: NOT REPRODUCED');
