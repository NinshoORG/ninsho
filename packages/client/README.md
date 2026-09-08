# @ninsho/client

Browser client for [Ninsho](https://github.com/NinshoORG/ninsho). Manages a DPoP
session so your application does not have to.

**Zero dependencies.** Web APIs only — WebCrypto, IndexedDB, fetch.

```bash
npm install @ninsho/client
```

## Setup

```ts
import { NinshoClient, IndexedDbKeyStore } from '@ninsho/client';

const auth = new NinshoClient({
  baseUrl: 'https://api.example.com',
  keyStore: new IndexedDbKeyStore(),   // so the key survives a reload
});

await auth.signIn('/auth/login', { email, password });

// Proof, Authorization header, and refresh-on-401 are all handled.
const orders = await auth.fetch('/orders').then((r) => r.json());

await auth.signOut();
```

## What it does that is easy to get wrong

**The private key is non-extractable.** `crypto.subtle.exportKey` on it throws,
and there is no other route to the bytes — including for script an attacker
injects through an XSS.

That is the whole point. A bearer token is a *string*: an XSS that can read it
copies it anywhere and uses it indefinitely. A DPoP-bound token is useless
without proofs, proofs need the key, and the key cannot leave the browser. An
attacker is reduced to signing proofs *while they still have execution* — far
more expensive to hold, and it ends when the page closes.

It does not make XSS harmless. It makes stolen credentials **non-portable**,
which is a different and much better failure mode.

**The access token is held in memory only.** Never `localStorage`: anything a
script can read, an XSS can read. Losing it on reload is the intended trade —
the refresh token is in an httpOnly cookie the browser replays itself, so a
reload costs one round trip rather than a sign-in.

**Refreshes are single-flight.** A page firing six requests when a token expires
gets six 401s. Six refreshes would be worse than wasteful: under rotation, five
of them present a token another has already rotated, and the server correctly
reads that as theft and ends the session. Collapsing them into one is what keeps
a normal page load from looking like an attack.

**Key initialisation is single-flight too**, for the same reason — concurrent
first requests would otherwise each generate a key, last write wins, and a
session bound to a discarded key is broken with nothing in the logs.

## Key storage

`IndexedDbKeyStore` is the browser default, because IndexedDB is the only
browser storage that can hold a `CryptoKey` handle. `localStorage` takes
strings, so using it would force `extractable: true` and hand any XSS the
private key.

`MemoryKeyStore` is provided for tests and non-browser clients. Implement
`DpopKeyStore` for anything else — but never one backed by string storage.

## Server side

Requires `binding: 'dpop'`:

```ts
const auth = new Ninsho({ store, binding: 'dpop' });

// On the login route, before any token exists:
const jkt = await auth.confirmProofOfPossession(req);
const pair = await auth.createSession(principal, { confirmationKey: jkt });
```

## Interoperability

The client signs with WebCrypto; the server verifies with `node:crypto`. Two
codebases, two crypto APIs, one wire format — so they are tested against each
other rather than each against its own assumptions: thumbprints compared across
both implementations, and client proofs verified by the server's real verifier.

## Status

Pre-release (0.1.0). Not independently audited.

MIT
