# @ninshorg/client

Browser client for [Ninsho](https://github.com/NinshoORG/ninsho). Manages a DPoP
session so your application does not have to.

**Zero dependencies.** Web APIs only — WebCrypto, IndexedDB, fetch.

```bash
npm install @ninshorg/client
```

## Setup

```ts
import { NinshoClient, IndexedDbKeyStore } from '@ninshorg/client';

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

**Refreshes are single-flight within one client instance.** A page firing six requests when a token expires
gets six 401s. Six refreshes would be worse than wasteful: under rotation, five
of them present a token another has already rotated, and the server correctly
reads that as theft and ends the session. Collapsing them into one is what keeps
a normal page load from looking like an attack.

**Key initialization uses an atomic winner.** Built-in stores implement
`getOrCreate(candidate)`; independent IndexedDB connections serialize the
read/insert transaction and return the existing winner. See `storage.test.ts`
and `manualtest/browser-key-store.mjs` for concurrent initialization regressions.

Custom persistent stores should implement the optional `getOrCreate` operation
atomically across all connections. Without it, the compatibility path only
coordinates clients sharing the same store object in one JavaScript realm.

Refresh and logout are not broadcast between tabs. A tab with an already cached
key can retain it after another tab clears IndexedDB. Server-side revocation is
the authority; applications needing synchronized tab UI should coordinate it.
Use distinct database names for independent authentication contexts on one origin.

**Logout invalidates pending client operations.** Late refresh/sign-in completions
cannot restore the previous identity. Sign-in waits for pending local logout
cleanup. See `lifecycle.test.ts`. A network failure still cannot establish that
remote logout succeeded; inspect the returned response/null.

**Transient refresh failures preserve recovery state.** HTTP 429/5xx does not
clear the access token; 401/403 does. Callers should back off before retrying and
honor Retry-After. A failed refresh returns false. Applications must not interpret
that boolean alone as proof the session was revoked. See `lifecycle.test.ts`.

## Key storage

`MemoryKeyStore` is the default. Pass `IndexedDbKeyStore` explicitly for reload
persistence. IndexedDB can hold a non-extractable `CryptoKey` handle;
`localStorage` takes
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
