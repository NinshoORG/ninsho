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

Cross-tab invalidation is opt-in; see the configuration below. Without it,
refresh and logout remain local to the client instance. Use distinct database
names for independent authentication contexts on one origin.

**Logout invalidates pending client operations.** Late refresh/sign-in completions
cannot restore the previous identity. Sign-in waits for pending local logout
cleanup. See `lifecycle.test.ts`. A network failure still cannot establish that
remote logout succeeded; inspect the returned response/null.

**Transient refresh failures preserve recovery state.** HTTP 429/5xx does not
clear the access token; 401/403 does. Callers should back off before retrying and
honor Retry-After. A failed refresh returns false. Applications must not interpret
that boolean alone as proof the session was revoked. See `lifecycle.test.ts`.

## Cross-tab session synchronization (opt-in)

Use this when several tabs share one authentication/cookie context and should
stop using an old identity after another tab logs out or signs in:

```ts
const auth = new NinshoClient({
  baseUrl: 'https://api.example.com',
  keyStore: new IndexedDbKeyStore('shop-auth-keys'),
  sessionSync: { context: 'shop-auth' },
});

await auth.signIn('/auth/login', { email, password });
const result = await auth.signOut('/auth/logout');
// Only result?.ok confirms success according to the endpoint's HTTP contract.
auth.dispose(); // terminal local cleanup; does not itself call the server
```

Choose a stable, non-secret context (1–128 characters, not whitespace-only).
All participating tabs must use the same context and a compatible shared DPoP
key store. Different applications, tenants or separately authenticated accounts
need different contexts **and** key database/cookie namespaces. A context name
is not an access-control boundary; do not put a token, email or session ID in it.

Events are invalidation notices, not token transfers:

- `logout` is published only after `signOut` receives an OK HTTP response for
  its logout request, provided no newer identity event superseded it. Errors,
  non-OK responses and a tokenless local logout do not publish success. Your
  endpoint must return success only after completing its revocation operation.
- `identity-change` is published after a successful `signIn` installs a
  nonempty access token, or `setAccessToken` explicitly changes its value
  (including clearing it). The client cannot infer identity from opaque tokens,
  so every such replacement is conservatively an identity change. Reassigning
  the same token does not notify peers. Use `refresh()` for routine rotation;
  refresh never broadcasts or asks other tabs to refresh.
- A receiving client clears its in-memory token, invalidates pending sign-in /
  refresh completions and prevents refresh or `fetch` until an explicit
  `signIn` succeeds or a non-null token is supplied via `setAccessToken`.
  `refresh()` returns false and `fetch()` throws while invalidated. Update
  application UI from the client's current state; the library does not render
  or reset application-owned caches. `isAuthenticated` is a local-state hint.

Local `signOut` also blocks recovery in synchronized mode, even on failure;
the caller chose to discard local identity, but peers are notified only on
confirmed success. An explicit new sign-in/token assignment can restore local
use. This does not retry a failed server revocation automatically.

The payload contains exactly `{ version: 1, context, type, id }`, with a random
event ID. No access/refresh token, credential, proof, user identity or key is
sent. Invalid shapes, versions and contexts are ignored; the last 128 event
IDs are retained to suppress duplicates. These properties and the behaviors
above are exercised in `src/session-sync.test.ts` (including “sends only
versioned lifecycle metadata”, “does not restore an old refresh”, and
“does not let a delayed sign-in overwrite a newer peer identity”).

**Shared-key lifecycle:** opting in retains persisted key material on both
local logout and received notifications, even when BroadcastChannel is absent.
Deleting a shared database key during logout could disrupt a concurrent tab's
new session; see “retains the shared key when either tab signs out”. Existing
non-synchronized clients retain their previous key-deletion behavior. Do not
mix these modes over one shared key database. For deliberate key rotation or
shared-device key removal, first revoke sessions and coordinate all writers,
then call the store's `clear()` yourself. Retaining a key is not proof that a
server session is still valid or revoked.

**Compatibility and limits:** the feature uses native BroadcastChannel within
the browser's same-origin/storage-partition rules. If the API is missing or
construction/delivery fails, local authentication continues with no cross-tab
delivery guarantee; there is no string-storage fallback. Call `dispose()` when
discarding a client to close its channel. It is idempotent, clears local state,
ignores stale completions and leaves shared key storage intact. Disposed
clients are terminal: `refresh()` returns false; other operational methods
throw. Tests cover unavailable/denied channels and repeated disposal.

This is best-effort live notification, not a durable event log or a distributed
lock. Closed/new tabs miss earlier events; suspended tabs may receive them
late. There is no total order across concurrent senders: a late unseen notice
may conservatively invalidate a newer login, and simultaneous sign-ins may
invalidate each other. Re-authenticate explicitly after delivery. Duplicate
IDs beyond the bounded cache can invalidate again. No event grants identity.

Requests already sent cannot be recalled, and browser-applied `Set-Cookie`
headers cannot be undone by ignoring a stale response body. An already-sent
request made with `fetch()` may still resolve with its original response;
applications must discard old-identity data before updating their own caches/UI.
An external login flow that calls `setAccessToken` must itself reject stale results; the setter
has no network-operation generation to check. Applications/server endpoints
must still coordinate concurrent account changes and cookie ownership.

Per-instance refresh single-flight and server rotation grace remain unchanged;
“preserves single-flight per tab and the real server rotation grace across tabs”
exercises concurrent refreshes. There is no cross-tab refresh mutex or promise
of grace beyond the server's configured window. Transient errors do not become
logout events. Server revocation/authorization remains authoritative: messages
cannot prove either. Same-origin malicious JavaScript can forge notifications,
clear state or invoke signing; this feature provides no XSS defense.

For the optional real-browser check, see
[`manualtest/browser-session-sync.mjs`](../../manualtest/browser-session-sync.mjs)
and [validation notes](../../docs/cross-tab-session-sync.md).

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
