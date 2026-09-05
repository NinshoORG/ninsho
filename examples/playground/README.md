# Ninsho playground

An interactive protocol explorer. Every button runs the **real library** — not a mock, not a
re-implementation — and shows what actually happened: the bytes handed to the client, the keys
written to the store, the audit events, and the attacks failing.

```bash
npm run build                                   # from the repo root
npm run dev --workspace @ninsho/playground
# → http://localhost:4000
```

## Why it exists

The README makes claims. Each has a test behind it, and a test is the right evidence for a
maintainer and the wrong evidence for someone deciding whether to adopt the thing. A visitor
should not have to read `session.test.ts` to believe that a replayed refresh token kills a family.

So the playground shows it happening, with the store operations underneath.

## What it demonstrates

**A session, end to end.** Create, verify, rotate. The store trace shows that what gets written is
`SHA-256(token)` and never the token — paste any credential the page shows you into the search box
and it will not be found among the live keys.

**Four attacks, and what stops each:**

| Attack | What you see |
| --- | --- |
| Replay a rotated refresh token | `REFRESH_REUSE_DETECTED`, the whole family revoked, and `signalMatch: different` on the audit event — the replay came from another client, which is close to certain theft rather than a retry |
| Flip one character of an access token | `TOKEN_INVALID`. The store is keyed by hash, so a mutation lands on a different key and finds nothing |
| Redeem a password-reset link twice | First accepted, second refused — the atomic `take()` that makes a forwarded email useless |
| Race two reset requests | Exactly one link survives. This one found a real bug: an index of outstanding tokens could not guarantee it under concurrency, and 80 of 80 raced tokens survived before the fix |

**Your browser holds the key.** The one section that does not run on the server, and therefore
the one a visitor does not have to take on trust. It imports `@ninsho/client` — served from the
package it was built from, not a copy — and walks six steps:

1. Generate a P-256 key pair **in the page**, non-extractable.
2. Try to steal it. `crypto.subtle.exportKey()` throws `InvalidAccessError` — the browser
   refusing, not the library asking politely.
3. Bind a session to its RFC 7638 thumbprint. The token now carries `cnf.jkt`.
4. Call an endpoint with a proof signed in the page. Accepted.
5. Send the same proof again. Refused — the `jti` has already been used.
6. Send the token with **no** proof, which is exactly what a thief who exfiltrated it has.
   Refused.

Step 6 is the point of the whole mechanism: a stolen token is useless without a key that cannot
leave the browser it was created in.

**Anatomy — the actual bytes.** Each button generates a genuine artefact with the shipped code
and annotates it field by field: offset, width, raw hex, value, and why the field is there.

- A **WebAuthn ceremony** run by the same virtual authenticator the test suite uses — a real P-256
  key signing real data. You get the 194-byte attestation object, the 164-byte registration
  `authenticatorData` with all eight flag bits broken out and the COSE key decoded, and a later
  37-byte assertion for contrast: header only, because an assertion carrying attested credential
  data is refused.
- A **PASETO v4.public** token, where the thing worth noticing is what is missing. There is no
  `alg` header, so the whole algorithm-confusion family has nothing to attack.
- A **DPoP proof**, presented twice — accepted, then refused as already used.

The parsing is done by the shipped parsers rather than reimplemented, so what you read is what the
verifier saw. A decoder that disagreed with the verifier would be worse than none.

**The keyspace.** Every live key, namespaced `ninsho:v1:`, with its value.

**The audit trail.** The structured events, whose shape is deliberately narrow — no free-form
payload that could accidentally carry a token, a password, or a request body.

## Tested

```bash
npm run test --workspace @ninsho/playground
```

21 tests over real HTTP. A demo does not usually get tests, and this one needs
them: every panel restates a claim from the README to an audience with no way
to check it. A demonstration that quietly stopped demonstrating would be worse
than a broken test — a page telling visitors something untrue while looking
entirely convincing.

So each claim the UI prints is asserted: that the raw token is absent from the
store and its SHA-256 present, that the trace shown beside it leaks no
credential either, that the replay is refused *and* classified as coming from a
different client, that exactly one of two raced reset links survives, and that
the byte offsets in the anatomy view are the ones the specification gives.

## What it is not

A production integration. It keeps one shared in-memory session for everyone who opens the page,
records every value that passes through the store, and hands out internals — including each
error's `detail`, which a real deployment never sends to a client — over HTTP.

Showing `detail` next to the client-facing message is deliberate: seeing what the server knows
beside what the caller is told is the clearest way to make that separation concrete. It is also
exactly why this must not be deployed as-is.

Copy [`examples/express-api`](../express-api) instead. That one is meant to be copied.
