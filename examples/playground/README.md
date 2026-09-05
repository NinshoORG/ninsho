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

**The keyspace.** Every live key, namespaced `ninsho:v1:`, with its value.

**The audit trail.** The structured events, whose shape is deliberately narrow — no free-form
payload that could accidentally carry a token, a password, or a request body.

## What it is not

A production integration. It keeps one shared in-memory session for everyone who opens the page,
records every value that passes through the store, and hands out internals — including each
error's `detail`, which a real deployment never sends to a client — over HTTP.

Showing `detail` next to the client-facing message is deliberate: seeing what the server knows
beside what the caller is told is the clearest way to make that separation concrete. It is also
exactly why this must not be deployed as-is.

Copy [`examples/express-api`](../express-api) instead. That one is meant to be copied.
