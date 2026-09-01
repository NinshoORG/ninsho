# Ninsho example — Express API

A complete, working API built on Ninsho. Everything here is meant to be copied.

```bash
npm install
npm run dev --workspace @ninsho/example-express-api
# with Redis:
REDIS_URL=redis://localhost:6379 npm run dev --workspace @ninsho/example-express-api
```

Runs on `MemoryStore` by default, which refuses to start under
`NODE_ENV=production`.

## What it demonstrates

| Route | Shows |
| :--- | :--- |
| `POST /auth/register` | Session creation; a registration response that does not confirm whether an address was already taken |
| `POST /auth/login` | Constant-time credential check; two-dimensional rate limiting |
| `POST /auth/refresh` | Rotation, and clearing the cookie on any failure |
| `POST /auth/logout` | Ending one session |
| `POST /auth/logout-all` | Ending every session for a user |
| `GET /auth/sessions` | Listing sessions without exposing credentials |
| `GET /me` | A plainly protected route |
| `GET /admin/reports` | Role-gated access |
| `GET /users/:id/orders` | **Ownership** — the check that is most often missing |
| `POST /auth/passkey/register/start` · `/finish` | Adding a passkey to an existing account, bound to the signed-in user |
| `GET /auth/passkeys` | Listing credentials without returning key material |
| `POST /auth/passkey/login/start` · `/finish` | Usernameless passkey sign-in, ending in an ordinary Ninsho session |

## The five decisions worth copying

**1. The whole Ninsho configuration is one line.**

```ts
const auth = new Ninsho({ store: new RedisStore(process.env.REDIS_URL!) });
```

No keys to generate, no algorithm to choose. The defaults are the secure ones.

**2. Rate limiting has two dimensions, because they stop different attacks.**

A per-IP bucket stops one host hammering the endpoint. A per-account bucket
stops a botnet spreading attempts across thousands of addresses so no single
one ever approaches a limit — which a per-IP limit alone never sees. The
reverse matters too: without the account bucket, one attacker can lock out
everyone behind a shared office address.

`trustProxy` has no default anywhere in Ninsho. Keying on the wrong address
either locks out every user behind a proxy, or lets an attacker bypass the
limit by rotating a header. Set it to match your deployment.

**3. Login answers identically whether or not the account exists.**

The obvious implementation returns early when no user is found, so an unknown
address answers in microseconds and a known one in ~100ms. That gap is a
reliable oracle for enumerating which addresses have accounts. `verifyCredentials`
hashes against an unmatchable dummy value on the miss path so both cost the same.

**4. The refresh token lives only in an httpOnly cookie.**

Never in a response body, where application code can log it or place it in
storage a script can read. `SameSite=Strict` means it is not attached to
cross-site requests, and `Path=/auth` keeps it off ordinary API calls.

**5. Authentication is not authorization.**

Without `requireOwner`, `GET /users/:id/orders` trusts `:id` because the
request was authenticated — so any signed-in user reads anyone's orders by
changing the value. That is OWASP API Security #1. Verifying a token says who
is calling; it says nothing about what they may address.

## Password hashing

scrypt with OWASP parameters (N=2¹⁷, r=8, p=1), built into Node so this example
needs no native dependency. Argon2id is the current first choice if you are
willing to take one.

bcrypt is deliberately absent: it silently ignores everything past byte 72, so
pairing it with a long-password form gives users far less strength than the
form implies, with nothing to indicate it.

**Ninsho does not hash passwords.** It manages what happens after identity is
established. Owning credential verification would mean owning your user model.

## Tests

```bash
npm run test --workspace @ninsho/example-express-api
```

72 end-to-end tests over real HTTP. They exist to catch what unit tests
structurally cannot — a middleware mounted in the wrong order, a cookie flag
that never reaches the wire, an error mapped to the wrong status by the
framework.

They have found two real bugs in this example so far. The first was an error
handler turning body-parser's 413 into a 500. The second was every `async`
route: Express 4 does not catch a rejected handler, so a failing route produced
an unhandled rejection and a request that never got a response — the client
would time out instead of seeing the 400 or 503 that actually happened. Both
are fixed; the second is why every async handler here is wrapped in `route()`.

The passkey tests drive a `VirtualAuthenticator` from
`@ninsho/webauthn/testing`, which holds a real key pair and produces real
signatures. That means the ceremony is verified by the real verifier rather
than by a stub agreeing with itself, and it is how a passkey integration can be
tested at all without a physical authenticator and a human finger.

## Not production-ready as-is

The user directory and the passkey directory are in-memory `Map`s. Replace them
with your database, keep the constant-time login path, keep writing the passkey
`signCount` back after every successful sign-in, and add whatever your
application needs — email verification, password reset, MFA. Ninsho has no
opinion about any of that.

The WebAuthn RP ID defaults to `localhost` for local development. Set `rpId`
and `webauthnOrigin` to your real domain before deploying: credentials are
scoped to the RP ID, so changing it later invalidates every passkey already
registered.
