# Contributing

## The rule

> **A security property stated in the documentation must name the test that
> demonstrates it, or it does not get stated.**

This is not a style preference. The library Ninsho replaces advertised "instant
revocation", "110 tests" and "all attacks blocked" while its CI had not run
since the release commit and 8 of 9 test files failed to import. The claims were
not dishonest by intent — they outran the evidence, which for an authentication
library amounts to the same thing.

## Setup

```bash
npm ci
npm run build      # core must be built before server tests resolve it
npm run test
npm run typecheck
```

Node 20+. CI runs on 20 and 22.

```bash
# The store contract suite runs against MemoryStore by default and adds
# RedisStore when REDIS_URL is set. There is deliberately no mock Redis.
docker run -d --rm -p 6379:6379 redis:7-alpine
REDIS_URL=redis://localhost:6379 npm run test
```

## What a change needs

**Every security-relevant change needs a test that fails without it.** Write the
test first and watch it fail; a test that has never failed proves nothing.

**Every bug fix needs a regression test.** Reproduce, write the failing test,
fix, confirm it passes, run the suite.

**Name the attack, not the mechanism.** `it('refuses a caller addressing
someone else's resource')` is worth more than `it('returns 403')` — the first
survives a refactor and explains why the assertion matters.

**Defaults are security decisions.** Changing one requires updating
`config.test.ts` › *secure defaults* and saying why in the PR.

## Design constraints

These are settled. Reopening one needs an argument, not a preference.

1. **`@ninsho/core` has zero runtime dependencies.** CI enforces that its bundle
   requires nothing beyond `node:crypto`.
2. **No cryptographic primitives are implemented here.** Ed25519, SHA-256 and
   the CSPRNG all come from `node:crypto`. PASETO's Pre-Authentication Encoding
   is serialization, not a primitive, and is proven against the specification's
   test vectors.
3. **No environment variable may weaken security.** The store is injected. CI
   fails the build if a test double or env kill-switch reaches `dist/`.
   `MemoryStore` reading `NODE_ENV` is the sole exception, and it can only ever
   make the library stricter.
4. **Fail closed.** A check that cannot be performed is not a check that passed.
5. **No framework dependency.** Middleware is typed structurally.
6. **Ninsho does not verify credentials.** Passwords, WebAuthn and federated
   sign-in belong to the application. Owning them would mean owning the user
   model.

## Adding a store

Implement `NinshoStore` and add it to the contract suite in
`store.contract.test.ts`. The suite is the specification — if an implementation
passes it, the engine works on it.

Two methods carry the load: `take` and `setIfAbsent` must be genuinely atomic.
Refresh rotation depends on exactly one concurrent caller winning, and a store
that gets this subtly wrong produces a race that only appears under production
concurrency.

## Errors

Never interpolate a caught value into a client-facing `message`. That is what
`detail` is for, and `toResponse()` does not read it — the separation is
structural so it cannot be forgotten.

Authentication failures share a deliberately uninformative message set. A client
learns its credential was not accepted, not why. Do not widen one to be helpful:
distinguishing "expired" from "revoked" from "never existed" hands an attacker
an oracle.

## Commits

Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`). For a
security-relevant change, say in the body what the attack was and which test now
covers it.

## Releasing

**Release is the maintainer's decision.** Nothing here publishes to npm.

Before a first public release:

- [ ] Fill in the reporting section of `SECURITY.md`; test the channel end to end
- [ ] Add `.well-known/security.txt` per RFC 9116
- [ ] **Replace the placeholder `github.com/ninsho/ninsho` URLs** in
      `packages/*/README.md` with the real repository. These are the package
      pages npm renders; a dead link there is the same failure the predecessor
      shipped in its security policy
- [ ] Claim the `@ninsho` scope — it was unclaimed as of 2026-08-31, which is
      not guaranteed to last
- [ ] `npm publish --dry-run` and check the file list
- [ ] Verify `npm ci && npm run build && npm run test` on a clean checkout
- [ ] Confirm CI is green — not assumed green
- [ ] Decide the version. `0.1.0` is honest for an unaudited pre-release; `1.0.0`
      is a promise about stability that should be earned, not defaulted to. The
      predecessor reached "1.0.0" in three days
