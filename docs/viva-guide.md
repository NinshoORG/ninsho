# Reproducible viva rehearsal

Use Node 20+ and npm 11+. Build first. Run against a dedicated local Redis
6.2+; the demo refuses to substitute MemoryStore. Docker is one way to start it:

```bash
npm ci
npm run build
npm run typecheck
docker run -d --rm --name ninsho-viva-redis -p 127.0.0.1:6379:6379 redis:7-alpine
REDIS_URL=redis://127.0.0.1:6379 npm run test
REDIS_URL=redis://127.0.0.1:6379 npm run demo:viva
docker stop ninsho-viva-redis
```

These commands use Bash/Git Bash. If Redis already runs, use its URL instead
of starting another container. The demo closes its own HTTP servers and Redis
connections in `finally` and deletes only its random namespace. Stop the Docker
container yourself even if a command fails. A killed process cannot run cleanup.

`manualtest/three-demos.mjs` is the maintained replacement: the separately
mentioned three-demo script was not present in the reviewed checkout or supplied
text. It awaits server startup and uses ephemeral ports. Two independent engine
instances and Redis connections share one namespace. Clients A/B are simulated
HTTP callers, not two physical devices. `three-demos.test.mjs` runs this same
HTTP scenario from `npm test` whenever `REDIS_URL` is set (including CI).
Failures exit nonzero; printed expected values are backed by assertions.

## Expected HTTP results

| Demo | Request | Expected |
|---|---|---:|
| 1 | Default opaque bearer on A | 200 |
| 1 | Copy same bearer to B | 200 |
| 1 | Logout on A | 204 |
| 1 | Reuse same token on B after logout completes | 401 |
| 2 | Bound token without proof | 401 |
| 2 | Proof signed by a different client's key | 401 |
| 2 | Valid proof from bound key | 200 |
| 2 | Replay that exact proof | 401 |
| 3 | Alice requests Alice's resource | 200 |
| 3 | Alice requests Bob's resource | 403 |

The bound session is issued only after `confirmProofOfPossession` validates
a login proof. The fixture fixes the identity to Alice; real applications must
verify credentials before issuing a session. The ownership demo models a resource
whose owner is the route ID. For a document/order ID, load the resource's actual
owner from trusted application data; comparing the document ID to the user ID is
not a general authorization policy.

## Explain the claims accurately

- **Default:** opaque bearer tokens, with no browser binding. Copying one to
  another caller works until expiry/revocation. The first two demo assertions
  deliberately demonstrate that limitation.
- **Optional DPoP:** `binding: 'dpop'` requires proof from the bound key and checks
  replay. Demonstrated by demo 2 and `dpop-integration.test.ts`. A non-extractable
  browser key helps prevent export; hostile code executing in the same origin
  may still use it to sign. This is not an XSS cure.
- **Revocation:** demo 1 demonstrates rejection of a request begun after successful
  logout against the shared store. An already-authorized in-flight operation is
  not cancelled. Logout-all handles a snapshot of indexed sessions, not a global
  cutoff for future logins. See `review-regressions.test.ts` and
  `store-invariants.test.ts`. JWT systems can also use a denylist, session version,
  or introspection to implement revocation; server-side state is the relevant
  tradeoff, not an exclusive property of Ninsho.
- **Tampering versus authorization:** changing a signed token's claims without
  the signing key is an integrity failure, covered for PASETO in
  `paseto-v4.test.ts`. BOLA/IDOR is using a valid identity to request someone else's
  object. Demo 3 and `middleware.test.ts` exercise ownership enforcement. Signature
  verification alone does not establish resource ownership.
- **Store failures:** defaults fail closed. Explicit PASETO fail-open configuration
  can accept cryptographically valid tokens without a revocation check during an
  outage; opaque verification still needs its stored record. Replay/limiter
  policies also depend on configuration. See `docs/configuration.md`,
  `store-invariants.test.ts`, `opaque-engine.test.ts`, and `paseto-engine.test.ts`.
  A reachable but wiped PASETO denylist is a distinct failure, documented in
  `SECURITY.md`.
- **Partial writes:** session creation, rotation and revocation are multi-operation
  workflows, not one ACID transaction. A failed rotation can consume the old
  refresh token; a retry is not guaranteed to recover it. Partial logout-all
  throws `RevocationIncompleteError` and retains failed sessions for retry
  (`session.test.ts`, partial-revocation regression). Never report successful
  logout after a rejected revocation promise. See `docs/review-remediation.md`.

## Recorded verification for this patch

On Node 24.19.0 with Redis 7.4.11, the full command passed **2,116 workspace
tests plus the new HTTP rehearsal test (2,117 total), zero skipped**. Build,
TypeScript checks and `npm run lint:lockfile` passed. All ten demo statuses
matched the table above. Raw rehearsal output is in
[`manualtest/evidence/viva-rehearsal.txt`](../manualtest/evidence/viva-rehearsal.txt).
The new HTTP rehearsal also passed on Node 20 and 22.
The previous engine/client fix was separately tested on Node 20, 22 and 24;
see `review-remediation.md` for that earlier run's scope.

## Checklist reconciliation

The previous fix commit (`d8895b0`) includes five reproduced findings, regression
coverage, cookie-outage handling, browser key persistence fixes, and the dynamic
CI badge. This follow-up adds the maintained three-demo runner, automated HTTP
rehearsal, historical benchmark labels and this explanation. It does not add
features to the authentication engine.

Creation, rotation, token reuse, logout-all and concurrent revocation are covered
by `session.test.ts`, `store-invariants.test.ts`, and `review-regressions.test.ts`.
Real Redis WRONGTYPE/transaction failures and unreachable connections are covered
in `store-invariants.test.ts`; client/example outage regressions are recorded in
`docs/review-remediation.md`. Passing tests are evidence for those cases, not a
proof covering every possible failure interleaving.

There is no general lint script in this repository. The defined `lint:lockfile`
checks manifest/lockfile consistency; build and TypeScript checks are separate.
The README badge uses GitHub CI status rather than a manually chosen test count.
Use output from your exact checkout, with Redis enabled, when quoting totals.

## Performance reproduction

Use Node 22+ for these existing TypeScript benchmark scripts:

```bash
npm run build
npm run bench --workspace @ninshorg/server
REDIS_URL=redis://127.0.0.1:6379 npm run bench --workspace @ninshorg/server
node --experimental-strip-types benchmarks/supplementary/crypto-micro.ts
node --experimental-strip-types benchmarks/supplementary/dpop-bench.ts
node --experimental-strip-types benchmarks/supplementary/concurrency-bench.ts
node --experimental-strip-types benchmarks/supplementary/express-e2e-bench.ts
```

Record commit, Node version, hardware, configuration and raw output. Historical
numbers in `PERFORMANCE.md` and `BENCHMARK-REPORT.md` are not a fresh measurement
of these fixes. No direct JWT-versus-Ninsho harness was found, so previous JWT
comparison numbers should be presented only as unverified historical local runs,
or omitted. Do not claim a universal speed multiplier.

## Five-minute presentation

1. State the application problem: consistent session lifecycle and resource
   authorization across API instances. Explain what the host app must still do
   (identity verification and application-specific permissions).
2. Show the copied bearer working, then failing after shared-store logout.
3. Enable DPoP and show missing/wrong/replayed proofs failing and a valid proof
   succeeding. Explain the additional key-management and per-request cost.
4. Show Alice's 200 versus Bob's 403. Explain why authentication alone is not enough.
5. Show the full test result, limits, and the specific regression tests behind
   fixes. Explain a real integration scenario; claims of user demand require
   interviews or deployment feedback, not just this repository review.

After pushing, compare `git rev-parse HEAD` with `git ls-remote origin refs/heads/main`
and inspect CI for that exact commit. Local tests do not establish GitHub CI success
or that the patch has already reached main. No independent security certification
or production-readiness certification is implied.
