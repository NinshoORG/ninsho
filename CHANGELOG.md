# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **A rate-limiting panel in the playground.** Four demonstrations of the two
  buckets: credential stuffing spread across twelve addresses that no per-IP
  limit would notice, two colleagues behind one office address where only one
  is limited, five forged `X-Forwarded-For` chains that all resolve to one
  bucket, and a burst either side of a window boundary that a fixed-window
  counter would let through at twice the limit.

  Each runs the real middleware against synthesised requests, and each is
  asserted in the HTTP tests rather than left to look convincing — which is how
  the address off-by-one below was found.

- **A Koa adapter — `@ninsho/server/koa`.** The middleware is Express-shaped,
  and Fastify and Hono already had adapters; Koa was the one framework the
  README had to say was not claimed. It is claimed now.

  Koa halts differently again from either of the others: a middleware answers
  by *not calling* `next()`. There is no return value saying so and no
  `Response` to hand back — the absence of the call is the whole signal. Get
  that backwards and an authorization check sets a 403 and then lets the route
  handler overwrite it with the resource, which a test asserting only on status
  codes would never see. So every negative test asserts the handler did not
  run, against real Koa over real HTTP.

  Koa also ships no body parser, so `ctx.request.body` exists only if you added
  one. The adapter reads it when present and does not pretend otherwise: a
  guard whose selector finds nothing fails its check, which is the fail-closed
  outcome `ValueSelector` already specifies, and there is a test for exactly
  that shape. 20 tests. Nothing imports Koa — the types are structural, as with
  the other two, and a test reads the source to keep it that way.

- **FIDO Metadata Service support — `parseMetadataBlob()` and
  `toAttestationPolicy()`.** Attestation is refused without trust anchors,
  which is correct and leaves a relying party holding a question: where do the
  roots come from? FIDO publishes them, in a signed document listing every
  certified authenticator — its AAGUID, its attestation roots, and whether it
  has since been found compromised.

  Verifying that document is library work: it is a signature, a chain, and a
  set of rules about what a status report means, and getting any of them wrong
  is a security bug. **Fetching it is not, and is deliberately absent.** A
  library that reaches out to the network on your behalf decides your caching,
  your update cadence, and your failure mode when the service is down — at
  exactly the moment you least want a surprise. Hand over a BLOB you fetched;
  this does no I/O.

  Two rules in it are judgement calls worth stating:

  - **A compromise is permanent.** An entry carries a history of status
    reports, and FIDO can certify a model, later mark its attestation key
    compromised, and later still certify a new revision. Reading only the
    newest status would quietly re-admit a model whose attestation key is known
    to be in someone else's hands — the key that vouches for every unit ever
    made. Any of `ATTESTATION_KEY_COMPROMISE`, `USER_VERIFICATION_BYPASS`,
    `USER_KEY_REMOTE_COMPROMISE`, `USER_KEY_PHYSICAL_COMPROMISE` or `REVOKED`
    anywhere in the history disqualifies the entry.
  - **A stale BLOB is refused by default.** It still verifies and still looks
    authoritative, and it is missing every compromise published since. A fetch
    that has been quietly failing for months should announce itself rather than
    keep working. `allowStale` opts out.

  `SELF_ASSERTION_SUBMITTED` and `NOT_FIDO_CERTIFIED` are not accepted statuses:
  they mean the vendor filled in a form, and drawing trust anchors on that basis
  would make the metadata service a directory of people who asked to be trusted.

  28 tests, of which the two that matter most check that a policy built this way
  is one the ceremony actually enforces: a model the BLOB certifies registers, a
  model it does not is refused, and the same device stops registering once the
  BLOB reports its attestation key compromised.

- **SafetyNet attestation — WebAuthn §8.5.** The last format, and the one that
  completes WebAuthn L3's attestation coverage: `none`, `packed`, `apple`,
  `tpm`, `fido-u2f`, `android-key` and `android-safetynet` are all verified,
  and a format name outside that set is still refused rather than
  parsed-and-ignored.

  It is also the weakest, and the implementation says so rather than letting
  the coverage imply otherwise. Every other format is signed by the
  authenticator or by the hardware holding the key. This one forwards a
  document *Google* composed about the phone: the signature is Google's, the
  claims are Google's, and the only thread back to the registration is a nonce.
  It attests to a **device**, not to where a key lives — so `aaguidVerified`
  stays `false`, an `allowedAaguids` policy is refused rather than being
  silently unenforceable, and SECURITY.md now carries a table of what each
  format actually establishes, because "all seven verified" is the kind of
  sentence that flattens exactly this distinction.

  What is checked: the nonce equals `SHA-256(authData || clientDataHash)`; the
  leaf certificate is issued to `attest.android.com`; the JWS signature
  verifies against it; the chain reaches a root you supply; the response is
  recent, and not timestamped in the future; and `ctsProfileMatch` is true.

  Two of those deserve their reasoning stated. **`ctsProfileMatch`, not
  `basicIntegrity`** — a rooted or bootloader-unlocked phone can still report
  `basicIntegrity: true`, so accepting on that would accept precisely the
  device the check exists to catch. And **RS256 only**: a JWS header names its
  own algorithm, which is the shape every algorithm-confusion attack is built
  on. Google's attestation service signs with RSA, so the allowlist has exactly
  one entry and the header has nothing left to negotiate.

  24 tests, including the nonce from another ceremony, a certificate issued to
  another host, a device failing CTS while reporting `basicIntegrity`, a
  response captured 40 minutes earlier, one timestamped in the future, four
  algorithm substitutions, and 300 random byte strings in the `response` field
  asserting that none of them produces anything but a controlled refusal.

- **Android Keystore attestation — WebAuthn §8.4.** Android platform
  authenticators, and the last of the formats that is not deprecated.

  The signature is over the ceremony the way `packed`'s is, and the attestation
  certificate holds the credential key. On its own that says only that whoever
  holds the credential also holds a certificate — which is what any self-signed
  chain can say. The proof is in an extension Keystore writes into the
  certificate it issues, and reading it is the whole job:

  - `attestationChallenge` must equal this ceremony's `clientDataHash`. The
    challenge is fixed when the key is *generated*, so a certificate carrying
    this hash is one Keystore minted for this registration and could not have
    minted earlier.
  - `allApplications` must be absent from both authorization lists. A key
    marked usable by every application on the device is not scoped to this
    relying party, and a credential another app can sign with is not a
    credential.
  - `origin` must be `KM_ORIGIN_GENERATED` and `purpose` must include
    `KM_PURPOSE_SIGN`: the key was generated inside the keystore rather than
    imported into it, and it is a signing key.

  **The list those are read from is a security decision, and the default is the
  strict one.** Keystore states a key's properties twice — once as the Android
  OS enforces them, once as the secure hardware does — and §8.4 permits reading
  either. Ninsho reads `teeEnforced`. A software-enforced authorization list is
  the operating system vouching for itself, and if the OS's word were enough
  there would be no reason to be doing attestation at all.
  `allowSoftwareEnforcedAndroidKey: true` opts into the looser reading for
  emulators and devices without a TEE; what comes back is then not a hardware
  claim and should not be recorded as one.

  Reading the extension needed one change to the DER reader: Android puts
  `allApplications` and `origin` at context tag numbers 600 and 702, which DER
  writes across several bytes, and the reader previously refused that form
  outright. It now decodes it, bounded to three groups, with the minimal-length
  rules enforced as everywhere else — and `Tlv` gained a `number` field so a
  caller can tell `[600]` from `[702]` at all.

  With this, `@ninsho/webauthn` verified `none`, `packed`, `apple`, `tpm`,
  `fido-u2f` and `android-key`; `android-safetynet` followed, and is the entry
  above.

- **TPM attestation — WebAuthn §8.3.** Windows Hello's path, and the format
  that takes the most care to get right.

  `packed` signs `authData || clientDataHash` directly. A TPM signs neither the
  ceremony nor the credential key: it signs a `TPMS_ATTEST` describing a key it
  certifies, and the tie back to the registration runs through two indirections
  that both have to hold — `certInfo.extraData` hashes
  `authData || clientDataHash`, and `certInfo.attested.name` is
  `nameAlg || digest(pubArea)`. On top of those, `pubArea` has to describe the
  credential key the browser sent.

  Skip any one of the three and a genuine TPM signature ends up vouching for
  something no TPM attested to. All three are checked, along with §8.3.1's
  requirements on the attestation identity key certificate: empty subject,
  `tcg-kp-AIKCertificate` extended key usage, not a CA. Trust anchors are
  mandatory, as for every other chain format.

  Both structures are packed big-endian binary arriving from a browser, so
  every length is bounds-checked before it drives a read and anything the
  parser does not recognise is refused rather than skipped. SHA-1 is a
  permitted TPM `nameAlg` and is refused here: a name is a hash whose only job
  is to identify one key, which is exactly where a collision would pay.

  Writing the tests found a real bug in the implementation. Node reports an
  empty distinguished name as `undefined` rather than `''`, so reading
  `.subject.trim()` threw a `TypeError` on precisely the certificate shape
  §8.3.1 mandates — every genuine Windows Hello registration would have failed
  with "the attestation was not acceptable". The test that caught it is the one
  asserting the happy path, which is the argument for writing that test even
  when the code looks obviously right.

- **FIDO U2F attestation — WebAuthn §8.6.** What CTAP1 security keys produce:
  most YubiKeys older than CTAP2.

  The plainest of the formats. One ECDSA signature over
  `0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F`, naming
  the credential outright rather than through the indirection TPM attestation
  carries. The leading zero byte is a reserved constant rather than padding: it
  is what keeps the statement from being replayable as a U2F *authentication*
  response, which is signed over a structure with a different first byte. The
  credential key is converted back out of COSE into the raw uncompressed point
  U2F signed over, because U2F predates COSE.

  §8.6's fixed rules are enforced rather than negotiated: exactly one
  certificate in `x5c`, P-256 for both the attestation certificate and the
  credential key. There is no `alg` field in this statement to be talked out
  of, and there should not be one in the implementation either.

  What the format does not carry is an AAGUID — U2F has no model identifier and
  the browser zeroes the field. So a verified U2F statement proves the
  credential lives on hardware a trusted root vouched for and proves nothing
  about *which model*. `aaguidVerified` stays `false`, and pairing the format
  with `allowedAaguids` is refused outright: "0000… is not on the allowed list"
  would be true and would send a caller off to add zeroes to their allowlist.

  With these two, `@ninsho/webauthn` verified `none`, `packed`, `apple`, `tpm`
  and `fido-u2f`; `android-key` and `android-safetynet` followed, and are the
  entries above.

- **An attestation panel in the playground.** The newest and least intuitive
  part of the library was the part the demonstration site did not show. Pick a
  format and a scenario, and the server runs a genuine ceremony — real key
  pair, real certificates, real signature — through the shipped verifier and
  prints what it concluded.

  The scenarios are the point. The roots are minted by the demo process, which
  is exactly why **no trust anchors** is the one worth trying: the chain is
  genuine, the signature verifies, and the ceremony is refused anyway, because
  a chain checked against no root proves nothing. The wrong root and a flipped
  signature byte are there for contrast — and `apple` has no signature to flip,
  which is itself the thing to notice about that format. `android-key` is
  offered so a visitor can watch allowlisting an unverifiable format still fail
  closed.

  The panel states its expectation before it reads the verdict and reports
  whether reality matched, rather than narrating whatever happened as correct.
  A page printing "refused, as expected" over an acceptance would be reassuring
  visitors with the opposite of the truth, so the two are asserted against each
  other in the tests as well.

- **Apple Anonymous Attestation — WebAuthn §8.8.** Touch ID and Face ID, which
  is a large share of real passkey users and the platform authenticators most
  people actually have.

  The format has no signature field, which looks alarming until you see what
  replaces it: the credential certificate itself carries a nonce equal to
  `SHA-256(authData || clientDataHash)`, placed there by Apple when it issued
  the certificate for *this* ceremony. Same binding strength, arriving
  differently — a certificate from another ceremony carries another nonce and
  is refused.

  Two checks matter and one of them is easy to skip. The nonce ties the
  certificate to the ceremony; the certificate's **subject public key must be
  the credential's public key**. Without the second, a genuine Apple
  certificate could be presented beside a credential key an attacker controls
  and every other check would still pass. There is a test that builds exactly
  that — right nonce, wrong key — and asserts it is refused.

  Trust anchors remain mandatory, for the same reason as `packed`: a chain
  checked against no root proves nothing. Apple issues these through an
  anonymisation CA, so the chain vouches for the platform rather than for an
  individual device, which is the point — it attests without becoming a
  tracking identifier.

  Still unimplemented at the time and refused rather than rubber-stamped:
  `tpm`, `android-key`, `android-safetynet`, `fido-u2f`. All of them have since
  been implemented; see the entries above.

- **An interactive protocol explorer — `examples/playground`.** The README
  makes claims and each has a test behind it, which is the right evidence for a
  maintainer and the wrong evidence for someone deciding whether to adopt the
  thing. Nobody should have to read `session.test.ts` to believe that a
  replayed refresh token kills a family.

  So the playground runs the real library in-process and shows what happens:
  the credentials handed to the client, the keys written to the store, the
  audit events, and four attacks failing. A `RecordingStore` wraps the real
  store and logs every operation, so each response carries the trace that
  produced it.

  The headline demonstration is one anyone can check: create a session, paste
  the token into the search box, and watch it not appear among the live keys —
  because what was written is `SHA-256(token)`. Verified programmatically as
  well as visually.

  The four attacks are a rotated refresh token replayed (family revoked, with
  `signalMatch: different` identifying the thief as another client), a
  single-character mutation of an access token, a reset link redeemed twice,
  and two reset requests raced — that last one being the case that found a real
  bug earlier in the week.

  One section runs in the visitor's browser rather than on the server, which
  makes it the one nobody has to take on trust: `@ninsho/client` generates a
  non-extractable P-256 key in the page, `exportKey()` throws
  `InvalidAccessError` when you try to steal it, a session binds to its
  thumbprint, a proof signed in the page is accepted, the same proof replayed
  is refused, and the token presented *without* a proof — exactly what a thief
  who exfiltrated it holds — is refused too. The bundle is served from the
  package it was built from rather than copied, so it cannot go stale.

  It also decodes the wire formats byte by byte — offset, width, raw hex, value
  and a sentence on why each field exists. A real WebAuthn ceremony run by the
  virtual authenticator, a PASETO token, a DPoP proof presented twice. The
  parsing goes through the shipped parsers rather than being reimplemented, so
  what a visitor reads is what the verifier saw; a decoder that disagreed with
  the verifier would be worse than none.

  It is tested — 21 cases over real HTTP. A demo does not usually get tests,
  and this one needs them: every panel restates a README claim to an audience
  with no way to check it, so a demonstration that quietly stopped
  demonstrating would be a page telling visitors something untrue while looking
  entirely convincing. The assertions are the claims themselves, including that
  the byte offsets in the anatomy view are the ones the specification gives.

  It deliberately exposes each error's `detail`, which a real deployment never
  sends to a client. Showing it beside the client-facing message is the
  clearest way to make that separation concrete, and it is also exactly why the
  README says not to deploy this one.

- **A Hono adapter — `@ninsho/server/hono`.** The last framework gap the docs
  admitted to. Around 2 KB, importing nothing at runtime; CI asserts both that
  and that it stays out of the main bundle.

  This one is real work where the Fastify adapter was not. A Fastify request
  already satisfies `HttpRequest` structurally, so that adapter only translated
  the reply. Hono differs more: a single `Context` carries both sides, headers
  and params arrive through *functions* rather than properties, and a
  middleware halts by returning a `Response` rather than by writing to an
  object. So this builds a small request view over the context and turns "the
  middleware wrote a response" into "return a Response".

  Getting that translation wrong in the direction of "continue" produces an
  authorization check that logs a denial and then serves the resource anyway.
  Every negative test therefore asserts the route handler did not run, not
  merely that the status was 403 — and runs against real Hono, since a stubbed
  context would confirm my expectations of Hono and nothing else.

  Body access is opt-in (`parseJsonBody`). Most guards need only headers and
  route parameters, and parsing a body nothing reads costs time on every
  request and fails on bodies that are not JSON. Where it is needed — a rate
  limit keyed on an email, `requireOwner` reading a body field — Hono caches
  the parse, so the route handler can still read the body afterwards. A
  malformed body leaves the selector empty and fails its check, which is the
  fail-closed outcome `ValueSelector` already specifies, rather than becoming a
  500.

  The identity lands on the context under a namespaced key rather than a plain
  `auth`, because context variables are shared with every other middleware in
  the application and a collision would silently replace an identity rather
  than fail.

  **It targets Hono on Node** (`@hono/node-server`). `@ninsho/server` depends on
  `ioredis` and Node's crypto, so Workers and Deno are out of reach — said here
  rather than left to be discovered at deploy time.

- **Client signals, and an actionable reuse alarm.** `SecuritySignals` and
  `hashSignal` had been declared since the rebuild and were used by nothing —
  a feature described in the types and never implemented. It is implemented
  now, for the one purpose that justifies storing anything about a client.

  `createSession` and `refresh` accept raw signals — a `User-Agent`, a resolved
  client address. Ninsho hashes them on the way in and stores only the
  truncated digests, so the raw values never reach the store and the privacy
  property is structural rather than a caller's responsibility.

  What that buys: when a rotated refresh token is replayed, the
  `refresh.reuse_detected` event now carries `signalMatch`. A replay from a
  *different* client is close to certain theft; one from the same client is
  more often a retry or a double-submit in the application's own code. Those
  deserve different responses, and an operator previously had no way to tell
  them apart. Absent signals report `unknown` rather than `same` — reporting
  confidence that was never established is worse than reporting none.

  **Nothing branches on them.** Every field is client-controlled and trivially
  forged, so a mismatch never rejects a request: a user moving from wifi to
  cellular changes address mid-session, and if a mismatch caused revocation
  then anyone who guessed a token could also choose the header that revokes it.
  There is a test for exactly that.

  Because the hashes are truncated they support correlation and not display —
  you can tell two sessions came from different clients, not which clients they
  were. If you want "Chrome on macOS" in a sessions list, keep it alongside
  your own record; it is personal data and Ninsho declines to hold it.

  `SessionSummary` exposes them, and the reference API records them on
  registration, login and refresh.

- **Single-use tokens — `auth.oneTimeTokens`.** Password reset, email
  verification, magic links.

  This does not change what Ninsho owns. It issues an opaque token bound to a
  subject and a purpose, and tells you which subject presented it; sending the
  email, setting the password and marking an address verified remain yours.

  It is here because password reset is the most reliably botched flow in
  authentication, and every way of botching it is a full account takeover:

  - a token stored in plaintext, so a database read is a takeover
  - a token that works twice, so a forwarded email is a takeover
  - a token that never expires, so an old inbox is a takeover
  - a reset token accepted by an email-verification endpoint, so the weaker
    flow becomes an entry point to the stronger one
  - an old link that keeps working after a new one was requested

  Each is closed by construction rather than by remembering to close it. The
  token is 256 bits of CSPRNG output, stored only as `hashToken(raw)`; the
  purpose is part of the storage key, so a token for another purpose is not
  rejected but absent; consumption goes through the store's atomic `take`, so
  two simultaneous clicks cannot both win; expiry is checked against the
  recorded timestamp as well as the store's TTL, failing closed on one it
  cannot parse; and issuing a replacement invalidates the subject's previous
  token by default, as OWASP advises.

  Every failure answers identically. "Expired", "already used" and "never
  issued" are one answer to a user and three hints to an attacker probing which
  reset links were real.

  Two audit events come with it — `onetime.issued` and `onetime.consumed`. A
  spike of the first aimed at one account is a takeover attempt; a spike across
  many is email flooding; the second is the moment an account changes hands.

- **A complete password-reset flow in the reference API.** `POST
  /auth/password/forgot` and `POST /auth/password/reset`, with the three things
  that are easy to leave out: the request endpoint is rate-limited per address
  *and* per IP, because without that it is an email-flooding tool pointed at
  your users; it answers identically whether or not the address exists, since
  it needs only an address where login at least demands a password guess; and
  completing a reset revokes every existing session, because whoever forced the
  reset may already hold one.

  `RevocationReason` gains `credential_changed` for that last step —
  distinguished from `administrative` because it is the one an incident review
  looks for.

  18 end-to-end tests over real HTTP, including eight simultaneous clicks on
  one link where exactly one must succeed.

- **A Fastify adapter — `@ninsho/server/fastify`.** The middleware was
  Express-shaped, and the docs said plainly that no adapter existed. One does
  now.

  It is 1.5 KB and imports nothing at runtime — CI asserts both. A Fastify
  *request* already satisfies `HttpRequest` structurally, so `headers`,
  `params`, `query` and `body` need no translation at all, and `verify()`
  attaches `auth` to the same object the route handler receives. Only the reply
  differs, and that is all the adapter converts.

  The part worth getting right is the return convention. Express middleware
  signals "continue" by calling `next()`; a Fastify hook signals "already
  answered" by returning the reply. Translating the first into the second
  wrongly, in the direction of "continue", produces an authorization check that
  logs a denial and then serves the resource anyway.

  So it is tested against real Fastify rather than a stub reply — a stub would
  confirm the author's expectations and nothing else — and every negative case
  asserts the route handler did not run, not merely that the status was 403.

  Hono and Koa still have no adapter, and are still not claimed.

- **`WWW-Authenticate` on 401 responses.** RFC 7235 §3.1 requires it: "The
  server generating a 401 response MUST send a WWW-Authenticate header field
  containing at least one challenge." Ninsho cited that RFC and did not send
  the header.

  The challenge names `DPoP` when the deployment binds tokens (RFC 9449 §7.1)
  and `Bearer` otherwise, so it advertises what would actually be accepted. It
  carries the error *code* and never the `detail`, keeping the same separation
  the response body does — asserted by a strict shape check rather than by
  scanning for words, since the code itself is public.

  A 403 deliberately sends no challenge: that caller authenticated fine and is
  simply not permitted, so inviting them to re-authenticate would be wrong
  advice.

- **Step-up authentication — `requireFreshAuth()`.** Some operations should
  need more than a live session: changing an email address, adding a passkey,
  moving money. OWASP ASVS asks for re-authentication before them, and until
  now Ninsho gave you no correct way to express it.

  ```ts
  app.post('/account/email', auth.verify(), auth.requireFreshAuth(300), handler);
  ```

  The reason this needed a new field rather than a new middleware alone is
  worth stating, because the obvious implementation is wrong in a way that
  looks right. Comparing `AuthContext.issuedAt` against the clock reads like a
  freshness check and is not one: rotation mints a new access token every few
  minutes for as long as a session lives, so on a session refreshed for thirty
  days `issuedAt` is always minutes old. A check built on it passes for
  everyone, forever, while appearing in the code as a real control.

  So `AuthContext` now carries `authenticatedAt`, fixed when the session is
  created and propagated unchanged through every rotation — including the grace
  path, where a parallel tab adopting a replacement is likewise not a new
  authentication. Refreshing can never satisfy the check. Only
  re-authenticating and starting a new session can, which is the point.

  In paseto mode it travels as `auth_time`, matching OIDC's claim of the same
  meaning. It is validated as a required string on the way in: a record that
  cannot say when the user authenticated is refused rather than being given the
  benefit of `issuedAt`, because substituting that would look harmless and
  silently make every step-up check wrong.

  **Breaking for anyone tracking `main`:** access and refresh records written
  before this change lack the field and are refused, so a deploy signs existing
  sessions out. Nothing is published, so this affects no released version.

- **WebAuthn attestation — `packed`, verified to roots you supply.** A normal
  passkey ceremony proves someone controls a private key. Attestation proves
  the key was generated inside a particular piece of hardware, vouched for by a
  chain the manufacturer signed. That is the difference between "a credential"
  and "a credential on an issued YubiKey", and it is the only way to express a
  policy like "company laptops authenticate with issued hardware".

  Configuring an attestation policy also changes what the browser is asked for:
  the ceremony switches to `direct` conveyance automatically, because a browser
  asked for `none` replaces the statement and there would be nothing left to
  verify. Two settings that must agree are two settings that will not, so there
  is only one.

  **Trust anchors are mandatory.** `packed` is refused outright without them. A
  chain checked against no root proves nothing — anyone can self-sign a CA and
  put any AAGUID they like in a certificate they issued to themselves — and a
  verifier reporting success there manufactures confidence, which is worse than
  having no attestation support at all. The result is explicit about what was
  established: `attestationType` is `none`, `self` or `basic`, and
  `aaguidVerified` is true only when a trusted chain vouched for the AAGUID.

  Also refused: a CA certificate presented as the attestation leaf (§8.2.1, it
  could sign for other authenticators), a certificate whose AAGUID contradicts
  the authenticator data (a statement lifted from another device), an expired
  certificate anywhere in the chain, and self-attestation unless explicitly
  enabled — it establishes no provenance, so an AAGUID allowlist against it is
  refused rather than silently meaningless.

  X.509 parsing, signature verification and issuance checks go through Node's
  vetted `X509Certificate`. The only thing written here is a walk to find one
  extension by OID, because the AAGUID lives in a custom one Node does not
  expose — hand-rolling a certificate parser would be inventing exactly the
  primitive this project refuses to invent.

  Not implemented when `packed` landed, and refused rather than
  rubber-stamped: `tpm`, `android-key`, `android-safetynet`, `apple`,
  `fido-u2f`. All of them have since been implemented; see the entries above. No root store ships with the package and FIDO Metadata Service
  integration is not implemented — which manufacturers you trust is an
  operational decision, not library content.

- **A certificate builder for tests, in `@ninsho/webauthn/testing`.**
  Attestation needs real certificate chains to test against. Committed fixtures
  expire, and shelling out to `openssl` makes the suite depend on a CLI that
  differs by platform — on this repo's own Windows checkout `req -x509` mangles
  the subject through mingw path conversion while CI's Linux openssl does not.
  So the chains are built in TypeScript, and every certificate produced is
  cross-checked by Node's own `X509Certificate`: if the encoder were wrong,
  that parser would reject its output.

- **The security invariants now run against real Redis, not just a Map.**
  `store.contract.test.ts` already proved the two stores agree about
  primitives. What was never checked is whether the *engine* invariants built
  on those primitives survive a store that lives across a socket.

  That gap mattered more than it looks. Against `MemoryStore` every operation
  completes synchronously inside one tick, so an interleaving production hits
  constantly can be unreachable locally — and the code most exposed to it is
  the code where a rotation can slip past a revocation.

  `store-invariants.test.ts` runs sixteen invariants against every available
  store: single-use refresh consumption, one replacement chain from forty
  concurrent callers, reuse detection revoking the family, the grace window not
  raising false alarms, DPoP `jti` replay, rate-limit accuracy under
  concurrency, and sign-out-everywhere at scale. The most important is the
  revocation-racing-rotation regression, run twelve times per store, because
  that one was a real bug.

  Three more run only against Redis, since a Map in the same process cannot be
  unreachable: an unreachable store must reject rather than read as "under the
  limit", must refuse a DPoP proof it cannot check for replay, and must report
  itself unhealthy rather than throwing.

  Every invariant held against Redis 7.4.8 on the first run. No bugs found —
  which is the result worth having, and one that could not have been claimed
  before.

- **`@ninsho/webauthn/testing` — a virtual authenticator.** Testing a passkey
  integration otherwise means a physical authenticator and a human finger,
  which is to say it does not get tested. `VirtualAuthenticator` holds a real
  key pair and produces genuinely signed responses, so an end-to-end test
  exercises the real verifier against real signatures rather than a stub
  agreeing with itself.

  It is a separate entry point, so it never reaches an application bundle that
  only imports the verifier — asserted by test. It also refuses to construct
  under `NODE_ENV=production`, following the `MemoryStore` precedent: a test
  double may ship as long as it must be named explicitly and cannot be selected
  by an environment variable. That guard matters more here than it does for
  `MemoryStore`, because a virtual authenticator running server-side means the
  *server* holds the credential's private key — WebAuthn defeated, quietly,
  while every signature still verifies.

- **Passkeys in the reference API.** `examples/express-api` now demonstrates
  the whole flow: adding a passkey to an existing account, listing credentials,
  and usernameless sign-in that ends in an ordinary Ninsho session.

  The points worth copying are the ones easy to get wrong. Registration
  requires a session and is bound to the signed-in user, because adding a
  passkey is adding a new way into the account. The sign counter is written
  back after every success, without which clone detection silently stops
  working — the check still runs, always against the same stale number. An
  unknown credential id answers exactly as a bad signature does, so the
  endpoint does not become an oracle for which credentials exist. And roles
  come from the directory, never from the passkey: WebAuthn proves who, not
  what they may do.

  29 new end-to-end tests, 72 in the example overall.

- **`@ninsho/webauthn` — passkey registration and authentication.** No
  third-party dependencies; depends only on `@ninsho/core`, which has none
  either.

  WebAuthn establishes *who someone is* and stops there, so the package
  produces a `Principal` you hand to `createSession()`. That boundary is what
  lets a passkey, a password and an OIDC login all end at the same place, with
  one session implementation behind them rather than three.

  Everything on the untrusted path is parsed here rather than delegated: a CBOR
  decoder restricted to definite lengths (no tags, no indefinite lengths, no
  floats — the constructs where CBOR parsers historically grow their
  vulnerabilities, and which CTAP2 canonical CBOR forbids anyway), a strict DER
  reader for ECDSA signatures, COSE key import, and WebAuthn §6.1 authenticator
  data. Each bounds-checks every length before using it, and each is fuzzed to
  confirm no input escapes its own error type.

  Correctness rests on outside evidence, not self-agreement: the CBOR decoder
  is checked against **RFC 8949 Appendix A** vectors, and the DER converter
  differentially against 200 signatures produced by OpenSSL through
  `node:crypto` and verified by WebCrypto — two implementations that know
  nothing about this code.

  Three things are worth calling out specifically:

  *Algorithm confusion is closed structurally.* A COSE key states its own type,
  curve and algorithm, all of it attacker-supplied. The algorithm must be on a
  relying-party allowlist, and the key type must match it — an EC2 key labelled
  RS256 is refused rather than coerced. At assertion time the algorithm comes
  from the stored key, never from the request.

  *WebCrypto's validation is uneven, so the gaps are filled here.* It rejects an
  off-curve P-256 point but imports a 512-bit RSA modulus without complaint —
  factorable on a laptop. A 2048-bit floor is enforced, measured in significant
  bits so a padded short modulus cannot slip through. Both facts are recorded as
  tests, so if a future Node starts rejecting these on its own, the test says the
  check became redundant rather than the check quietly protecting nothing.

  *Challenges are single-use and scoped by construction.* Consumption goes
  through the store's atomic `take()`, and the ceremony type is part of the
  storage key rather than a field compared afterwards — a registration challenge
  replayed at an authentication endpoint is not rejected, it is simply not
  there. A check can be forgotten in a later refactor; a key that does not exist
  cannot be.

  `WebAuthnServer` wires the two together and consumes the challenge *before*
  verifying, so a failed attempt still burns it and cannot be ground against.
  Getting that order wrong in either direction is a real vulnerability, so it is
  written once rather than in every application.

  **Attestation is not verified, and this is stated rather than implied.** Only
  the `none` format is accepted, and adding another to
  `allowedAttestationFormats` does not change that — there is no arrangement of
  options that turns an unverified attestation into a verified one. Verifying
  `packed`/`tpm`/`android-key`/`apple` means X.509 chains and root stores, and a
  verifier that parses an attestation statement without checking it is worse
  than one that refuses it. Passkeys are unaffected.

  318 tests.

- **`@ninsho/client` — the browser half of DPoP.** Zero dependencies, Web APIs
  only.

  The key is generated **non-extractable**: `crypto.subtle.exportKey` on it
  throws, and there is no other route to the bytes — including for script an
  attacker injects. That is the whole reason browser DPoP is worth having. A
  bearer token is a string an XSS copies and uses indefinitely; a DPoP key
  cannot leave the browser, so an attacker is reduced to signing proofs while
  they still have execution. It does not make XSS harmless — it makes stolen
  credentials non-portable.

  Also handled: the access token held in memory only (never `localStorage`),
  IndexedDB persistence because it is the only browser storage that can hold a
  `CryptoKey` handle, a fresh proof per request, and automatic refresh on 401.

  Refresh and key initialisation are both **single-flight**. Six requests
  hitting an expired token would otherwise start six refreshes, and under
  rotation five of them present a token another has already rotated — which the
  server correctly reads as theft. A normal page load would look like an attack.

  Client and server are tested **against each other** rather than each against
  its own assumptions: thumbprints compared across both implementations, and
  client-generated proofs verified by the server's real verifier.

- **Proof-of-possession — `binding: 'dpop'` (RFC 9449).** Access and refresh
  tokens can now be bound to a key the client holds privately, with a fresh
  signed proof required on every request. A stolen token alone becomes useless.

  This closes the one limitation the security policy previously listed as
  unmitigated with "no configuration changes this".

  - ES256 and EdDSA proofs, on an **allowlist**. A DPoP proof is a JWT, so the
    whole algorithm-confusion family applies — the class PASETO was chosen to
    avoid for Ninsho's own tokens. `alg: none` and every symmetric algorithm
    are refused, the latter because the "public" key sits in the header and
    would otherwise serve as an HMAC secret.
  - RFC 7638 thumbprints, verified against the specification's own worked
    example.
  - Single-use proof identifiers (RFC 9449 §11.1), so a captured proof cannot
    be replayed within its acceptance window.
  - Refresh tokens bound too (RFC 9449 §5) — otherwise the longest-lived
    credential would be the one piece with no proof-of-possession.
  - `createDpopProof` / `generateDpopKeyPair` for Node clients and tests.
    Browsers should use WebCrypto with a non-extractable key, which is the
    property that makes DPoP worth having there.

  Opt-in, because enabling it is a breaking change for clients.

### Fixed

- **The rate limiter resolved the wrong client address, off by one hop.**
  `clientIp` read the chain at `chain.length - 1 - trustProxy`. It should be
  `chain.length - trustProxy`: each trusted proxy appends the address it
  received the request from, so `n` proxies contribute the last `n` entries and
  the client is the one just before them.

  One position is enough to produce **both** of the failure modes that module
  was written to prevent, and which one you got depended on your deployment.

  Behind a single proxy — the ordinary case — the chain holds one entry, the
  index ran off the start, and the resolution fell back to the peer address:
  the proxy's own. Every user of the service in one bucket, so five failed
  logins from anyone locked out everyone.

  And with anything prepended, the index moved onto an entry the client had
  supplied. Rotating one header minted a fresh allowance per request, which is
  the limiter counting nothing at all.

  The existing test passed because it used a three-entry chain where the index
  happened to land on an honest value, and its comment mislabelled which entry
  was the client. Corrected, with two regression tests written from the
  deployment rather than from the code: the single-proxy case must resolve to
  the client and not the proxy, and prepending onto a one-entry chain must not
  shift the result.

  `trustProxy: 0` now explicitly means what `false` means — no proxy is
  entitled to speak for the client, so the header is not read.

  Found by building the playground's rate-limit panel: the demonstration showed
  five separate buckets and refused nothing, while its own prose said the
  opposite.

- **An `Asn1Error` could escape `parseKeyDescription`.** The function's contract
  is that it throws `AndroidKeyError`; the DER walk through an authorization
  list was not wrapped, so a malformed list threw the reader's own error type
  straight out.

  Inside the ceremony this was contained — `verifyAndroidKeyAttestation`
  catches anything that is not an `AndroidKeyError` and reports a generic
  refusal — so no registration could crash on it. But `parseKeyDescription` is
  exported for applications that want to report what the keystore said about a
  credential, and one of those, catching the documented type, would have taken
  an uncaught throw instead.

  Found by adding the mutation fuzzer the other parsers already had: flipping
  byte 54 of a valid structure. Random-bytes fuzzing had not found it and would
  not have, because random bytes almost never form a structure the parser gets
  deep enough into to reach a nested list.

- **The benchmarks had not run since step-up auth landed.** `issue()` gained a
  required `authenticatedAt`, `bench.ts` kept calling it the old way, and the
  script threw on its first `verify` — "stored access record is malformed" —
  for weeks.

  Nothing caught it because nothing ran it. Meanwhile PERFORMANCE.md carried
  the figures it had produced before the break, presented as current, which is
  the same failure this project was rebuilt to avoid: a claim outliving its
  evidence.

  Fixed, re-measured, and PERFORMANCE.md updated throughout. Both benchmark
  scripts now run in CI — not as a performance gate, which would be flaky on
  shared runners, but as a check that the documented figures can still be
  reproduced by the command the documentation tells you to run.

  The refresh also adds a table nobody had published: the same operations
  against a real Redis. `session: refresh` is 16,512/sec against `MemoryStore`
  and **211/sec** across loopback Redis. The first table measures this
  library; the second measures what a deployment actually experiences, and the
  distance between them is the honest answer to "how fast is it".

- **A repeated `Authorization` header was accepted, not refused.** The README
  claimed ambiguous duplicates were rejected, and the code had a check for it.
  The check could not fire.

  Node's HTTP server does not join duplicate `Authorization` headers the way it
  joins ordinary ones — it keeps the **first** and silently discards the rest.
  Measured, once the question was actually asked: two headers on the wire,
  `rawHeaders` shows both, `req.headers.authorization` shows one clean
  credential. The guard tested `Array.isArray(headers.authorization)`, a shape
  Node never produces, and the existing test constructed that array by hand
  rather than sending a request. So the check passed its test and protected
  nothing.

  This is the desync the check exists to prevent: a proxy that validates the
  last occurrence and an application that reads the first disagree about who is
  calling.

  `HttpRequest` now carries an optional `rawHeaders`, and `extractBearer`
  counts occurrences there before trusting `headers`. Two credentials joined
  into one value — what a proxy that concatenates produces — are refused too,
  before the greedy scheme capture can swallow the second into the token and
  turn an ambiguous request into a merely invalid one.

  Express passes Node's request straight through, so it needed nothing; the
  Fastify and Koa adapters copy `raw.rawHeaders` across. **Hono cannot be
  fixed this way** and is now documented rather than covered: it hands over
  headers already collapsed, so on `@hono/node-server` the duplicate is gone
  before Ninsho sees it.

  Found while writing the Koa adapter's tests, by sending a real request
  instead of assuming what one would look like.

- **The test certificate builder emitted invalid DER about once in 512.** A
  DER INTEGER may not carry a leading zero byte that is not needed for its
  sign. The builder added the zero when the high bit was set — the half of the
  rule everyone remembers — but never trimmed one that was already there, and
  certificate serial numbers are eight random bytes, so roughly one in 256
  began with a zero and about half of those were then unencodable.

  Measured before the fix: **9 invalid certificates out of 4,000** generated.
  After: **0 of 4,000.**

  The reason it went unnoticed for so long is the reason it is worth writing
  down. The failure did not surface in the builder or its tests. It surfaced as
  `an x5c entry is not a valid certificate` from whichever attestation test
  happened to draw the unlucky serial that run — a message that reads as the
  verifier rejecting a chain, which is exactly what a verifier is supposed to
  do. With a hundred-odd attestation tests each minting two or three
  certificates, a full run failed somewhere most of the time, and never twice
  in the same place. It looked like flakiness in the concurrency tests it
  happened to land near.

  `createCertificate` now takes a `serialNumber`, so the encoding edge cases
  are exercised on purpose rather than waited for: a leading zero, two leading
  zeros, a set high bit, a required leading zero before a set high bit, and
  zero itself. Three consecutive full-suite runs, 1,756 tests each, are clean.

- **A signed-out tab waited out the full rotation-race backoff.** The tombstone
  wait exists so a browser's second tab, having lost a rotation race by
  microseconds, is handed the winner's replacement instead of a spurious sign
  out. Its exponential backoff totals ~126ms, and that budget was charged to
  any token with no tombstone.

  Revocation deletes the live record, the tombstone and the grace mapping, so a
  token from a session that was deliberately ended looked exactly like a forged
  one and paid the same 126ms — and then got "no record for presented refresh
  token", which is also the wrong answer. The session did exist; it was signed
  out.

  That is the wrong trade for a routine event. After a sign-out-everywhere,
  every tab still holding a token pays it, each occupying a request slot for
  the duration.

  Revocation now leaves a small marker per refresh hash in place of the records
  it deletes, written before them for the same ordering reason the session
  tombstone is, and the wait is skipped when the marker is present: a family
  that was deliberately ended has no rotation in flight to wait for. Measured
  on the two concurrency suites that surfaced it, 40 sequential
  post-revocation refresh attempts went from over five seconds — a test
  timeout — to well inside it.

  The full backoff still applies to a genuinely unrecognised token, which is
  the case it was written for.

- **"Issuing a token invalidates the previous one" did not hold under
  concurrency.** Invalidation swept a per-subject index of outstanding token
  hashes. Two concurrent `issue` calls each read that index before the other
  wrote to it, so neither saw the other's token and *both* stayed valid —
  measured at 80 of 80 across 40 races.

  The practical exposure was small: both links land in the same inbox, and an
  attacker who triggers two resets receives neither. What was wrong is that the
  guarantee had been documented as one, which is the kind of overclaim this
  project exists to avoid.

  Replaced with an atomic generation counter. `increment` gives two concurrent
  issues distinct generations; the token stamped with the older one no longer
  matches and consumption refuses it. The new design is also simpler and
  cheaper — revoking everything outstanding is a single increment rather than a
  bounded fan-out over a set, and there is no longer a per-subject index of
  token hashes to store at all.

  If the counter lapses while a token is still live the generations disagree
  and the token is refused, so that failure lands closed too. Its TTL is set
  well beyond the longest token to keep it from arising.

  The regression test runs the race twenty-five times and asserts exactly one
  survivor. Found by adversarial review, not by a failing test.


- **Two separate `toHono()` calls did not compose.** Each call builds its own
  request view over the Hono context, so an application written the way Hono
  applications usually are —

  ```ts
  app.use('/admin', toHono(auth.verify()));
  app.use('/admin', toHono(auth.requireRole('admin')));
  ```

  — gave the second call no identity to read. `getAuth` threw and a correctly
  written application got a 500.

  It failed closed, which is the right direction, and the chained form
  (`toHono([verify, requireRole])`) always worked. But the composition a Hono
  user would naturally reach for was broken, and the suite had only ever
  exercised the chained form.

  The request view is now seeded from the context, so the two forms behave
  identically. Fastify never had the equivalent problem because there the
  framework's own request object *is* the `HttpRequest` and `auth` persists on
  it. Found by adversarial review rather than by a failing test, which is why
  four regression tests now cover it — including that the fix does not turn the
  composition into one that always passes, does not leak an identity between
  requests, and still refuses a guard mounted without `verify()` ahead of it.


- **Parallel tabs were spuriously signed out under a real store.** A caller
  that loses a refresh rotation race waits briefly for the winner to publish
  its tombstone, then adopts the same replacement — that wait is what stops a
  parallel-tab page load from looking like token theft.

  The wait was a flat 3 x 5ms. That ceiling was tuned against `MemoryStore`,
  where the winner's follow-up writes complete inside a single tick, and it is
  far too tight for a store that lives across a socket. Losers gave up before
  the winner had published and reported `no record for presented refresh
  token`, which is a sign-out for a user who did nothing wrong.

  Measured against a local Redis before the fix: a rotation race takes 14ms at
  the median with two callers and 45-85ms with forty. Spurious rejections
  appeared in 1 of 20 rounds at a concurrency of 40, and 5 of 20 — a quarter of
  attempts — at 100.

  Replaced with exponential steps of 2, 4, 8, 16, 32 and 64ms, totalling about
  126ms. The loop still returns the instant the tombstone appears, so the
  common case got *faster* rather than slower: the median at low concurrency
  improved from 14.5ms to 8.3ms, because the first step is now 2ms rather than
  5ms. After the change, 0 spurious rejections across all 100 measured rounds.

  The cost lands only on a token that never had a tombstone — genuinely unknown
  or forged — which now occupies a request for up to ~126ms before being
  refused. That is bounded, and the refresh endpoint should be rate-limited
  regardless.

  Found by running the engine invariants against real Redis rather than against
  a Map, which is exactly what that suite was added for. The regression test
  now runs the race at a concurrency of 100 and asserts no rejections at all.

- **Every async route in the reference API dropped its errors.** Express 4 does
  not catch a rejection from an `async` handler. A failing route — a store
  outage on `/auth/logout`, a rejected passkey ceremony, a degraded `/health`
  — produced an unhandled rejection and *no response at all*: the error
  middleware never ran, and the client waited until it timed out. A monitoring
  dashboard would show a timeout rather than the 400 or 503 that actually
  happened, which is the difference between a bug you can diagnose and one you
  cannot.

  Found by the new passkey tests, which asserted a 400 on a rejected ceremony
  and got an unhandled rejection instead. It affected `/auth/login`,
  `/auth/logout`, `/auth/logout-all`, `/auth/sessions` and `/health` as well,
  all of which had the same shape and none of which had a test that made them
  throw.

  Fixed with a single `route()` wrapper applied to all eleven async handlers,
  rather than a `try`/`catch` remembered at each call site — the latter is the
  version that is correct on the day it is written and wrong after the next
  route is added.

- **Concurrent first requests each generated their own client key.** Ten
  callers arriving before a key existed each found none, each generated one, and
  each wrote it — last write wins. Requests already in flight would then sign
  proofs with a key the store no longer held, and a session bound to a discarded
  key is broken with nothing in the logs to explain it. Key initialisation is
  now single-flight, like refresh.

- **Non-canonical base64url was accepted in DPoP proofs.** The segment check
  verified only the character set, not canonicality. Node's decoder ignores the
  spare bits in a segment's final character, so a 64-byte ECDSA signature had
  sixteen distinct spellings that all decoded to identical bytes and all
  verified — one proof with many textual forms, which breaks anything treating
  the proof string as an identity. The PASETO parser already rejected this; the
  DPoP one now does too. Found by a mutation test, which surfaced it as an
  intermittent failure before the cause was understood.

- **Two flaky tests, both fixed at the source rather than by loosening them.**
  A wall-clock assertion on parallelism now observes task overlap instead of
  elapsed time, and the rate-limit window-boundary test controls the clock
  rather than racing it. A flaky test of a security property is worse than no
  test, because it trains people to re-run rather than investigate.

- **A rejected DPoP proof could destroy a session.** The binding was checked
  inside `#rotate`, which runs after the atomic `take()` that consumes the
  refresh token. An attacker holding a stolen refresh token — but not the key —
  could therefore end the session simply by presenting it: the token was
  consumed, the rotation then failed, and the legitimate client's next refresh
  found nothing. A denial of service handed to precisely the party the binding
  exists to shut out. The binding is now checked before the token is consumed.

- **Revocation could lose a race against rotation.** `#revokeFamily` worked by
  enumerating the family index and deleting what it found. A rotation running
  concurrently could add its replacement to that index *after* revocation had
  read it; revocation then deleted the index, leaving a live refresh record
  that nothing pointed to. No later revocation could find the orphan either, so
  a refresh token survived a completed logout for its full lifetime — a "sign
  out this device" button reporting success while a credential stayed usable.

  Fixed with a positive session tombstone written *before* the index is read
  and consulted by rotation, so the outcome no longer depends on which
  operation touched the index first. Found by the new concurrency suite; no
  sequential test could have surfaced it.

- **`revokeAllForUser` and `listSessions` were latency-bound.** Both walked
  their sessions serially — around 4,500 store round trips for a user with 500
  sessions, never more than one in flight, which is seconds against a real
  store. "Sign out everywhere" is what gets invoked during an incident, and one
  that slow risks timing out partway and leaving sessions live.

  Both now use bounded parallelism (pool of 16): ~282 effective serial steps
  instead of ~4,500, with fan-out capped so a user with very many sessions
  cannot exhaust the connection pool. A failure on one session no longer
  abandons the rest of the sweep.

- **Token lifetimes were off by up to a millisecond.** `issuedAt` and
  `expiresAt` were derived from two separate clock readings, so a tick between
  them made the recorded lifetime differ from the configured TTL. Both now
  derive from one captured instant.

## [0.1.0] — 2026-09-01

First release of Ninsho. **Not published to npm.** Pre-release: the API may
change, and the library has not been independently audited.

Ninsho supersedes `@secureauth/server@1.0.2`, which remains on npm unmaintained
and should not be used. It is a ground-up rebuild rather than a rename — the
package name is different, so there is no upgrade path and none is owed.

### Added

**Core** (`@ninsho/core`, zero runtime dependencies)
- Strategy-agnostic type surface, compiled under `strict` with
  `exactOptionalPropertyTypes` and `noUncheckedIndexedAccess`.
- Error taxonomy with HTTP status mapping, where diagnostic `detail` is
  structurally separate from the client-facing `message`.
- CSPRNG identifiers and tokens, constant-time comparison, and time predicates
  that fail closed on unparseable input — all on `node:crypto`.

**Storage**
- `NinshoStore` interface, injected rather than constructed internally.
- `RedisStore` (Redis 6.2+, for `GETDEL`) and `MemoryStore`, which refuses to
  construct under `NODE_ENV=production` with no opt-out.
- One contract suite executed against both, so they cannot drift apart.

**Token strategies**
- `opaque` (default) — 256-bit random tokens, all state in the store. No signing
  keys exist. Revocation is native and immediate.
- `paseto` — PASETO v4.public, Ed25519, `kid` in the footer, required `iss` and
  `aud`. Key sets with a rotation overlap window, so rotation forces no
  sign-outs.
- PASETO v4.public implemented on `node:crypto` and verified against the
  specification's official test vectors — all three `4-S-*` cases, both verified
  and reproduced byte for byte.

**Sessions**
- Refresh-token rotation, made race-free by an atomic `take` rather than a lock.
- **Reuse detection**: replaying a rotated token revokes the entire family and
  emits `refresh.reuse_detected` (RFC 9700 §4.14.2).
- A grace window so parallel browser tabs are not signed out by a lost race.
- `familyExpiresAt`, a hard ceiling fixed at creation that rotation never
  extends.
- Session listing and sign-out-everywhere.

**HTTP and authorization**
- Framework-agnostic middleware, typed structurally — Express `Request` and
  `Response` satisfy it with no Express dependency.
- `verify`, `requireRole`, `requireAllRoles`, `requireScope`, `requireTenant`,
  and `requireOwner` — the last closing OWASP API Security #1.

**Rate limiting**
- Sliding-window counter with per-IP **and** per-account buckets, the second of
  which is what catches distributed credential stuffing.
- `trustProxy` with no default; a limiter cannot be constructed without one.

**Operations**
- `Ninsho` facade: `new Ninsho({ store })` is a complete configuration.
- Pluggable audit sink, wrapped so a throwing implementation cannot fail an
  authentication.
- Startup `config.insecure` events for every accepted-but-weakening choice.

**Project**
- 600 tests. CI gates `npm ci`, lockfile drift, typecheck, build, tests against
  real Redis, `npm audit`, and bundle purity.
- Reference Express API with end-to-end tests over real HTTP.
- Benchmarks, threat model, and security model.

### Security

Every critical and high finding from the audit of the predecessor is addressed
by design rather than patched:

| Finding | Resolution |
| :--- | :--- |
| C1 — lockfile desync disabled all CI | `npm ci` first, plus a dedicated drift gate |
| C2 — env var swapped the store for a fake | Store injected; bundle purity enforced in CI |
| C3 — refresh reuse undetected | Family revocation and an audit event |
| H1 — expired path used an unsigned decoder | That code path does not exist |
| H2 — UA fingerprint sold as replay protection | Removed; DPoP seam reserved instead |
| H3 — fail-open default | Fail-closed, and rejected where it could not take effect |
| H4 — no key rotation, no `iss`/`aud` | `KeyRing` overlap window; both claims required |
| H5 — rate limiting keyed on a spoofable IP | Per-account bucket and a mandatory `trustProxy` |
| M3 — no authorization primitives | Role, scope, tenant and owner middleware |
| M4 — vulnerable id dependency | Zero dependencies; `node:crypto` directly |
| M8 — library errors leaked to clients | `detail` separated from `message` |

### Known limitations

- **Bearer tokens can be replayed.** Anyone holding a valid access token can use
  it, and no configuration changes that. The `cnf` claim slot and `BindingMode`
  type are reserved for DPoP (RFC 9449); selecting `binding: 'dpop'` throws
  today rather than silently doing nothing.
- One raw token is stored for the grace window (30s default) so a parallel tab
  can adopt a rotated replacement. `refreshGraceSeconds: 0` removes it.
- Reuse detection has a false-positive floor: a client two or more rotations
  stale is indistinguishable from an attacker.
- One accepted low advisory: `GHSA-g7r4-m6w7-qqqr` (esbuild), reachable only via
  `esbuild serve`, which nothing here invokes.

See [SECURITY.md](./SECURITY.md) for the full threat model.
