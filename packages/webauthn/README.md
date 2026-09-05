# @ninsho/webauthn

Passkey registration and authentication verification for Node.js. No third-party dependencies.

WebAuthn establishes **who someone is**, and stops there. Sessions, tokens, revocation and
authorization are [`@ninsho/server`](../server)'s job. So this package produces a `Principal`, and
you hand that to `createSession()`:

```ts
const result = await webauthn.finishAuthentication(response, credential);
const tokens = await auth.createSession(result.principal);
```

Keeping the boundary there is what lets a passkey, a password and an OIDC login all end at the same
place, with one session implementation behind them rather than three.

## Install

```bash
npm install @ninsho/webauthn
```

## Usage

```ts
import { WebAuthnServer } from '@ninsho/webauthn';
import { MemoryStore } from '@ninsho/server';

const webauthn = new WebAuthnServer({
  rpId: 'example.com',
  rpName: 'Example',
  origin: 'https://example.com',
  store: new MemoryStore(), // use RedisStore in production
});
```

### Registration

```ts
// 1. Start — issues a single-use challenge and returns browser-ready JSON.
app.post('/webauthn/register/start', requireLogin, async (req, res) => {
  const options = await webauthn.startRegistration({
    userId: req.auth.userId,
    userName: req.auth.email,
    existingCredentials: await db.credentialsFor(req.auth.userId),
  });
  res.json(options);
});

// 2. Finish — consumes the challenge, then verifies.
app.post('/webauthn/register/finish', requireLogin, async (req, res) => {
  const verified = await webauthn.finishRegistration(
    {
      clientDataJSON: fromBase64Url(req.body.response.clientDataJSON),
      attestationObject: fromBase64Url(req.body.response.attestationObject),
    },
    req.auth.userId, // binds the ceremony to the signed-in user
  );

  await db.saveCredential({
    userId: verified.userId,
    credentialId: verified.credentialId,
    publicKey: verified.credentialPublicKey, // COSE bytes — store verbatim
    signCount: verified.signCount,
  });
  res.status(201).end();
});
```

### Authentication

```ts
app.post('/webauthn/login/start', async (req, res) => {
  res.json(await webauthn.startAuthentication()); // usernameless
});

app.post('/webauthn/login/finish', async (req, res) => {
  const credentialId = fromBase64Url(req.body.rawId);
  const stored = await db.credentialByCredentialId(credentialId);
  if (!stored) return res.status(400).json({ error: 'unknown credential' });

  const result = await webauthn.finishAuthentication(
    {
      clientDataJSON: fromBase64Url(req.body.response.clientDataJSON),
      authenticatorData: fromBase64Url(req.body.response.authenticatorData),
      signature: fromBase64Url(req.body.response.signature),
      userHandle: req.body.response.userHandle
        ? fromBase64Url(req.body.response.userHandle)
        : undefined,
      credentialId,
    },
    stored,
  );

  // Persist the counter, or clone detection stops working.
  await db.updateSignCount(credentialId, result.newSignCount);

  const tokens = await auth.createSession({
    ...result.principal,
    roles: await db.rolesFor(result.principal.userId),
  });
  res.json(tokens);
});
```

The browser side is the standard API — `navigator.credentials.create/get` with
`PublicKeyCredential.parseCreationOptionsFromJSON()`. The options this package emits are already in
that JSON form, so no translation layer is needed.

## What is verified

Both ceremonies check the client data type, the challenge, the origin, the RP ID hash, the
user-presence flag and the backup-state invariant. Authentication additionally checks the signature,
the sign counter, and the user handle.

| Property | How it is enforced | Test |
| --- | --- | --- |
| The challenge is single-use | Atomic `take()`, never read-then-delete | `challenge.test.ts` — "lets exactly one of many concurrent attempts win" |
| A registration challenge cannot be used to authenticate | Ceremony type is part of the storage key, not a comparison | `challenge.test.ts` — "ceremony scoping" |
| A failed verification still burns the challenge | `finish*` consumes before it verifies | `server.test.ts` — "burns the challenge even when verification then fails" |
| A response cannot be replayed across ceremonies | `clientData.type` must match exactly | `ceremony.test.ts` — "refuses a registration response replayed at authentication" |
| Origins match exactly | Allowlist, no substring or suffix matching | `ceremony.test.ts` — "refuses the lookalike origin …" (5 cases) |
| A credential for one site cannot be used at another | RP ID hash is compared against `SHA-256(rpId)` | `ceremony.test.ts` — "refuses an assertion for a different relying party" |
| The verification algorithm never comes from the request | It comes from the stored key | `cose.test.ts` — "never lets the verify-time algorithm come from the signature" |
| An EC2 key cannot claim to be RSA | Key type must match the algorithm | `cose.test.ts` — "algorithm confusion" (4 cases) |
| Undersized RSA keys are refused | 2048-bit floor, measured in significant bits | `cose.test.ts` — "refuses a 512-bit modulus" |
| A cloned authenticator is detected | Counter regression rejects by default | `ceremony.test.ts` — "sign counter" |
| A ceremony cannot be completed against another account | Challenge user and credential owner must agree | `server.test.ts` — "binding a ceremony to its user" |
| Parsers never read past their input | Every length is bounds-checked before use | `cbor.test.ts`, `der.test.ts`, `authdata.test.ts` — prefix and fuzz suites |
| Failures never leak which check failed | Reason lives in `detail`, which `toResponse()` cannot read | `ceremony.test.ts` — "gives the same body whichever check failed" |
| Only approved hardware may enrol | `packed` chain verified to your roots + AAGUID allowlist | `attestation.test.ts` — "enforces an AAGUID allowlist" |
| A self-signed CA cannot forge attestation | Trust anchors are mandatory | `attestation.test.ts` — "refuses a chain that does not reach a configured root" |
| An attestation lifted from another device is refused | Certificate AAGUID must match the authenticator data | `attestation.test.ts` |
| A CA certificate cannot pose as an attestation leaf | Refused per §8.2.1 | `attestation.test.ts` |

400 tests. The CBOR decoder is verified against **RFC 8949 Appendix A** vectors; the DER signature
parser is verified differentially against signatures produced by OpenSSL through `node:crypto` and
checked by WebCrypto, so the conversion has to satisfy two implementations that know nothing about
this code. Certificate parsing leans on Node's own vetted `X509Certificate` rather than a
hand-rolled X.509 parser — only the AAGUID extension lookup is done here, because that is the one
thing Node does not expose.

## Attestation — proving *which hardware*

A normal passkey ceremony proves someone controls a private key. Attestation proves the key was
generated inside a particular piece of hardware, vouched for by a chain the manufacturer signed.
That is the difference between "a credential" and "a credential on an issued YubiKey".

```ts
const webauthn = new WebAuthnServer({
  rpId: 'example.com',
  rpName: 'Example',
  origin: 'https://example.com',
  store,
  attestation: {
    formats: ['packed'],
    trustAnchors: [vendorRootDer],              // roots you decide to trust
    allowedAaguids: ['d8522d9f575b486688a9ba99fa02f35b'], // optional model allowlist
  },
});
```

Configuring this also changes what the browser is asked for — the ceremony requests `direct`
conveyance automatically, because a browser asked for `none` replaces the statement and there would
be nothing left to verify. Two settings that must agree are two settings that will not, so there is
only one.

The result tells you exactly what was established:

```ts
verified.attestationType   // 'none' | 'self' | 'basic'
verified.aaguidVerified    // true only when a trusted chain vouched for the AAGUID
verified.attestationSubject
```

**Trust anchors are mandatory.** `packed` is refused outright without them. A chain checked against
no root proves nothing — anyone can self-sign a CA and put any AAGUID they like in a certificate
they issued to themselves — and a verifier reporting success there would manufacture confidence.
If you have no roots, you have no attestation, and saying so is the honest answer.

## What is *not* verified

**Attestation formats other than `packed` and `apple`.** `tpm` (Windows Hello), `android-key`,
`android-safetynet` and `fido-u2f` are not implemented and are refused rather than
parsed-and-ignored — allowlisting one still fails closed. `packed` covers most security keys
including the YubiKey line; `apple` covers Touch ID and Face ID.

**No root store ships here.** Which manufacturers you trust is an operational decision that changes
without this package changing. FIDO's Metadata Service is where most relying parties draw roots
from; fetching it, verifying its signature and honouring its revocations is not implemented.

**Self-attestation proves nothing about hardware.** It is off by default, and reports
`aaguidVerified: false` even when enabled — the credential key signing for itself adds nothing
beyond what the ceremony already established.

For passkeys none of this matters: the browser substitutes `none`, which is the default and the
right answer.

## Defaults worth knowing

| Option | Default | Why |
| --- | --- | --- |
| `userVerification` | `'preferred'` | Matches the WebAuthn API's own default. Set `'required'` for high-value operations; the result always reports `userVerified` so you can gate on it yourself. |
| `onCounterRegression` | `'reject'` | The counter exists to signal a cloned authenticator. A library that only logs the signal has moved the decision somewhere nobody is looking. |
| `allowCrossOrigin` | `false` | A ceremony in an iframe the user may not know they are in is one they cannot meaningfully consent to. |
| `timeoutMs` | `300000` | Also the challenge lifetime — one number governs both, so a ceremony cannot outlive the challenge it depends on. |
| `attestation` | accept `none` only | Passkeys convey nothing. Accepting `packed` requires trust anchors. |
| algorithms | ES256, EdDSA, RS256 | RS256 is included because Windows Hello's TPM path still produces RSA keys. |

User presence is always required and has no option to disable it, because the specification does not
offer one.

## Storing credentials

Credential storage belongs in your own database, next to the user it identifies. Store:

- `credentialId` — the lookup key
- `credentialPublicKey` — the COSE bytes, verbatim; they are re-imported on every authentication
- `signCount` — update it after every success, or clone detection silently stops working
- `userId` — the owner
- optionally `backedUp` / `transports`

## Lower-level API

`verifyRegistration` and `verifyAuthentication` take an expected challenge and leave storing and
consuming it to you — the right seam if you already have your own ceremony state. `WebAuthnServer`
is the wiring on top; it exists because consume-before-verify is easy to get wrong and should be
written once.

The parsers (`parseAuthenticatorData`, `decodeCbor`, `importCoseKey`, `derToRawSignature`) are
exported too, so inspecting a credential — reading the AAGUID to name the authenticator, say —
does not require reimplementing them.

## Testing your integration

Testing a passkey flow otherwise means a physical authenticator and a human finger — which is to say
it does not get tested. `@ninsho/webauthn/testing` ships a software authenticator that holds a real
key pair and produces genuinely signed responses, so your tests exercise the real verifier:

```ts
import { VirtualAuthenticator, createChain } from '@ninsho/webauthn/testing';

const device = await VirtualAuthenticator.create();

const options = await webauthn.startRegistration({ userId: 'u1', userName: 'ada@example.com' });
const verified = await webauthn.finishRegistration(
  await device.register({
    challenge: Buffer.from(options.challenge, 'base64url'),
    origin: 'https://example.com',
    rpId: 'example.com',
  }),
  'u1',
);
```

`createChain()` builds a certificate chain so attestation paths can be tested too, and every
override you need for the negative cases is there — a wrong origin, a stale counter, a broken
signature, a chain that reaches no trusted root.

It is a separate entry point, so it never reaches a bundle that only imports the verifier, and it
**refuses to construct under `NODE_ENV=production`**. That guard is not decoration: a virtual
authenticator running server-side would mean your server holds the credential's private key —
WebAuthn defeated, quietly, while every signature still verifies.

## Requirements

Node 20 or newer. Ed25519 support comes from Node's WebCrypto.

## Licence

MIT
