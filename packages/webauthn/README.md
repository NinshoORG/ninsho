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

318 tests. The CBOR decoder is verified against **RFC 8949 Appendix A** vectors; the DER signature
parser is verified differentially against signatures produced by OpenSSL through `node:crypto` and
checked by WebCrypto, so the conversion has to satisfy two implementations that know nothing about
this code.

## What is *not* verified

**Attestation is not verified.** Only the `none` format is accepted.

Verifying `packed`, `tpm`, `android-key` or `apple` means parsing X.509 chains and maintaining root
stores. A verifier that parses an attestation statement without checking it is worse than one that
refuses it — it looks like a guarantee and is not one. So other formats are refused, and adding one
to `allowedAttestationFormats` does not change that: there is no arrangement of options that turns
an unverified attestation into a verified one.

For passkeys this costs nothing. The browser replaces the attestation with `none` whenever the
relying party requests `none` conveyance, which is what this package always requests.

If you need enterprise attestation — proving a credential lives on a specific approved hardware
model — that is a feature to build, not a flag to flip.

## Defaults worth knowing

| Option | Default | Why |
| --- | --- | --- |
| `userVerification` | `'preferred'` | Matches the WebAuthn API's own default. Set `'required'` for high-value operations; the result always reports `userVerified` so you can gate on it yourself. |
| `onCounterRegression` | `'reject'` | The counter exists to signal a cloned authenticator. A library that only logs the signal has moved the decision somewhere nobody is looking. |
| `allowCrossOrigin` | `false` | A ceremony in an iframe the user may not know they are in is one they cannot meaningfully consent to. |
| `timeoutMs` | `300000` | Also the challenge lifetime — one number governs both, so a ceremony cannot outlive the challenge it depends on. |
| `attestation` | `'none'` | See above. |
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

## Requirements

Node 20 or newer. Ed25519 support comes from Node's WebCrypto.

## Licence

MIT
