import { describe, it, expect } from 'vitest';
import { ES256, EdDSA, RS256, SUPPORTED_ALGORITHMS } from './cose.js';
import {
  WebAuthnError,
  extractChallenge,
  parseClientData,
  verifyAuthentication,
  verifyRegistration,
  type AuthenticationExpectations,
  type RegistrationExpectations,
  type StoredCredential,
} from './ceremony.js';
import {
  FLAG_AT,
  FLAG_BE,
  FLAG_BS,
  FLAG_UP,
  FLAG_UV,
  VirtualAuthenticator,
  buildAuthenticatorData,
  encodeCbor,
  type Encodable,
} from './testing.js';

const RP_ID = 'example.com';
const ORIGIN = 'https://example.com';

const challengeBytes = (): Uint8Array => {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytes;
};

const b64u = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');

/** Captures a rejection so assertions can read `detail`, where the reason lives. */
async function rejection(promise: Promise<unknown>): Promise<WebAuthnError> {
  try {
    await promise;
  } catch (error) {
    return error as WebAuthnError;
  }
  throw new Error('expected the promise to reject');
}

/** The synchronous counterpart to `rejection`, for the parsing entry points. */
function caught(fn: () => unknown): WebAuthnError {
  try {
    fn();
  } catch (error) {
    return error as WebAuthnError;
  }
  throw new Error('expected the call to throw');
}

const registrationExpectations = (challenge: Uint8Array): RegistrationExpectations => ({
  rpId: RP_ID,
  origin: ORIGIN,
  challenge: b64u(challenge),
});

/** Registers an authenticator and returns what a relying party would store. */
async function register(
  authenticator: VirtualAuthenticator,
): Promise<{ credential: StoredCredential; challenge: Uint8Array }> {
  const challenge = challengeBytes();
  const response = await authenticator.register({ challenge, origin: ORIGIN, rpId: RP_ID });
  const verified = await verifyRegistration(response, registrationExpectations(challenge));

  return {
    challenge,
    credential: {
      credentialId: verified.credentialId,
      publicKey: verified.credentialPublicKey,
      signCount: verified.signCount,
      userId: 'user-1',
    },
  };
}

const authExpectations = (
  credential: StoredCredential,
  challenge: Uint8Array,
  overrides: Partial<AuthenticationExpectations> = {},
): AuthenticationExpectations => ({
  rpId: RP_ID,
  origin: ORIGIN,
  challenge: b64u(challenge),
  credential,
  ...overrides,
});

// ─── Registration ──────────────────────────────────────────────────────────

describe('registration', () => {
  it.each(SUPPORTED_ALGORITHMS)('verifies a %i registration end to end', async (alg) => {
    const authenticator = await VirtualAuthenticator.create(alg);
    const challenge = challengeBytes();
    const response = await authenticator.register({ challenge, origin: ORIGIN, rpId: RP_ID });

    const verified = await verifyRegistration(response, registrationExpectations(challenge));

    expect(verified.algorithm).toBe(alg);
    expect(Buffer.from(verified.credentialId)).toEqual(Buffer.from(authenticator.credentialId));
    expect(Buffer.from(verified.aaguid)).toEqual(Buffer.from(authenticator.aaguid));
    expect(verified.attestationFormat).toBe('none');
    expect(verified.attestationType).toBe('none');
    // Nothing vouched for the AAGUID, and the result says so rather than
    // leaving a caller to assume.
    expect(verified.aaguidVerified).toBe(false);
    expect(verified.userVerified).toBe(true);
    expect(verified.origin).toBe(ORIGIN);
  });

  it('returns a public key that actually verifies a later assertion', async () => {
    // The point of registration is to produce a usable key. A result that
    // parses but cannot verify anything is a registration that fails at the
    // user's next sign-in.
    const authenticator = await VirtualAuthenticator.create();
    const { credential } = await register(authenticator);

    const challenge = challengeBytes();
    const assertion = await authenticator.authenticate({ challenge, origin: ORIGIN, rpId: RP_ID });

    await expect(
      verifyAuthentication(assertion, authExpectations(credential, challenge)),
    ).resolves.toBeTruthy();
  });

  it('copies the credential out of the response buffer', async () => {
    // The parser returns subarrays that share memory with the response. A
    // caller storing those would be storing a view of bytes it no longer
    // controls.
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const response = await authenticator.register({ challenge, origin: ORIGIN, rpId: RP_ID });
    const verified = await verifyRegistration(response, registrationExpectations(challenge));

    const before = Buffer.from(verified.credentialPublicKey).toString('hex');
    response.attestationObject.fill(0);
    expect(Buffer.from(verified.credentialPublicKey).toString('hex')).toBe(before);
  });

  it('accepts an array of permitted origins', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: 'https://app.example.com',
      rpId: RP_ID,
    });

    await expect(
      verifyRegistration(response, {
        ...registrationExpectations(challenge),
        origin: [ORIGIN, 'https://app.example.com'],
      }),
    ).resolves.toBeTruthy();
  });

  it('records backup eligibility and state', async () => {
    // A synced passkey lives in a cloud account; a relying party may well want
    // to treat that differently from a hardware-bound one.
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      flags: FLAG_UP | FLAG_UV | FLAG_AT | FLAG_BE | FLAG_BS,
    });

    const verified = await verifyRegistration(response, registrationExpectations(challenge));
    expect(verified.backupEligible).toBe(true);
    expect(verified.backedUp).toBe(true);
  });
});

describe('registration — rejections', () => {
  it('refuses a mismatched challenge', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const response = await authenticator.register({
      challenge: challengeBytes(),
      origin: ORIGIN,
      rpId: RP_ID,
    });

    const error = await rejection(
      verifyRegistration(response, registrationExpectations(challengeBytes())),
    );
    expect(error.detail).toMatch(/challenge does not match/);
  });

  it('refuses an unexpected origin', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: 'https://evil.example',
      rpId: RP_ID,
    });

    const error = await rejection(verifyRegistration(response, registrationExpectations(challenge)));
    expect(error.detail).toMatch(/is not an expected origin/);
  });

  it.each([
    'https://example.com.attacker.net',
    'https://notexample.com',
    'http://example.com',
    'https://example.com:8443',
    'https://sub.example.com',
  ])('refuses the lookalike origin %s', async (origin) => {
    // Exact match against an allowlist. Substring or suffix matching is how
    // the first of these gets accepted.
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const response = await authenticator.register({ challenge, origin, rpId: RP_ID });

    await expect(verifyRegistration(response, registrationExpectations(challenge))).rejects.toThrow(
      WebAuthnError,
    );
  });

  it('refuses a wrong RP ID hash', async () => {
    // What stops a credential registered for one site being usable at
    // another.
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: 'attacker.example',
    });

    const error = await rejection(verifyRegistration(response, registrationExpectations(challenge)));
    expect(error.detail).toMatch(/RP ID hash does not match/);
  });

  it('refuses an assertion response replayed at registration', async () => {
    // The two responses are otherwise the same shape; only clientData.type
    // separates them.
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      clientDataOverride: authenticator.clientData('webauthn.get', challenge, ORIGIN),
    });

    const error = await rejection(verifyRegistration(response, registrationExpectations(challenge)));
    expect(error.detail).toMatch(/clientData.type is webauthn.get/);
  });

  it('refuses a response with the user-presence flag clear', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      flags: FLAG_AT, // no UP
    });

    const error = await rejection(verifyRegistration(response, registrationExpectations(challenge)));
    expect(error.detail).toMatch(/user-presence flag is not set/);
  });

  it('refuses an unverified user when verification is required', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      flags: FLAG_UP | FLAG_AT, // no UV
    });

    await expect(
      verifyRegistration(response, {
        ...registrationExpectations(challenge),
        userVerification: 'required',
      }),
    ).rejects.toThrow(WebAuthnError);

    // And accepts it under the default, so the rejection came from the policy
    // rather than from something else being wrong.
    await expect(
      verifyRegistration(response, registrationExpectations(challenge)),
    ).resolves.toMatchObject({ userVerified: false });
  });

  it('refuses a cross-origin ceremony by default', async () => {
    // A ceremony in an iframe the user may not have known they were in is one
    // they cannot meaningfully consent to.
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const clientData = new TextEncoder().encode(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: b64u(challenge),
        origin: ORIGIN,
        crossOrigin: true,
      }),
    );

    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      clientDataOverride: clientData,
    });

    const error = await rejection(verifyRegistration(response, registrationExpectations(challenge)));
    expect(error.detail).toMatch(/cross-origin iframe/);

    await expect(
      verifyRegistration(response, {
        ...registrationExpectations(challenge),
        allowCrossOrigin: true,
      }),
    ).resolves.toBeTruthy();
  });

  it('refuses an algorithm the relying party did not allow', async () => {
    const authenticator = await VirtualAuthenticator.create(RS256);
    const challenge = challengeBytes();
    const response = await authenticator.register({ challenge, origin: ORIGIN, rpId: RP_ID });

    await expect(
      verifyRegistration(response, {
        ...registrationExpectations(challenge),
        allowedAlgorithms: [ES256, EdDSA],
      }),
    ).rejects.toThrow(WebAuthnError);
  });

  it('refuses a registration with no attested credential data', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const authData = await buildAuthenticatorData({
      rpId: RP_ID,
      flags: FLAG_UP | FLAG_UV, // no AT
      signCount: 0,
    });

    const response = {
      clientDataJSON: authenticator.clientData('webauthn.create', challenge, ORIGIN),
      attestationObject: encodeCbor(
        new Map<string, Encodable>([
          ['fmt', 'none'],
          ['attStmt', new Map<string | number, Encodable>()],
          ['authData', authData],
        ]),
      ),
    };

    const error = await rejection(verifyRegistration(response, registrationExpectations(challenge)));
    expect(error.detail).toMatch(/no attested credential data/);
  });
});

/**
 * Attestation is refused rather than parsed-and-ignored. A verifier that reads
 * an attestation statement without checking it looks like a guarantee and is
 * not one.
 */
describe('attestation', () => {
  it.each(['packed', 'tpm', 'android-key', 'android-safetynet', 'apple', 'fido-u2f'])(
    'refuses the %s format',
    async (fmt) => {
      const authenticator = await VirtualAuthenticator.create();
      const challenge = challengeBytes();
      const response = await authenticator.register({
        challenge,
        origin: ORIGIN,
        rpId: RP_ID,
        attestationFormat: fmt,
      });

      const error = await rejection(
        verifyRegistration(response, registrationExpectations(challenge)),
      );
      expect(error.detail).toMatch(/is not accepted/);
    },
  );

  it('refuses a statement labelled packed that carries nothing', async () => {
    // An empty attStmt under a `packed` label is refused for want of an
    // algorithm, before any policy question arises. The trust-anchor
    // requirement is exercised against genuine chains in attestation.test.ts.
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      attestationFormat: 'packed',
    });

    const error = await rejection(
      verifyRegistration(response, {
        ...registrationExpectations(challenge),
        attestation: { formats: ['none', 'packed'] },
      }),
    );
    expect(error.detail).toMatch(/has no algorithm/);
  });

  it('refuses a format this package cannot verify even when allowlisted', async () => {
    // android-key, android-safetynet and fido-u2f are unimplemented.
    // Allowlisting one must not produce a result that reads as verified.
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      attestationFormat: 'android-key',
    });

    const error = await rejection(
      verifyRegistration(response, {
        ...registrationExpectations(challenge),
        attestation: { formats: ['none', 'android-key'] },
      }),
    );
    expect(error.detail).toMatch(/cannot be verified/);
  });

  it('refuses an attestation object missing attStmt', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const authData = await buildAuthenticatorData({
      rpId: RP_ID,
      flags: FLAG_UP | FLAG_UV | FLAG_AT,
      signCount: 0,
      attestedCredential: {
        aaguid: authenticator.aaguid,
        credentialId: authenticator.credentialId,
        credentialPublicKey: await authenticator.coseKey(),
      },
    });

    const response = {
      clientDataJSON: authenticator.clientData('webauthn.create', challenge, ORIGIN),
      attestationObject: encodeCbor(
        new Map<string, Encodable>([
          ['fmt', 'none'],
          ['authData', authData],
        ]),
      ),
    };

    const error = await rejection(verifyRegistration(response, registrationExpectations(challenge)));
    expect(error.detail).toMatch(/attStmt is missing/);
  });

  it.each([
    ['not CBOR at all', new Uint8Array([0xff, 0xfe])],
    ['a CBOR array', encodeCbor([1, 2, 3])],
    ['an empty map', encodeCbor(new Map<string, Encodable>())],
  ])('refuses an attestation object that is %s', async (_label, attestationObject) => {
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();

    await expect(
      verifyRegistration(
        {
          clientDataJSON: authenticator.clientData('webauthn.create', challenge, ORIGIN),
          attestationObject,
        },
        registrationExpectations(challenge),
      ),
    ).rejects.toThrow(WebAuthnError);
  });
});

// ─── Authentication ────────────────────────────────────────────────────────

describe('authentication', () => {
  it.each(SUPPORTED_ALGORITHMS)('verifies a %i assertion end to end', async (alg) => {
    const authenticator = await VirtualAuthenticator.create(alg);
    const { credential } = await register(authenticator);

    const challenge = challengeBytes();
    const assertion = await authenticator.authenticate({ challenge, origin: ORIGIN, rpId: RP_ID });

    const verified = await verifyAuthentication(assertion, authExpectations(credential, challenge));
    expect(verified.newSignCount).toBe(1);
    expect(verified.userVerified).toBe(true);
    expect(verified.origin).toBe(ORIGIN);
  });

  it('accepts a matching user handle', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const { credential } = await register(authenticator);

    const challenge = challengeBytes();
    const assertion = await authenticator.authenticate({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      userHandle: new TextEncoder().encode('user-1'),
    });

    await expect(
      verifyAuthentication(assertion, authExpectations(credential, challenge)),
    ).resolves.toMatchObject({ userHandle: 'user-1' });
  });

  it('refuses a user handle belonging to someone else', async () => {
    // Otherwise an assertion from one account could be presented as another's.
    const authenticator = await VirtualAuthenticator.create();
    const { credential } = await register(authenticator);

    const challenge = challengeBytes();
    const assertion = await authenticator.authenticate({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      userHandle: new TextEncoder().encode('user-2'),
    });

    const error = await rejection(
      verifyAuthentication(assertion, authExpectations(credential, challenge)),
    );
    expect(error.detail).toMatch(/user handle does not match/);
  });

  it('refuses a credential id that is not the stored one', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const { credential } = await register(authenticator);

    const challenge = challengeBytes();
    const assertion = await authenticator.authenticate({ challenge, origin: ORIGIN, rpId: RP_ID });

    const error = await rejection(
      verifyAuthentication(
        { ...assertion, credentialId: new Uint8Array(32).fill(9) },
        authExpectations(credential, challenge),
      ),
    );
    expect(error.detail).toMatch(/credential id does not match/);
  });
});

describe('authentication — signature', () => {
  it('refuses an assertion signed by a different authenticator', async () => {
    const legitimate = await VirtualAuthenticator.create();
    const attacker = await VirtualAuthenticator.create();
    const { credential } = await register(legitimate);

    const challenge = challengeBytes();
    const assertion = await attacker.authenticate({ challenge, origin: ORIGIN, rpId: RP_ID });

    const error = await rejection(
      verifyAuthentication(
        // Present the attacker's assertion under the legitimate credential id,
        // which is what an attacker would actually do.
        { ...assertion, credentialId: credential.credentialId },
        authExpectations(credential, challenge),
      ),
    );
    expect(error.detail).toMatch(/signature did not verify/);
  });

  it('refuses a tampered authenticator data', async () => {
    // The signature covers authData, so flipping a flag must invalidate it.
    const authenticator = await VirtualAuthenticator.create();
    const { credential } = await register(authenticator);

    const challenge = challengeBytes();
    const assertion = await authenticator.authenticate({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      flags: FLAG_UP,
    });

    const tampered = new Uint8Array(assertion.authenticatorData);
    // Set UV on data that was signed without it — the actual attack, claiming
    // a user verification that never happened. OR-ing a flag that is already
    // set changes nothing and would prove nothing.
    tampered[32] = (tampered[32] as number) | FLAG_UV;

    const error = await rejection(
      verifyAuthentication(
        { ...assertion, authenticatorData: tampered },
        authExpectations(credential, challenge),
      ),
    );
    expect(error.detail).toMatch(/signature did not verify/);
  });

  it('refuses tampered client data', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const { credential } = await register(authenticator);

    const challenge = challengeBytes();
    const assertion = await authenticator.authenticate({ challenge, origin: ORIGIN, rpId: RP_ID });

    // Same challenge and origin, but different bytes — the hash changes, so
    // the signature must stop verifying.
    const restated = new TextEncoder().encode(
      JSON.stringify({ type: 'webauthn.get', challenge: b64u(challenge), origin: ORIGIN }),
    );

    const error = await rejection(
      verifyAuthentication(
        { ...assertion, clientDataJSON: restated },
        authExpectations(credential, challenge),
      ),
    );
    expect(error.detail).toMatch(/signature did not verify/);
  });

  it.each([
    ['an empty signature', new Uint8Array(0)],
    ['a random signature', new Uint8Array(70).fill(3)],
    ['a truncated signature', new Uint8Array(10)],
  ])('refuses %s', async (_label, signatureOverride) => {
    const authenticator = await VirtualAuthenticator.create();
    const { credential } = await register(authenticator);

    const challenge = challengeBytes();
    const assertion = await authenticator.authenticate({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      signatureOverride,
    });

    await expect(
      verifyAuthentication(assertion, authExpectations(credential, challenge)),
    ).rejects.toThrow(WebAuthnError);
  });

  it('refuses an assertion carrying attested credential data', async () => {
    // Registration data has no business in a sign-in: accepting it would let
    // an assertion smuggle in a new credential.
    const authenticator = await VirtualAuthenticator.create();
    const { credential } = await register(authenticator);

    const challenge = challengeBytes();
    const authData = await buildAuthenticatorData({
      rpId: RP_ID,
      flags: FLAG_UP | FLAG_UV | FLAG_AT,
      signCount: 5,
      attestedCredential: {
        aaguid: authenticator.aaguid,
        credentialId: authenticator.credentialId,
        credentialPublicKey: await authenticator.coseKey(),
      },
    });

    const clientDataJSON = authenticator.clientData('webauthn.get', challenge, ORIGIN);
    const clientDataHash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientDataJSON));
    const signed = new Uint8Array(authData.length + clientDataHash.length);
    signed.set(authData);
    signed.set(clientDataHash, authData.length);

    const error = await rejection(
      verifyAuthentication(
        {
          clientDataJSON,
          authenticatorData: authData,
          signature: await authenticator.sign(signed),
          userHandle: undefined,
        },
        authExpectations(credential, challenge),
      ),
    );
    expect(error.detail).toMatch(/must not carry attested credential data/);
  });
});

describe('authentication — replay and scope', () => {
  it('refuses a replayed assertion under a fresh challenge', async () => {
    // The challenge is the only unpredictable part of the signed data, which
    // is why single-use consumption is what actually stops replay.
    const authenticator = await VirtualAuthenticator.create();
    const { credential } = await register(authenticator);

    const challenge = challengeBytes();
    const assertion = await authenticator.authenticate({ challenge, origin: ORIGIN, rpId: RP_ID });
    await verifyAuthentication(assertion, authExpectations(credential, challenge));

    await expect(
      verifyAuthentication(assertion, authExpectations(credential, challengeBytes())),
    ).rejects.toThrow(WebAuthnError);
  });

  it('refuses an assertion for a different relying party', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const { credential } = await register(authenticator);

    const challenge = challengeBytes();
    const assertion = await authenticator.authenticate({
      challenge,
      origin: ORIGIN,
      rpId: 'attacker.example',
    });

    const error = await rejection(
      verifyAuthentication(assertion, authExpectations(credential, challenge)),
    );
    expect(error.detail).toMatch(/RP ID hash does not match/);
  });

  it('refuses a registration response replayed at authentication', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const { credential } = await register(authenticator);

    const challenge = challengeBytes();
    const assertion = await authenticator.authenticate({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      clientDataOverride: authenticator.clientData('webauthn.create', challenge, ORIGIN),
    });

    const error = await rejection(
      verifyAuthentication(assertion, authExpectations(credential, challenge)),
    );
    expect(error.detail).toMatch(/clientData.type is webauthn.create/);
  });

  it('refuses an assertion made at another origin', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const { credential } = await register(authenticator);

    const challenge = challengeBytes();
    const assertion = await authenticator.authenticate({
      challenge,
      origin: 'https://evil.example',
      rpId: RP_ID,
    });

    const error = await rejection(
      verifyAuthentication(assertion, authExpectations(credential, challenge)),
    );
    expect(error.detail).toMatch(/is not an expected origin/);
  });

  it('refuses an unverified user when verification is required', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const { credential } = await register(authenticator);

    const challenge = challengeBytes();
    const assertion = await authenticator.authenticate({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      flags: FLAG_UP,
    });

    await expect(
      verifyAuthentication(
        assertion,
        authExpectations(credential, challenge, { userVerification: 'required' }),
      ),
    ).rejects.toThrow(WebAuthnError);

    await expect(
      verifyAuthentication(assertion, authExpectations(credential, challenge)),
    ).resolves.toMatchObject({ userVerified: false });
  });
});

/**
 * §6.1.1 — a counter that fails to advance is the spec's clone signal. The
 * default is to act on it, because a library that only logs the signal has
 * moved the decision somewhere nobody is looking.
 */
describe('sign counter', () => {
  it('accepts a counter that advances', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const { credential } = await register(authenticator);

    let stored = credential;
    for (let i = 1; i <= 3; i += 1) {
      const challenge = challengeBytes();
      const assertion = await authenticator.authenticate({ challenge, origin: ORIGIN, rpId: RP_ID });
      const verified = await verifyAuthentication(assertion, authExpectations(stored, challenge));

      expect(verified.newSignCount).toBe(i);
      expect(verified.counterSupported).toBe(true);
      stored = { ...stored, signCount: verified.newSignCount };
    }
  });

  it.each([
    ['a repeated counter', 5, 5],
    ['a counter that went backwards', 5, 2],
    ['a counter reset to zero', 5, 0],
  ])('refuses %s', async (_label, storedCount, presentedCount) => {
    const authenticator = await VirtualAuthenticator.create();
    const { credential } = await register(authenticator);

    const challenge = challengeBytes();
    const assertion = await authenticator.authenticate({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      signCount: presentedCount,
    });

    const error = await rejection(
      verifyAuthentication(
        assertion,
        authExpectations({ ...credential, signCount: storedCount }, challenge),
      ),
    );
    expect(error.detail).toMatch(/may be cloned/);
  });

  it('allows the regression when the relying party asks it to', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const { credential } = await register(authenticator);

    const challenge = challengeBytes();
    const assertion = await authenticator.authenticate({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      signCount: 1,
    });

    await expect(
      verifyAuthentication(
        assertion,
        authExpectations({ ...credential, signCount: 5 }, challenge, {
          onCounterRegression: 'allow',
        }),
      ),
    ).resolves.toMatchObject({ counterSupported: true });
  });

  it('does not treat an always-zero counter as a clone', async () => {
    // Most passkeys do not implement a counter and report 0 forever.
    // Rejecting that would break them all.
    const authenticator = await VirtualAuthenticator.create();
    const { credential } = await register(authenticator);

    for (let i = 0; i < 3; i += 1) {
      const challenge = challengeBytes();
      const assertion = await authenticator.authenticate({
        challenge,
        origin: ORIGIN,
        rpId: RP_ID,
        signCount: 0,
      });

      const verified = await verifyAuthentication(
        assertion,
        authExpectations({ ...credential, signCount: 0 }, challenge),
      );
      expect(verified.counterSupported).toBe(false);
      expect(verified.newSignCount).toBe(0);
    }
  });
});

// ─── clientDataJSON parsing ────────────────────────────────────────────────

describe('clientDataJSON', () => {
  const encode = (value: unknown): Uint8Array =>
    new TextEncoder().encode(typeof value === 'string' ? value : JSON.stringify(value));

  it('extracts the challenge without verifying anything else', async () => {
    // Consumption is what makes a replay fail, so it must not depend on the
    // rest of the response being well-formed.
    const challenge = challengeBytes();
    const clientData = encode({
      type: 'webauthn.get',
      challenge: b64u(challenge),
      origin: 'https://wrong.example',
    });

    expect(extractChallenge(clientData)).toBe(b64u(challenge));
  });

  it('canonicalises the challenge encoding', async () => {
    // Padding variants exist in the wild. Normalising through the bytes means
    // the comparison is about the value rather than its spelling.
    const challenge = challengeBytes();
    const padded = Buffer.from(challenge).toString('base64');
    const clientData = encode({ type: 'webauthn.get', challenge: padded, origin: ORIGIN });

    expect(extractChallenge(clientData)).toBe(b64u(challenge));
  });

  it.each([
    ['not JSON', 'not json at all'],
    ['a JSON array', '[1,2,3]'],
    ['a JSON string', '"hello"'],
    ['null', 'null'],
    ['an empty object', '{}'],
  ])('refuses clientData that is %s', (_label, text) => {
    expect(() => parseClientData(encode(text))).toThrow(WebAuthnError);
  });

  it('refuses empty clientData', () => {
    expect(caught(() => parseClientData(new Uint8Array(0))).detail).toMatch(/is empty/);
  });

  it('refuses invalid UTF-8', () => {
    // A replacement character would change what the origin string says while
    // still parsing as JSON.
    expect(caught(() => parseClientData(new Uint8Array([0x7b, 0xc3, 0x28, 0x7d]))).detail).toMatch(
      /not valid UTF-8/,
    );
  });

  it('refuses clientData beyond the size limit', () => {
    const huge = encode({
      type: 'webauthn.get',
      challenge: 'x',
      origin: ORIGIN,
      padding: 'a'.repeat(9000),
    });
    expect(caught(() => parseClientData(huge)).detail).toMatch(/exceeds the 8192-byte limit/);
  });

  it.each([
    ['type', { challenge: 'x', origin: ORIGIN }],
    ['challenge', { type: 'webauthn.get', origin: ORIGIN }],
    ['origin', { type: 'webauthn.get', challenge: 'x' }],
  ])('refuses clientData missing %s', (field, value) => {
    expect(caught(() => parseClientData(encode(value))).detail).toMatch(
      new RegExp(`${field} is missing`),
    );
  });

  it.each([
    ['a numeric type', { type: 1, challenge: 'x', origin: ORIGIN }],
    ['a null origin', { type: 'webauthn.get', challenge: 'x', origin: null }],
    ['an array challenge', { type: 'webauthn.get', challenge: [], origin: ORIGIN }],
  ])('refuses %s', (_label, value) => {
    expect(caught(() => parseClientData(encode(value))).detail).toMatch(/not a string/);
  });

  it('refuses a non-boolean crossOrigin', () => {
    expect(
      caught(() =>
        parseClientData(
          encode({ type: 'webauthn.get', challenge: 'x', origin: ORIGIN, crossOrigin: 'yes' }),
        ),
      ).detail,
    ).toMatch(/crossOrigin is not a boolean/);
  });

  it('never throws anything but WebAuthnError on random input', () => {
    for (let i = 0; i < 2000; i += 1) {
      const bytes = new Uint8Array(Math.floor(Math.random() * 50));
      crypto.getRandomValues(bytes);

      try {
        parseClientData(bytes);
      } catch (error) {
        if (!(error instanceof WebAuthnError)) {
          throw new Error(
            `uncontrolled ${(error as Error).constructor.name}: ${(error as Error).message}`,
          );
        }
      }
    }
  });
});

describe('error surface', () => {
  it('never puts the failed check in the client-facing body', async () => {
    // Which check failed is a free oracle for probing what a relying party
    // expects.
    const authenticator = await VirtualAuthenticator.create();
    const response = await authenticator.register({
      challenge: challengeBytes(),
      origin: 'https://evil.example',
      rpId: 'attacker.example',
    });

    const error = await rejection(
      verifyRegistration(response, registrationExpectations(challengeBytes())),
    );

    expect(error.status).toBe(400);
    expect(error.code).toBe('WEBAUTHN_VERIFICATION_FAILED');
    expect(JSON.stringify(error.toResponse())).not.toMatch(/challenge|origin|rp id|flag/i);
    // The reason is still available server-side.
    expect(error.detail).toBeTruthy();
  });

  it('gives the same body whichever check failed', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const { credential } = await register(authenticator);
    const challenge = challengeBytes();

    const wrongChallenge = await rejection(
      verifyAuthentication(
        await authenticator.authenticate({ challenge, origin: ORIGIN, rpId: RP_ID }),
        authExpectations(credential, challengeBytes()),
      ),
    );
    const wrongOrigin = await rejection(
      verifyAuthentication(
        await authenticator.authenticate({
          challenge,
          origin: 'https://evil.example',
          rpId: RP_ID,
        }),
        authExpectations(credential, challenge),
      ),
    );

    expect(JSON.stringify(wrongChallenge.toResponse())).toBe(
      JSON.stringify(wrongOrigin.toResponse()),
    );
    expect(wrongChallenge.detail).not.toBe(wrongOrigin.detail);
  });
});
