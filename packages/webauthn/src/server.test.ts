import { describe, it, expect } from 'vitest';
import { MemoryStore } from '@ninshorg/server';
import { WebAuthnServer } from './server.js';
import { ChallengeError } from './challenge.js';
import { WebAuthnError } from './ceremony.js';
import { ES256, EdDSA, RS256, SUPPORTED_ALGORITHMS } from './cose.js';
import { VirtualAuthenticator, FLAG_UP, FLAG_UV } from './testing.js';
import { createChain } from './x509-fixtures.js';
import type { StoredCredential } from './ceremony.js';

const RP_ID = 'example.com';
const ORIGIN = 'https://example.com';

const makeServer = (overrides: Partial<ConstructorParameters<typeof WebAuthnServer>[0]> = {}) =>
  new WebAuthnServer({
    rpId: RP_ID,
    rpName: 'Example',
    origin: ORIGIN,
    store: new MemoryStore(),
    ...overrides,
  });

const fromB64u = (value: string): Uint8Array => new Uint8Array(Buffer.from(value, 'base64url'));

async function rejection(promise: Promise<unknown>): Promise<Error & { detail?: string }> {
  try {
    await promise;
  } catch (error) {
    return error as Error & { detail?: string };
  }
  throw new Error('expected the promise to reject');
}

/** Runs a full registration through the server and returns what to store. */
async function enrol(
  server: WebAuthnServer,
  authenticator: VirtualAuthenticator,
  userId = 'user-1',
): Promise<StoredCredential> {
  const options = await server.startRegistration({ userId, userName: 'ada@example.com' });
  const response = await authenticator.register({
    challenge: fromB64u(options.challenge),
    origin: ORIGIN,
    rpId: RP_ID,
  });
  const verified = await server.finishRegistration(response, userId);

  return {
    credentialId: verified.credentialId,
    publicKey: verified.credentialPublicKey,
    signCount: verified.signCount,
    userId,
  };
}

describe('the full round trip', () => {
  it.each(SUPPORTED_ALGORITHMS)('registers and authenticates with algorithm %i', async (alg) => {
    const server = makeServer();
    const authenticator = await VirtualAuthenticator.create(alg);
    const credential = await enrol(server, authenticator);

    const options = await server.startAuthentication({ userId: 'user-1' });
    const assertion = await authenticator.authenticate({
      challenge: fromB64u(options.challenge),
      origin: ORIGIN,
      rpId: RP_ID,
    });

    const result = await server.finishAuthentication(assertion, credential);
    expect(result.principal.userId).toBe('user-1');
    expect(result.principal.roles).toEqual([]);
    expect(result.userVerified).toBe(true);
  });

  it('produces a Principal ready for createSession', async () => {
    // The boundary this package is built around: WebAuthn proves who, and
    // hands off to the session layer.
    const server = makeServer();
    const authenticator = await VirtualAuthenticator.create();
    const credential = await enrol(server, authenticator);

    const options = await server.startAuthentication({ userId: 'user-1' });
    const result = await server.finishAuthentication(
      await authenticator.authenticate({
        challenge: fromB64u(options.challenge),
        origin: ORIGIN,
        rpId: RP_ID,
      }),
      credential,
    );

    expect(Object.keys(result.principal).sort()).toEqual(['roles', 'scopes', 'userId']);
  });

  it('carries the counter forward across several sign-ins', async () => {
    const server = makeServer();
    const authenticator = await VirtualAuthenticator.create();
    let credential = await enrol(server, authenticator);

    for (let i = 1; i <= 3; i += 1) {
      const options = await server.startAuthentication({ userId: 'user-1' });
      const result = await server.finishAuthentication(
        await authenticator.authenticate({
          challenge: fromB64u(options.challenge),
          origin: ORIGIN,
          rpId: RP_ID,
        }),
        credential,
      );
      expect(result.newSignCount).toBe(i);
      credential = { ...credential, signCount: result.newSignCount };
    }
  });

  it('supports a usernameless sign-in', async () => {
    // No user id at start; the authenticator says who it is via the user
    // handle.
    const server = makeServer();
    const authenticator = await VirtualAuthenticator.create();
    const credential = await enrol(server, authenticator);

    const options = await server.startAuthentication();
    expect(options.allowCredentials).toEqual([]);

    const result = await server.finishAuthentication(
      await authenticator.authenticate({
        challenge: fromB64u(options.challenge),
        origin: ORIGIN,
        rpId: RP_ID,
        userHandle: new TextEncoder().encode('user-1'),
      }),
      credential,
    );
    expect(result.principal.userId).toBe('user-1');
  });
});

/**
 * The reason this layer exists. Getting the order wrong in either direction is
 * a real vulnerability, so it is written once here rather than in every
 * application.
 */
describe('challenge consumption', () => {
  it('refuses a replayed registration response', async () => {
    const server = makeServer();
    const authenticator = await VirtualAuthenticator.create();

    const options = await server.startRegistration({ userId: 'user-1', userName: 'ada' });
    const response = await authenticator.register({
      challenge: fromB64u(options.challenge),
      origin: ORIGIN,
      rpId: RP_ID,
    });

    await expect(server.finishRegistration(response)).resolves.toBeTruthy();
    await expect(server.finishRegistration(response)).rejects.toBeInstanceOf(ChallengeError);
  });

  it('refuses a replayed assertion', async () => {
    const server = makeServer();
    const authenticator = await VirtualAuthenticator.create();
    const credential = await enrol(server, authenticator);

    const options = await server.startAuthentication({ userId: 'user-1' });
    const assertion = await authenticator.authenticate({
      challenge: fromB64u(options.challenge),
      origin: ORIGIN,
      rpId: RP_ID,
    });

    await expect(server.finishAuthentication(assertion, credential)).resolves.toBeTruthy();
    await expect(server.finishAuthentication(assertion, credential)).rejects.toBeInstanceOf(
      ChallengeError,
    );
  });

  it('burns the challenge even when verification then fails', async () => {
    // Consume-before-verify: otherwise an attacker grinds attempts against one
    // challenge until something gets through.
    const server = makeServer();
    const authenticator = await VirtualAuthenticator.create();
    const credential = await enrol(server, authenticator);

    const options = await server.startAuthentication({ userId: 'user-1' });
    const badAssertion = await authenticator.authenticate({
      challenge: fromB64u(options.challenge),
      origin: 'https://evil.example',
      rpId: RP_ID,
    });

    await expect(server.finishAuthentication(badAssertion, credential)).rejects.toBeInstanceOf(
      WebAuthnError,
    );

    // The same challenge, now presented correctly, must still be refused.
    const goodAssertion = await authenticator.authenticate({
      challenge: fromB64u(options.challenge),
      origin: ORIGIN,
      rpId: RP_ID,
    });
    await expect(server.finishAuthentication(goodAssertion, credential)).rejects.toBeInstanceOf(
      ChallengeError,
    );
  });

  it('lets exactly one of many concurrent submissions win', async () => {
    const server = makeServer();
    const authenticator = await VirtualAuthenticator.create();
    const credential = await enrol(server, authenticator);

    const options = await server.startAuthentication({ userId: 'user-1' });
    const assertion = await authenticator.authenticate({
      challenge: fromB64u(options.challenge),
      origin: ORIGIN,
      rpId: RP_ID,
    });

    const results = await Promise.allSettled(
      Array.from({ length: 16 }, () => server.finishAuthentication(assertion, credential)),
    );
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
  });

  it('will not complete a registration with an authentication challenge', async () => {
    const server = makeServer();
    const authenticator = await VirtualAuthenticator.create();

    const options = await server.startAuthentication({ userId: 'user-1' });
    const response = await authenticator.register({
      challenge: fromB64u(options.challenge),
      origin: ORIGIN,
      rpId: RP_ID,
    });

    await expect(server.finishRegistration(response)).rejects.toBeInstanceOf(ChallengeError);
  });

  it('will not complete an authentication with a registration challenge', async () => {
    const server = makeServer();
    const authenticator = await VirtualAuthenticator.create();
    const credential = await enrol(server, authenticator);

    const options = await server.startRegistration({ userId: 'user-1', userName: 'ada' });
    const assertion = await authenticator.authenticate({
      challenge: fromB64u(options.challenge),
      origin: ORIGIN,
      rpId: RP_ID,
    });

    await expect(server.finishAuthentication(assertion, credential)).rejects.toBeInstanceOf(
      ChallengeError,
    );
  });
});

describe('binding a ceremony to its user', () => {
  it('refuses a registration completed against a different account', async () => {
    // Without this, a ceremony started by one user could be finished against
    // another's account.
    const server = makeServer();
    const authenticator = await VirtualAuthenticator.create();

    const options = await server.startRegistration({ userId: 'victim', userName: 'v' });
    const response = await authenticator.register({
      challenge: fromB64u(options.challenge),
      origin: ORIGIN,
      rpId: RP_ID,
    });

    const error = await rejection(server.finishRegistration(response, 'attacker'));
    expect(error.detail).toMatch(/issued for a different user/);
  });

  it('reports the user the challenge was issued for', async () => {
    const server = makeServer();
    const authenticator = await VirtualAuthenticator.create();

    const options = await server.startRegistration({ userId: 'user-9', userName: 'x' });
    const verified = await server.finishRegistration(
      await authenticator.register({
        challenge: fromB64u(options.challenge),
        origin: ORIGIN,
        rpId: RP_ID,
      }),
    );
    expect(verified.userId).toBe('user-9');
  });

  it('refuses a credential belonging to someone other than the challenge user', async () => {
    const server = makeServer();
    const victim = await VirtualAuthenticator.create();
    const attacker = await VirtualAuthenticator.create();

    const victimCredential = await enrol(server, victim, 'victim');
    const attackerCredential = await enrol(server, attacker, 'attacker');

    // A challenge issued for the victim, completed with the attacker's own
    // (perfectly valid) credential.
    const options = await server.startAuthentication({ userId: 'victim' });
    const assertion = await attacker.authenticate({
      challenge: fromB64u(options.challenge),
      origin: ORIGIN,
      rpId: RP_ID,
    });

    const error = await rejection(server.finishAuthentication(assertion, attackerCredential));
    expect(error.detail).toMatch(/does not belong to the user/);
    expect(victimCredential.userId).toBe('victim');
  });
});

describe('ceremony options', () => {
  it('produces registration options a browser can parse directly', async () => {
    const server = makeServer();
    const options = await server.startRegistration({
      userId: 'user-1',
      userName: 'ada@example.com',
      displayName: 'Ada',
    });

    expect(options.rp).toEqual({ id: RP_ID, name: 'Example' });
    expect(options.user.name).toBe('ada@example.com');
    expect(options.user.displayName).toBe('Ada');
    expect(options.attestation).toBe('none');
    expect(options.pubKeyCredParams.map((p) => p.alg)).toEqual([ES256, EdDSA, RS256]);
    expect(options.challenge).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(options.timeout).toBe(300_000);
  });

  it('uses the opaque user id as the handle, never the username', async () => {
    // WebAuthn §14.6.1: the user handle is stored on the authenticator and may
    // be displayed, so it must not carry personally identifying information.
    const server = makeServer();
    const options = await server.startRegistration({
      userId: 'user-1',
      userName: 'ada@example.com',
    });

    expect(Buffer.from(options.user.id, 'base64url').toString()).toBe('user-1');
  });

  it('keeps requireResidentKey in step with residentKey', async () => {
    // Older authenticators read the deprecated boolean. Letting the two
    // disagree is how a discoverable credential quietly stops being one.
    for (const [residentKey, expected] of [
      ['required', true],
      ['preferred', false],
      ['discouraged', false],
    ] as const) {
      const server = makeServer({ residentKey });
      const options = await server.startRegistration({ userId: 'u', userName: 'n' });
      expect(options.authenticatorSelection.residentKey).toBe(residentKey);
      expect(options.authenticatorSelection.requireResidentKey).toBe(expected);
    }
  });

  it('lists existing credentials so a duplicate is not created', async () => {
    const server = makeServer();
    const authenticator = await VirtualAuthenticator.create();
    const credential = await enrol(server, authenticator);

    const options = await server.startRegistration({
      userId: 'user-1',
      userName: 'ada',
      existingCredentials: [{ credentialId: credential.credentialId, transports: ['internal'] }],
    });

    expect(options.excludeCredentials).toHaveLength(1);
    expect(options.excludeCredentials[0]?.id).toBe(
      Buffer.from(credential.credentialId).toString('base64url'),
    );
    expect(options.excludeCredentials[0]?.transports).toEqual(['internal']);
  });

  it('names allowed credentials for a known user', async () => {
    const server = makeServer();
    const authenticator = await VirtualAuthenticator.create();
    const credential = await enrol(server, authenticator);

    const options = await server.startAuthentication({
      userId: 'user-1',
      allowCredentials: [{ credentialId: credential.credentialId }],
    });

    expect(options.rpId).toBe(RP_ID);
    expect(options.allowCredentials).toHaveLength(1);
  });

  it('issues a distinct challenge every time', async () => {
    const server = makeServer();
    const seen = new Set<string>();

    for (let i = 0; i < 50; i += 1) {
      const { challenge } = await server.startAuthentication();
      expect(seen.has(challenge)).toBe(false);
      seen.add(challenge);
    }
  });

  it('ties the challenge lifetime to the ceremony timeout', async () => {
    // A timeout longer than the challenge TTL produces users who are told to
    // try again after doing everything right.
    const server = makeServer({ timeoutMs: 60_000 });
    expect(server.challenges.ttlSeconds).toBe(60);

    const options = await server.startRegistration({ userId: 'u', userName: 'n' });
    expect(options.timeout).toBe(60_000);
  });
});

describe('policy is applied at both ends', () => {
  it('enforces required user verification through the server', async () => {
    const server = makeServer({ userVerification: 'required' });
    const authenticator = await VirtualAuthenticator.create();

    const options = await server.startRegistration({ userId: 'u', userName: 'n' });
    expect(options.authenticatorSelection.userVerification).toBe('required');

    const response = await authenticator.register({
      challenge: fromB64u(options.challenge),
      origin: ORIGIN,
      rpId: RP_ID,
      flags: FLAG_UP | 0x40, // AT, but no UV
    });

    const error = await rejection(server.finishRegistration(response));
    expect(error.detail).toMatch(/user verification was required/);
  });

  it('enforces the origin allowlist through the server', async () => {
    const server = makeServer({ origin: [ORIGIN, 'https://app.example.com'] });
    const authenticator = await VirtualAuthenticator.create();

    const good = await server.startRegistration({ userId: 'u', userName: 'n' });
    await expect(
      server.finishRegistration(
        await authenticator.register({
          challenge: fromB64u(good.challenge),
          origin: 'https://app.example.com',
          rpId: RP_ID,
        }),
      ),
    ).resolves.toBeTruthy();

    const bad = await server.startRegistration({ userId: 'u', userName: 'n' });
    await expect(
      server.finishRegistration(
        await authenticator.register({
          challenge: fromB64u(bad.challenge),
          origin: 'https://evil.example',
          rpId: RP_ID,
        }),
      ),
    ).rejects.toBeInstanceOf(WebAuthnError);
  });

  it('enforces the algorithm allowlist through the server', async () => {
    const server = makeServer({ algorithms: [ES256] });
    const authenticator = await VirtualAuthenticator.create(RS256);

    const options = await server.startRegistration({ userId: 'u', userName: 'n' });
    expect(options.pubKeyCredParams.map((p) => p.alg)).toEqual([ES256]);

    await expect(
      server.finishRegistration(
        await authenticator.register({
          challenge: fromB64u(options.challenge),
          origin: ORIGIN,
          rpId: RP_ID,
        }),
      ),
    ).rejects.toBeInstanceOf(WebAuthnError);
  });

  it('enforces the counter policy through the server', async () => {
    const server = makeServer();
    const authenticator = await VirtualAuthenticator.create();
    const credential = await enrol(server, authenticator);

    const options = await server.startAuthentication({ userId: 'user-1' });
    const assertion = await authenticator.authenticate({
      challenge: fromB64u(options.challenge),
      origin: ORIGIN,
      rpId: RP_ID,
      signCount: 1,
    });

    const error = await rejection(
      server.finishAuthentication(assertion, { ...credential, signCount: 9 }),
    );
    expect(error.detail).toMatch(/may be cloned/);
  });

  it('isolates two relying parties sharing one store', async () => {
    const store = new MemoryStore();
    const a = new WebAuthnServer({
      rpId: RP_ID,
      rpName: 'A',
      origin: ORIGIN,
      store,
      keyPrefix: 'app-a',
    });
    const b = new WebAuthnServer({
      rpId: RP_ID,
      rpName: 'B',
      origin: ORIGIN,
      store,
      keyPrefix: 'app-b',
    });

    const authenticator = await VirtualAuthenticator.create();
    const options = await a.startRegistration({ userId: 'u', userName: 'n' });
    const response = await authenticator.register({
      challenge: fromB64u(options.challenge),
      origin: ORIGIN,
      rpId: RP_ID,
    });

    await expect(b.finishRegistration(response)).rejects.toBeInstanceOf(ChallengeError);
    await expect(a.finishRegistration(response)).resolves.toBeTruthy();
  });
});

describe('attestation through the server', () => {
  it('asks the browser for none when no attestation is configured', async () => {
    // Requesting attestation you cannot check collects a statement nobody
    // verifies, so the default asks for nothing.
    const server = makeServer();
    const options = await server.startRegistration({ userId: 'u', userName: 'n' });
    expect(options.attestation).toBe('none');
  });

  it('asks for direct conveyance once a policy accepts packed', async () => {
    // The conveyance follows the policy rather than being a second setting:
    // two settings that must agree are two settings that will not.
    const chain = createChain();
    const server = makeServer({
      attestation: { formats: ['packed'], trustAnchors: [chain.root.der] },
    });

    const options = await server.startRegistration({ userId: 'u', userName: 'n' });
    expect(options.attestation).toBe('direct');
  });

  it('verifies a real attestation end to end and vouches for the AAGUID', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const chain = createChain({ aaguid: authenticator.aaguid });
    const server = makeServer({
      attestation: {
        formats: ['packed'],
        trustAnchors: [chain.root.der],
        allowedAaguids: [Buffer.from(authenticator.aaguid).toString('hex')],
      },
    });

    const options = await server.startRegistration({ userId: 'user-1', userName: 'ada' });
    const verified = await server.finishRegistration(
      await authenticator.register({
        challenge: fromB64u(options.challenge),
        origin: ORIGIN,
        rpId: RP_ID,
        attestationChain: chain,
      }),
      'user-1',
    );

    expect(verified.attestationType).toBe('basic');
    expect(verified.aaguidVerified).toBe(true);
  });

  it('refuses hardware outside the allowlist end to end', async () => {
    // The enterprise requirement, expressed as a policy and enforced by the
    // server rather than by the caller remembering to check.
    const authenticator = await VirtualAuthenticator.create();
    const chain = createChain({ aaguid: authenticator.aaguid });
    const server = makeServer({
      attestation: {
        formats: ['packed'],
        trustAnchors: [chain.root.der],
        allowedAaguids: ['0'.repeat(32)],
      },
    });

    const options = await server.startRegistration({ userId: 'user-1', userName: 'ada' });
    const error = await rejection(
      server.finishRegistration(
        await authenticator.register({
          challenge: fromB64u(options.challenge),
          origin: ORIGIN,
          rpId: RP_ID,
          attestationChain: chain,
        }),
        'user-1',
      ),
    );
    expect(error.detail).toMatch(/is not on the allowed list/);
  });

  it('refuses a passkey with no attestation when attestation is required', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const chain = createChain({ aaguid: authenticator.aaguid });
    const server = makeServer({
      attestation: { formats: ['packed'], trustAnchors: [chain.root.der] },
    });

    const options = await server.startRegistration({ userId: 'user-1', userName: 'ada' });
    const error = await rejection(
      server.finishRegistration(
        // A plain passkey: `none` attestation, which the policy no longer accepts.
        await authenticator.register({
          challenge: fromB64u(options.challenge),
          origin: ORIGIN,
          rpId: RP_ID,
        }),
        'user-1',
      ),
    );
    expect(error.detail).toMatch(/is not accepted/);
  });
});

describe('assertions that identify nobody', () => {
  it('refuses when nothing names the user', async () => {
    // No stored owner, no challenge context, no user handle. Guessing would be
    // worse than refusing.
    const server = makeServer();
    const authenticator = await VirtualAuthenticator.create();

    const registration = await server.startRegistration({ userId: 'user-1', userName: 'n' });
    const verified = await server.finishRegistration(
      await authenticator.register({
        challenge: fromB64u(registration.challenge),
        origin: ORIGIN,
        rpId: RP_ID,
      }),
    );

    const options = await server.startAuthentication();
    const assertion = await authenticator.authenticate({
      challenge: fromB64u(options.challenge),
      origin: ORIGIN,
      rpId: RP_ID,
    });

    const error = await rejection(
      server.finishAuthentication(assertion, {
        credentialId: verified.credentialId,
        publicKey: verified.credentialPublicKey,
        signCount: verified.signCount,
        // no userId
      }),
    );
    expect(error.detail).toMatch(/did not identify a user/);
  });

  it('falls back to the user handle when the credential has no owner', async () => {
    const server = makeServer();
    const authenticator = await VirtualAuthenticator.create();

    const registration = await server.startRegistration({ userId: 'user-1', userName: 'n' });
    const verified = await server.finishRegistration(
      await authenticator.register({
        challenge: fromB64u(registration.challenge),
        origin: ORIGIN,
        rpId: RP_ID,
      }),
    );

    const options = await server.startAuthentication();
    const result = await server.finishAuthentication(
      await authenticator.authenticate({
        challenge: fromB64u(options.challenge),
        origin: ORIGIN,
        rpId: RP_ID,
        userHandle: new TextEncoder().encode('user-1'),
        flags: FLAG_UP | FLAG_UV,
      }),
      {
        credentialId: verified.credentialId,
        publicKey: verified.credentialPublicKey,
        signCount: verified.signCount,
      },
    );

    expect(result.principal.userId).toBe('user-1');
  });
});
