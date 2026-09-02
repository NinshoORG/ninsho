import { describe, it, expect } from 'vitest';
import { AttestationError } from './attestation.js';
import { WebAuthnError, verifyRegistration, type RegistrationExpectations } from './ceremony.js';
import { ES256 } from './cose.js';
import { VirtualAuthenticator } from './testing.js';
import { createCertificate, createChain, type CertificateChain } from './x509-fixtures.js';

const RP_ID = 'example.com';
const ORIGIN = 'https://example.com';

const challengeBytes = (): Uint8Array => {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytes;
};

const b64u = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');
const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

async function rejection(promise: Promise<unknown>): Promise<WebAuthnError> {
  try {
    await promise;
  } catch (error) {
    return error as WebAuthnError;
  }
  throw new Error('expected the promise to reject');
}

const expectations = (
  challenge: Uint8Array,
  overrides: Partial<RegistrationExpectations> = {},
): RegistrationExpectations => ({
  rpId: RP_ID,
  origin: ORIGIN,
  challenge: b64u(challenge),
  ...overrides,
});

/** Registers with a genuine packed statement signed by `chain`'s leaf. */
async function attest(
  authenticator: VirtualAuthenticator,
  chain: CertificateChain,
  overrides: Partial<RegistrationExpectations> = {},
  registerOverrides: { breakAttestationSignature?: boolean } = {},
) {
  const challenge = challengeBytes();
  const response = await authenticator.register({
    challenge,
    origin: ORIGIN,
    rpId: RP_ID,
    attestationChain: chain,
    ...registerOverrides,
  });
  return verifyRegistration(response, expectations(challenge, overrides));
}

/**
 * The whole point of attestation: proving a credential lives on hardware the
 * relying party approved, rather than merely that someone holds a key.
 */
describe('basic attestation with a trusted chain', () => {
  it('verifies a packed statement and vouches for the AAGUID', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const chain = createChain({ aaguid: authenticator.aaguid });

    const verified = await attest(authenticator, chain, {
      attestation: { formats: ['packed'], trustAnchors: [chain.root.der] },
    });

    expect(verified.attestationFormat).toBe('packed');
    expect(verified.attestationType).toBe('basic');
    // The claim that actually matters — a root the relying party trusts
    // vouched for this authenticator model.
    expect(verified.aaguidVerified).toBe(true);
    expect(verified.attestationSubject).toContain('Ninsho Test Authenticator');
    expect(toHex(verified.aaguid)).toBe(toHex(authenticator.aaguid));
  });

  it('enforces an AAGUID allowlist', async () => {
    // "Only issued YubiKeys may enrol", expressed as policy.
    const approved = await VirtualAuthenticator.create();
    const chain = createChain({ aaguid: approved.aaguid });

    await expect(
      attest(approved, chain, {
        attestation: {
          formats: ['packed'],
          trustAnchors: [chain.root.der],
          allowedAaguids: [toHex(approved.aaguid)],
        },
      }),
    ).resolves.toMatchObject({ aaguidVerified: true });
  });

  it('refuses an authenticator model that is not on the allowlist', async () => {
    const unapproved = await VirtualAuthenticator.create();
    const chain = createChain({ aaguid: unapproved.aaguid });

    const error = await rejection(
      attest(unapproved, chain, {
        attestation: {
          formats: ['packed'],
          trustAnchors: [chain.root.der],
          allowedAaguids: ['00000000000000000000000000000000'],
        },
      }),
    );
    expect(error.detail).toMatch(/is not on the allowed list/);
  });

  it('verifies through an intermediate CA', async () => {
    // Real manufacturer chains are rarely two links.
    const authenticator = await VirtualAuthenticator.create();
    const root = createCertificate({ subject: 'Vendor Root', isCa: true });
    const intermediate = createCertificate({
      subject: 'Vendor Issuing CA',
      issuer: root,
      isCa: true,
    });
    const leaf = createCertificate({
      subject: 'Vendor Authenticator',
      issuer: intermediate,
      aaguid: authenticator.aaguid,
    });

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      attestationChain: { root: intermediate, leaf },
      // As a real authenticator does: leaf and intermediate travel together,
      // and the root is configured by the relying party out of band.
      attestationIntermediates: [intermediate.der],
    });

    // x5c carries leaf and intermediate; only the root is configured as trusted.
    const verified = await verifyRegistration(
      response,
      expectations(challenge, {
        attestation: { formats: ['packed'], trustAnchors: [root.der] },
      }),
    );
    expect(verified.attestationType).toBe('basic');
  });
});

describe('attestation that must be refused', () => {
  it('refuses a chain that does not reach a configured root', async () => {
    // The attacker generates their own perfectly valid CA and signs a
    // statement with it. Everything is internally consistent; it just is not
    // vouched for by anyone the relying party trusts.
    const authenticator = await VirtualAuthenticator.create();
    const attackerChain = createChain({ aaguid: authenticator.aaguid });
    const trustedRoot = createCertificate({ subject: 'Real Vendor Root', isCa: true });

    const error = await rejection(
      attest(authenticator, attackerChain, {
        attestation: { formats: ['packed'], trustAnchors: [trustedRoot.der] },
      }),
    );
    expect(error.detail).toMatch(/does not reach a trusted root/);
  });

  it('refuses a tampered attestation signature', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const chain = createChain({ aaguid: authenticator.aaguid });

    const error = await rejection(
      attest(
        authenticator,
        chain,
        { attestation: { formats: ['packed'], trustAnchors: [chain.root.der] } },
        { breakAttestationSignature: true },
      ),
    );
    expect(error.detail).toMatch(/attestation signature did not verify/);
  });

  it('refuses a certificate whose AAGUID contradicts the authenticator data', async () => {
    // A statement lifted from a different device would look like this.
    const authenticator = await VirtualAuthenticator.create();
    const chain = createChain({ aaguid: new Uint8Array(16).fill(0x99) });

    const error = await rejection(
      attest(authenticator, chain, {
        attestation: { formats: ['packed'], trustAnchors: [chain.root.der] },
      }),
    );
    expect(error.detail).toMatch(/certificate AAGUID does not match/);
  });

  it('refuses a CA certificate presented as the attestation leaf', async () => {
    // A CA leaf could sign for other authenticators too, so §8.2.1 forbids it.
    const authenticator = await VirtualAuthenticator.create();
    const root = createCertificate({ subject: 'Root', isCa: true });
    const caLeaf = createCertificate({
      subject: 'Improper CA Leaf',
      issuer: root,
      isCa: true,
      aaguid: authenticator.aaguid,
    });

    const error = await rejection(
      attest(
        authenticator,
        { root, leaf: caLeaf },
        { attestation: { formats: ['packed'], trustAnchors: [root.der] } },
      ),
    );
    expect(error.detail).toMatch(/must not be a CA certificate/);
  });

  it('refuses an expired attestation certificate', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const root = createCertificate({ subject: 'Root', isCa: true });
    const leaf = createCertificate({
      subject: 'Expired Authenticator',
      issuer: root,
      aaguid: authenticator.aaguid,
      notBefore: new Date('2020-01-01T00:00:00Z'),
      notAfter: new Date('2021-01-01T00:00:00Z'),
    });

    const error = await rejection(
      attest(
        authenticator,
        { root, leaf },
        { attestation: { formats: ['packed'], trustAnchors: [root.der] } },
      ),
    );
    expect(error.detail).toMatch(/does not reach a trusted root/);
  });

  it('refuses packed with no trust anchors configured', async () => {
    // The check that keeps this module honest: without roots there is nothing
    // to verify against, and reporting success would manufacture confidence.
    const authenticator = await VirtualAuthenticator.create();
    const chain = createChain({ aaguid: authenticator.aaguid });

    const error = await rejection(
      attest(authenticator, chain, { attestation: { formats: ['packed'] } }),
    );
    expect(error.detail).toMatch(/requires trustAnchors/);
  });

  it('refuses packed when the policy did not allow the format', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const chain = createChain({ aaguid: authenticator.aaguid });

    const error = await rejection(
      attest(authenticator, chain, {
        attestation: { formats: ['none'], trustAnchors: [chain.root.der] },
      }),
    );
    expect(error.detail).toMatch(/is not accepted/);
  });

  it('refuses a trust anchor that is not a certificate', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const chain = createChain({ aaguid: authenticator.aaguid });

    const error = await rejection(
      attest(authenticator, chain, {
        attestation: { formats: ['packed'], trustAnchors: [new Uint8Array([1, 2, 3])] },
      }),
    );
    expect(error.detail).toMatch(/trust anchor is not a valid certificate/);
  });
});

describe('self-attestation', () => {
  it('is refused by default', async () => {
    // It conveys no hardware provenance, and a relying party that asked for
    // attestation almost certainly wanted provenance.
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      selfAttested: true,
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, { attestation: { formats: ['packed'] } }),
      ),
    );
    expect(error.detail).toMatch(/self-attestation is not accepted/);
  });

  it('verifies when explicitly allowed, and still vouches for nothing', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      selfAttested: true,
    });

    const verified = await verifyRegistration(
      response,
      expectations(challenge, {
        attestation: { formats: ['packed'], allowSelfAttestation: true },
      }),
    );

    expect(verified.attestationType).toBe('self');
    // The signature checked out, and it still establishes no provenance. The
    // result says so rather than leaving a caller to infer it.
    expect(verified.aaguidVerified).toBe(false);
  });

  it('refuses a tampered self-attestation signature', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      selfAttested: true,
      breakAttestationSignature: true,
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: { formats: ['packed'], allowSelfAttestation: true },
        }),
      ),
    );
    expect(error.detail).toMatch(/self-attestation signature did not verify/);
  });

  it('refuses an AAGUID allowlist against self-attestation', async () => {
    // Enforcing a hardware allowlist against a statement that vouches for no
    // hardware would be a policy that silently means nothing.
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      selfAttested: true,
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: {
            formats: ['packed'],
            allowSelfAttestation: true,
            allowedAaguids: [toHex(authenticator.aaguid)],
          },
        }),
      ),
    );
    expect(error.detail).toMatch(/cannot be enforced against self-attestation/);
  });
});

describe('the none format', () => {
  it('reports that it established nothing', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const response = await authenticator.register({ challenge, origin: ORIGIN, rpId: RP_ID });

    const verified = await verifyRegistration(response, expectations(challenge));
    expect(verified.attestationType).toBe('none');
    expect(verified.aaguidVerified).toBe(false);
    expect(verified.attestationSubject).toBeUndefined();
  });

  it('refuses an AAGUID allowlist, which it cannot possibly enforce', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const response = await authenticator.register({ challenge, origin: ORIGIN, rpId: RP_ID });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: { formats: ['none'], allowedAaguids: [toHex(authenticator.aaguid)] },
        }),
      ),
    );
    expect(error.detail).toMatch(/requires attestation/);
  });

  it('refuses a none statement carrying hidden fields', async () => {
    // §8.7 requires it to be empty. Data in a field nobody reads is data
    // nobody is checking.
    const authenticator = await VirtualAuthenticator.create();
    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      selfAttested: true,
      attestationFormat: 'none', // a populated statement labelled `none`
    });

    const error = await rejection(verifyRegistration(response, expectations(challenge)));
    expect(error.detail).toMatch(/none attestation statement must be empty/);
  });
});

describe('malformed statements', () => {
  it('reports every failure as a WebAuthnError, never an uncontrolled throw', async () => {
    // The caller maps this one class onto a 400. Anything escaping becomes a
    // 500 for what is really a bad request.
    const authenticator = await VirtualAuthenticator.create();
    const chain = createChain({ aaguid: authenticator.aaguid });

    const policies: Partial<RegistrationExpectations>[] = [
      { attestation: { formats: ['packed'] } },
      { attestation: { formats: ['packed'], trustAnchors: [new Uint8Array(0)] } },
      { attestation: { formats: [] } },
    ];

    for (const overrides of policies) {
      const error = await rejection(attest(authenticator, chain, overrides));
      expect(error).toBeInstanceOf(WebAuthnError);
      expect(error.status).toBe(400);
    }
  });

  it('never leaks the failed check to the client', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const chain = createChain({ aaguid: new Uint8Array(16).fill(1) });

    const error = await rejection(
      attest(authenticator, chain, {
        attestation: { formats: ['packed'], trustAnchors: [chain.root.der] },
      }),
    );

    expect(JSON.stringify(error.toResponse())).not.toMatch(/aaguid|certificate|chain|anchor/i);
    expect(error.detail).toBeTruthy();
  });

  it('exports AttestationError for callers that catch it directly', () => {
    expect(new AttestationError('x')).toBeInstanceOf(Error);
    expect(new AttestationError('x').name).toBe('AttestationError');
  });
});

describe('the credential still works after attestation', () => {
  it('produces a key that verifies a later assertion', async () => {
    // Attestation must not disturb the thing registration exists to produce.
    const authenticator = await VirtualAuthenticator.create(ES256);
    const chain = createChain({ aaguid: authenticator.aaguid });

    const verified = await attest(authenticator, chain, {
      attestation: { formats: ['packed'], trustAnchors: [chain.root.der] },
    });

    const { verifyAuthentication } = await import('./ceremony.js');
    const challenge = challengeBytes();
    const assertion = await authenticator.authenticate({ challenge, origin: ORIGIN, rpId: RP_ID });

    await expect(
      verifyAuthentication(assertion, {
        rpId: RP_ID,
        origin: ORIGIN,
        challenge: b64u(challenge),
        credential: {
          credentialId: verified.credentialId,
          publicKey: verified.credentialPublicKey,
          signCount: verified.signCount,
        },
      }),
    ).resolves.toBeTruthy();
  });
});
