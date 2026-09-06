import { describe, it, expect } from 'vitest';
import { createSign, generateKeyPairSync } from 'node:crypto';
import { AttestationError } from './attestation.js';
import { WebAuthnError, verifyRegistration, type RegistrationExpectations } from './ceremony.js';
import { ES256, EdDSA } from './cose.js';
import { VirtualAuthenticator, buildTpmPublic, encodeCbor, type Encodable } from './testing.js';
import { decodeCbor } from './cbor.js';
import {
  createCertificate,
  createChain,
  type CertificateChain,
  type GeneratedCertificate,
} from './x509-fixtures.js';

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

/**
 * Apple Anonymous Attestation — WebAuthn §8.8.
 *
 * The format carries no signature, which looks alarming until you see what
 * replaces it: the certificate itself holds a nonce equal to
 * SHA-256(authData || clientDataHash), put there by Apple when it issued the
 * certificate for *this* ceremony. Same binding strength, arriving differently.
 */
describe('apple attestation', () => {
  it('verifies a ceremony-bound certificate', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const root = createCertificate({ subject: 'Apple WebAuthn Root CA', isCa: true });

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      appleAttestation: { root },
    });

    const verified = await verifyRegistration(
      response,
      expectations(challenge, {
        attestation: { formats: ['apple'], trustAnchors: [root.der] },
      }),
    );

    expect(verified.attestationFormat).toBe('apple');
    expect(verified.attestationType).toBe('basic');
    expect(verified.aaguidVerified).toBe(true);
    expect(verified.attestationSubject).toContain('Apple Anonymous Attestation');
  });

  it('refuses a statement replayed against a different ceremony', async () => {
    // The nonce is the binding. A statement lifted from another registration
    // carries another ceremony's hash.
    const authenticator = await VirtualAuthenticator.create();
    const root = createCertificate({ subject: 'Apple WebAuthn Root CA', isCa: true });

    const first = await authenticator.register({
      challenge: challengeBytes(),
      origin: ORIGIN,
      rpId: RP_ID,
      appleAttestation: { root },
    });

    const error = await rejection(
      verifyRegistration(
        first,
        expectations(challengeBytes(), {
          attestation: { formats: ['apple'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toBeTruthy();
  });

  it('refuses a chain that reaches no configured root', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const attackerRoot = createCertificate({ subject: 'Not Apple', isCa: true });
    const realRoot = createCertificate({ subject: 'Apple WebAuthn Root CA', isCa: true });

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      appleAttestation: { root: attackerRoot },
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: { formats: ['apple'], trustAnchors: [realRoot.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/does not reach a trusted root/);
  });

  it('refuses apple with no trust anchors configured', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const root = createCertificate({ subject: 'Apple WebAuthn Root CA', isCa: true });

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      appleAttestation: { root },
    });

    const error = await rejection(
      verifyRegistration(response, expectations(challenge, { attestation: { formats: ['apple'] } })),
    );
    expect(error.detail).toMatch(/requires trustAnchors/);
  });

  it('refuses a certificate carrying no nonce extension', async () => {
    // Without the extension nothing ties the certificate to this ceremony —
    // and the format has no signature to fall back on.
    const authenticator = await VirtualAuthenticator.create();
    const root = createCertificate({ subject: 'Apple WebAuthn Root CA', isCa: true });
    const bare = createCertificate({ subject: 'No Nonce', issuer: root });

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      attestationFormat: 'apple',
      attestationChain: { root, leaf: bare },
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: { formats: ['apple'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/no Apple nonce extension/);
  });

  it('refuses a certificate whose subject key is not the credential key', async () => {
    // The check an implementation can silently skip. Without it a genuine
    // Apple certificate could be presented beside a credential key the
    // attacker holds, and every other check would still pass.
    const authenticator = await VirtualAuthenticator.create();
    const root = createCertificate({ subject: 'Apple WebAuthn Root CA', isCa: true });

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      appleAttestation: { root },
    });

    // Rebuild the statement around a certificate holding a different key,
    // keeping the correct nonce so only the key check can catch it.
    const decoded = decodeCbor(response.attestationObject) as Map<string, unknown>;
    const authData = decoded.get('authData') as Uint8Array;
    const clientDataHash = new Uint8Array(
      await crypto.subtle.digest('SHA-256', response.clientDataJSON),
    );
    const nonceInput = new Uint8Array(authData.length + clientDataHash.length);
    nonceInput.set(authData, 0);
    nonceInput.set(clientDataHash, authData.length);
    const nonce = new Uint8Array(await crypto.subtle.digest('SHA-256', nonceInput));

    const impostor = createCertificate({
      subject: 'Right Nonce, Wrong Key',
      issuer: root,
      appleNonce: nonce,
    });

    const swapped = encodeCbor(
      new Map<string, Encodable>([
        ['fmt', 'apple'],
        ['attStmt', new Map<string | number, Encodable>([['x5c', [impostor.der]]])],
        ['authData', authData],
      ]),
    );

    const error = await rejection(
      verifyRegistration(
        { clientDataJSON: response.clientDataJSON, attestationObject: swapped },
        expectations(challenge, {
          attestation: { formats: ['apple'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/does not match the attestation certificate/);
  });

  it('enforces an AAGUID allowlist', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const root = createCertificate({ subject: 'Apple WebAuthn Root CA', isCa: true });

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      appleAttestation: { root },
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: {
            formats: ['apple'],
            trustAnchors: [root.der],
            allowedAaguids: ['0'.repeat(32)],
          },
        }),
      ),
    );
    expect(error.detail).toMatch(/is not on the allowed list/);
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

// ─── TPM attestation helpers ───────────────────────────────────────────────

/** `tcg-kp-AIKCertificate` — the usage §8.3.1 requires of an attestation key. */
const AIK_EKU = '2.23.133.8.3';

/** The `attStmt` fields and `authData`, as a shape the tests can rebuild from. */
function statementParts(attestationObject: Uint8Array): {
  fields: Map<string | number, Encodable>;
  authData: Uint8Array;
} {
  const decoded = decodeCbor(attestationObject) as Map<string, unknown>;
  const attStmt = decoded.get('attStmt') as Map<string | number, unknown>;
  const fields = new Map<string | number, Encodable>();
  for (const [key, value] of attStmt) fields.set(key, value as Encodable);
  return { fields, authData: decoded.get('authData') as Uint8Array };
}

/** Re-encodes an attestation object around edited `attStmt` fields. */
function packStatement(
  format: string,
  fields: Map<string | number, Encodable>,
  authData: Uint8Array,
): Uint8Array {
  return encodeCbor(
    new Map<string, Encodable>([
      ['fmt', format],
      ['attStmt', fields],
      ['authData', authData],
    ]),
  );
}

/** Where `needle` starts in `haystack`, or -1. Used to find fields by content. */
function indexOfBytes(haystack: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i + needle.length <= haystack.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

/**
 * TPM attestation — WebAuthn §8.3. The path Windows Hello takes.
 *
 * A TPM signs neither the ceremony nor the credential key. It signs a
 * `TPMS_ATTEST` describing a key it certifies, and the tie back to this
 * registration runs through two indirections that both have to hold:
 * `certInfo.extraData` hashes `authData || clientDataHash`, and
 * `certInfo.attested.name` hashes `pubArea`. Check one without the other, or
 * skip the comparison of `pubArea` against the credential key, and a genuine
 * TPM signature ends up vouching for something no TPM ever attested to. Most
 * of what follows is about those three joins.
 */
describe('tpm attestation', () => {
  const vendorRoot = (): GeneratedCertificate =>
    createCertificate({ subject: 'TPM Vendor Root', isCa: true });

  it('verifies a real TPM statement', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const root = vendorRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root },
    });

    const verified = await verifyRegistration(
      response,
      expectations(challenge, {
        attestation: { formats: ['tpm'], trustAnchors: [root.der] },
      }),
    );

    expect(verified.attestationFormat).toBe('tpm');
    expect(verified.attestationType).toBe('basic');
    expect(verified.aaguidVerified).toBe(true);
    expect(verified.attestationSubject).toContain('TPM Vendor Root');
  });

  it('accepts the credential the ceremony produced', async () => {
    // A verifier that returned a key nobody attested to would still pass every
    // assertion above, so this walks the credential through an authentication.
    const authenticator = await VirtualAuthenticator.create();
    const root = vendorRoot();

    const challenge = challengeBytes();
    const verified = await verifyRegistration(
      await authenticator.register({
        challenge,
        origin: ORIGIN,
        rpId: RP_ID,
        tpmAttestation: { root },
      }),
      expectations(challenge, {
        attestation: { formats: ['tpm'], trustAnchors: [root.der] },
      }),
    );

    const { verifyAuthentication } = await import('./ceremony.js');
    const assertionChallenge = challengeBytes();
    const assertion = await authenticator.authenticate({
      challenge: assertionChallenge,
      origin: ORIGIN,
      rpId: RP_ID,
    });

    await expect(
      verifyAuthentication(assertion, {
        rpId: RP_ID,
        origin: ORIGIN,
        challenge: b64u(assertionChallenge),
        credential: {
          credentialId: verified.credentialId,
          publicKey: verified.credentialPublicKey,
          signCount: verified.signCount,
        },
      }),
    ).resolves.toBeTruthy();
  });

  it('refuses a tampered signature', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const root = vendorRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root },
      breakAttestationSignature: true,
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: { formats: ['tpm'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/signature did not verify/);
  });

  it('refuses a chain that reaches no configured root', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const attackerRoot = createCertificate({ subject: 'Not A Vendor', isCa: true });
    const realRoot = vendorRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root: attackerRoot },
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: { formats: ['tpm'], trustAnchors: [realRoot.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/does not reach a trusted root/);
  });

  it('refuses tpm with no trust anchors configured', async () => {
    // A chain nobody roots proves only that its own leaf signed something.
    const authenticator = await VirtualAuthenticator.create();
    const root = vendorRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root },
    });

    const error = await rejection(
      verifyRegistration(response, expectations(challenge, { attestation: { formats: ['tpm'] } })),
    );
    expect(error.detail).toMatch(/requires trustAnchors/);
  });

  it('refuses an AIK certificate without the tcg-kp-AIKCertificate usage', async () => {
    // §8.3.1. Without the usage restriction, any leaf the vendor root ever
    // issued — a TLS certificate, say — could sign TPM attestations.
    const authenticator = await VirtualAuthenticator.create();
    const root = vendorRoot();
    const plainLeaf = createCertificate({ subject: '', issuer: root });

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root, aik: plainLeaf },
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: { formats: ['tpm'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/tcg-kp-AIKCertificate/);
  });

  it('refuses an AIK certificate with a non-empty subject', async () => {
    // §8.3.1 wants the subject empty so the certificate does not itself become
    // a device identifier the relying party can track.
    const authenticator = await VirtualAuthenticator.create();
    const root = vendorRoot();
    const named = createCertificate({
      subject: 'Device 12345',
      issuer: root,
      extendedKeyUsage: [AIK_EKU],
    });

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root, aik: named },
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: { formats: ['tpm'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/subject must be empty/);
  });

  it('refuses a CA certificate as the AIK', async () => {
    // An attestation key that can also issue certificates is a key that can
    // mint more attestation keys.
    const authenticator = await VirtualAuthenticator.create();
    const root = vendorRoot();
    const caAik = createCertificate({
      subject: '',
      issuer: root,
      isCa: true,
      extendedKeyUsage: [AIK_EKU],
    });

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root, aik: caAik },
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: { formats: ['tpm'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/must not be a CA certificate/);
  });

  it('refuses a signed statement replayed onto another ceremony', async () => {
    // Both registrations use the same authenticator, so `pubArea`, the
    // attested name and `authData` are identical and only `extraData` can tell
    // the two ceremonies apart. That is exactly the check under test.
    const authenticator = await VirtualAuthenticator.create();
    const root = vendorRoot();
    const aik = createCertificate({ subject: '', issuer: root, extendedKeyUsage: [AIK_EKU] });

    const first = await authenticator.register({
      challenge: challengeBytes(),
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root, aik },
    });

    const secondChallenge = challengeBytes();
    const second = await authenticator.register({
      challenge: secondChallenge,
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root, aik },
    });

    const { fields } = statementParts(first.attestationObject);
    const { authData } = statementParts(second.attestationObject);

    const error = await rejection(
      verifyRegistration(
        {
          clientDataJSON: second.clientDataJSON,
          attestationObject: packStatement('tpm', fields, authData),
        },
        expectations(secondChallenge, {
          attestation: { formats: ['tpm'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/extraData does not hash this ceremony/);
  });

  it('refuses a pubArea describing a key that is not the credential', async () => {
    // The join an implementation can silently skip. Without it, a genuine TPM
    // statement stands beside a credential key the attacker generated, and
    // every signature in sight still verifies.
    const authenticator = await VirtualAuthenticator.create();
    const stranger = await VirtualAuthenticator.create();
    const root = vendorRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root },
    });

    const strangerJwk = await stranger.publicKeyJwk();
    const otherPubArea = buildTpmPublic(
      new Uint8Array(Buffer.from(strangerJwk.x as string, 'base64url')),
      new Uint8Array(Buffer.from(strangerJwk.y as string, 'base64url')),
    );

    const { fields, authData } = statementParts(response.attestationObject);
    fields.set('pubArea', otherPubArea);

    const error = await rejection(
      verifyRegistration(
        {
          clientDataJSON: response.clientDataJSON,
          attestationObject: packStatement('tpm', fields, authData),
        },
        expectations(challenge, {
          attestation: { formats: ['tpm'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/is not the credential key/);
  });

  it('refuses an attested name that does not describe the supplied pubArea', async () => {
    // Corrupting the digest inside `certInfo` breaks the name/pubArea join
    // while leaving `extraData` and the credential-key comparison intact.
    const authenticator = await VirtualAuthenticator.create();
    const root = vendorRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root },
    });

    const { fields, authData } = statementParts(response.attestationObject);
    const pubArea = fields.get('pubArea') as Uint8Array;
    const certInfo = Uint8Array.from(fields.get('certInfo') as Uint8Array);

    const nameDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', pubArea));
    const at = indexOfBytes(certInfo, nameDigest);
    expect(at).toBeGreaterThan(0);
    certInfo[at] = (certInfo[at] as number) ^ 0xff;
    fields.set('certInfo', certInfo);

    const error = await rejection(
      verifyRegistration(
        {
          clientDataJSON: response.clientDataJSON,
          attestationObject: packStatement('tpm', fields, authData),
        },
        expectations(challenge, {
          attestation: { formats: ['tpm'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/attested name does not describe/);
  });

  it('refuses a SHA-1 name algorithm', async () => {
    // TPM 2.0 permits SHA-1 as a nameAlg. A name is a hash whose only job is
    // to identify one key, which makes it precisely where a collision pays.
    const authenticator = await VirtualAuthenticator.create();
    const root = vendorRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root },
    });

    const { fields, authData } = statementParts(response.attestationObject);
    const pubArea = fields.get('pubArea') as Uint8Array;
    const certInfo = Uint8Array.from(fields.get('certInfo') as Uint8Array);

    // The two bytes ahead of the digest are the name algorithm.
    const nameDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', pubArea));
    const at = indexOfBytes(certInfo, nameDigest);
    expect(at).toBeGreaterThan(1);
    certInfo[at - 2] = 0x00;
    certInfo[at - 1] = 0x04; // TPM_ALG_SHA1
    fields.set('certInfo', certInfo);

    const error = await rejection(
      verifyRegistration(
        {
          clientDataJSON: response.clientDataJSON,
          attestationObject: packStatement('tpm', fields, authData),
        },
        expectations(challenge, {
          attestation: { formats: ['tpm'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/SHA-1 name algorithm is not accepted/);
  });

  it('refuses certInfo without TPM_GENERATED_VALUE', async () => {
    // The marker only a TPM is supposed to be able to place.
    const authenticator = await VirtualAuthenticator.create();
    const root = vendorRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root },
    });

    const { fields, authData } = statementParts(response.attestationObject);
    const certInfo = Uint8Array.from(fields.get('certInfo') as Uint8Array);
    certInfo[0] = 0x00;
    fields.set('certInfo', certInfo);

    const error = await rejection(
      verifyRegistration(
        {
          clientDataJSON: response.clientDataJSON,
          attestationObject: packStatement('tpm', fields, authData),
        },
        expectations(challenge, {
          attestation: { formats: ['tpm'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/TPM_GENERATED_VALUE/);
  });

  it('refuses an attestation that is not a TPM_ST_ATTEST_CERTIFY', async () => {
    // Other attestation types describe other things — a quote over PCRs, say.
    // Reading one of those as a key certification would be reading a different
    // sentence than the TPM signed.
    const authenticator = await VirtualAuthenticator.create();
    const root = vendorRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root },
    });

    const { fields, authData } = statementParts(response.attestationObject);
    const certInfo = Uint8Array.from(fields.get('certInfo') as Uint8Array);
    certInfo[4] = 0x80;
    certInfo[5] = 0x18; // TPM_ST_ATTEST_QUOTE
    fields.set('certInfo', certInfo);

    const error = await rejection(
      verifyRegistration(
        {
          clientDataJSON: response.clientDataJSON,
          attestationObject: packStatement('tpm', fields, authData),
        },
        expectations(challenge, {
          attestation: { formats: ['tpm'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/not a TPM_ST_ATTEST_CERTIFY/);
  });

  it.each([['pubArea'], ['certInfo']])('refuses a statement with no %s', async (field) => {
    const authenticator = await VirtualAuthenticator.create();
    const root = vendorRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root },
    });

    const { fields, authData } = statementParts(response.attestationObject);
    fields.delete(field);

    const error = await rejection(
      verifyRegistration(
        {
          clientDataJSON: response.clientDataJSON,
          attestationObject: packStatement('tpm', fields, authData),
        },
        expectations(challenge, {
          attestation: { formats: ['tpm'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/missing certInfo or pubArea/);
  });

  it('refuses a truncated pubArea', async () => {
    // Every length in these structures drives a read, which is the shape an
    // out-of-bounds bug takes. A structure cut short should be refused, with a
    // message about the structure rather than a stray runtime error.
    const authenticator = await VirtualAuthenticator.create();
    const root = vendorRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root },
    });

    const { fields, authData } = statementParts(response.attestationObject);
    const pubArea = fields.get('pubArea') as Uint8Array;
    fields.set('pubArea', pubArea.subarray(0, pubArea.length - 10));

    const error = await rejection(
      verifyRegistration(
        {
          clientDataJSON: response.clientDataJSON,
          attestationObject: packStatement('tpm', fields, authData),
        },
        expectations(challenge, {
          attestation: { formats: ['tpm'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toBeTruthy();
    expect(error.detail).not.toMatch(/Cannot read|RangeError|undefined/);
  });

  it('refuses a version other than 2.0', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const root = vendorRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root },
    });

    const { fields, authData } = statementParts(response.attestationObject);
    fields.set('ver', '1.2');

    const error = await rejection(
      verifyRegistration(
        {
          clientDataJSON: response.clientDataJSON,
          attestationObject: packStatement('tpm', fields, authData),
        },
        expectations(challenge, {
          attestation: { formats: ['tpm'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/unsupported TPM version/);
  });

  it('refuses an unsupported attestation algorithm', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const root = vendorRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root },
    });

    const { fields, authData } = statementParts(response.attestationObject);
    fields.set('alg', -8); // EdDSA, which the TPM formats do not carry

    const error = await rejection(
      verifyRegistration(
        {
          clientDataJSON: response.clientDataJSON,
          attestationObject: packStatement('tpm', fields, authData),
        },
        expectations(challenge, {
          attestation: { formats: ['tpm'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/unsupported TPM attestation algorithm/);
  });

  it('refuses a statement with no x5c chain', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const root = vendorRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root },
    });

    const { fields, authData } = statementParts(response.attestationObject);
    fields.delete('x5c');

    const error = await rejection(
      verifyRegistration(
        {
          clientDataJSON: response.clientDataJSON,
          attestationObject: packStatement('tpm', fields, authData),
        },
        expectations(challenge, {
          attestation: { formats: ['tpm'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/requires an x5c chain/);
  });

  it('enforces an AAGUID allowlist', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const root = vendorRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root },
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: {
            formats: ['tpm'],
            trustAnchors: [root.der],
            allowedAaguids: ['0'.repeat(32)],
          },
        }),
      ),
    );
    expect(error.detail).toMatch(/is not on the allowed list/);
  });

  it('refuses tpm when the policy does not list the format', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const root = vendorRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      tpmAttestation: { root },
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: { formats: ['packed'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/tpm/);
  });
});

/**
 * FIDO U2F attestation — WebAuthn §8.6. What a CTAP1 security key produces.
 *
 * The oldest of the formats and the plainest: one signature over a flat
 * concatenation that names the credential outright, with none of the
 * indirection TPM attestation carries. The interesting part is what it does
 * *not* say — U2F has no AAGUID, so a verified statement proves the hardware
 * and says nothing about the model, and the result has to report that
 * honestly rather than putting a manufacturer's name behind sixteen zero
 * bytes the client chose.
 */
describe('fido-u2f attestation', () => {
  const u2fRoot = (): GeneratedCertificate =>
    createCertificate({ subject: 'U2F Vendor Root', isCa: true });

  it('verifies a real U2F statement', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const root = u2fRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      u2fAttestation: { root },
    });

    const verified = await verifyRegistration(
      response,
      expectations(challenge, {
        attestation: { formats: ['fido-u2f'], trustAnchors: [root.der] },
      }),
    );

    expect(verified.attestationFormat).toBe('fido-u2f');
    expect(verified.attestationType).toBe('basic');
    expect(verified.attestationSubject).toContain('Ninsho U2F Attestation');
  });

  it('reports no verified AAGUID, because U2F conveys none', async () => {
    // The claim worth being careful about. The chain vouches for hardware;
    // nothing in it vouches for a model, and the AAGUID in the authenticator
    // data is sixteen zero bytes the client supplied.
    const authenticator = await VirtualAuthenticator.create();
    const root = u2fRoot();

    const challenge = challengeBytes();
    const verified = await verifyRegistration(
      await authenticator.register({
        challenge,
        origin: ORIGIN,
        rpId: RP_ID,
        u2fAttestation: { root },
      }),
      expectations(challenge, {
        attestation: { formats: ['fido-u2f'], trustAnchors: [root.der] },
      }),
    );

    expect(verified.aaguidVerified).toBe(false);
    expect(toHex(verified.aaguid)).toBe('0'.repeat(32));
  });

  it('refuses an AAGUID allowlist rather than failing it obscurely', async () => {
    // "0000… is not on the allowed list" would be true and useless. The
    // policy cannot be enforced on this format at all, and saying which is
    // the difference between a caller fixing their config and a caller
    // adding zeroes to their allowlist.
    const authenticator = await VirtualAuthenticator.create();
    const root = u2fRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      u2fAttestation: { root },
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: {
            formats: ['fido-u2f'],
            trustAnchors: [root.der],
            allowedAaguids: ['0'.repeat(32)],
          },
        }),
      ),
    );
    expect(error.detail).toMatch(/cannot be enforced on fido-u2f/);
  });

  it('accepts the credential the ceremony produced', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const root = u2fRoot();

    const challenge = challengeBytes();
    const verified = await verifyRegistration(
      await authenticator.register({
        challenge,
        origin: ORIGIN,
        rpId: RP_ID,
        u2fAttestation: { root },
      }),
      expectations(challenge, {
        attestation: { formats: ['fido-u2f'], trustAnchors: [root.der] },
      }),
    );

    const { verifyAuthentication } = await import('./ceremony.js');
    const assertionChallenge = challengeBytes();
    const assertion = await authenticator.authenticate({
      challenge: assertionChallenge,
      origin: ORIGIN,
      rpId: RP_ID,
    });

    await expect(
      verifyAuthentication(assertion, {
        rpId: RP_ID,
        origin: ORIGIN,
        challenge: b64u(assertionChallenge),
        credential: {
          credentialId: verified.credentialId,
          publicKey: verified.credentialPublicKey,
          signCount: verified.signCount,
        },
      }),
    ).resolves.toBeTruthy();
  });

  it('refuses a tampered signature', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const root = u2fRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      u2fAttestation: { root },
      breakAttestationSignature: true,
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: { formats: ['fido-u2f'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/signature did not verify/);
  });

  it('refuses a statement replayed onto another ceremony', async () => {
    // Same authenticator twice, so the authenticator data is byte-identical
    // and only the client data hash differs. The signature covers it, so the
    // splice fails on the signature rather than on anything incidental.
    const authenticator = await VirtualAuthenticator.create();
    const root = u2fRoot();

    const first = await authenticator.register({
      challenge: challengeBytes(),
      origin: ORIGIN,
      rpId: RP_ID,
      u2fAttestation: { root },
    });

    const secondChallenge = challengeBytes();
    const second = await authenticator.register({
      challenge: secondChallenge,
      origin: ORIGIN,
      rpId: RP_ID,
      u2fAttestation: { root },
    });

    const stolen = decodeCbor(first.attestationObject) as Map<string, unknown>;
    const target = decodeCbor(second.attestationObject) as Map<string, unknown>;

    const swapped = encodeCbor(
      new Map<string, Encodable>([
        ['fmt', 'fido-u2f'],
        ['attStmt', stolen.get('attStmt') as Encodable],
        ['authData', target.get('authData') as Uint8Array],
      ]),
    );

    const error = await rejection(
      verifyRegistration(
        { clientDataJSON: second.clientDataJSON, attestationObject: swapped },
        expectations(secondChallenge, {
          attestation: { formats: ['fido-u2f'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/signature did not verify/);
  });

  it('refuses a chain that reaches no configured root', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const attackerRoot = createCertificate({ subject: 'Not A Vendor', isCa: true });
    const realRoot = u2fRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      u2fAttestation: { root: attackerRoot },
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: { formats: ['fido-u2f'], trustAnchors: [realRoot.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/does not reach a trusted root/);
  });

  it('refuses fido-u2f with no trust anchors configured', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const root = u2fRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      u2fAttestation: { root },
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, { attestation: { formats: ['fido-u2f'] } }),
      ),
    );
    expect(error.detail).toMatch(/requires trustAnchors/);
  });

  it('refuses more than one certificate', async () => {
    // §8.6 permits exactly one. Accepting a list would mean accepting whichever
    // leaf the client picked out of certificates it supplied itself.
    const authenticator = await VirtualAuthenticator.create();
    const root = u2fRoot();
    const spare = createCertificate({ subject: 'Spare', issuer: root });

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      u2fAttestation: { root },
    });

    const decoded = decodeCbor(response.attestationObject) as Map<string, unknown>;
    const attStmt = decoded.get('attStmt') as Map<string | number, unknown>;
    const rebuilt = new Map<string | number, Encodable>();
    for (const [k, v] of attStmt) rebuilt.set(k, v as Encodable);
    rebuilt.set('x5c', [...(attStmt.get('x5c') as Uint8Array[]), spare.der]);

    const swapped = encodeCbor(
      new Map<string, Encodable>([
        ['fmt', 'fido-u2f'],
        ['attStmt', rebuilt],
        ['authData', decoded.get('authData') as Uint8Array],
      ]),
    );

    const error = await rejection(
      verifyRegistration(
        { clientDataJSON: response.clientDataJSON, attestationObject: swapped },
        expectations(challenge, {
          attestation: { formats: ['fido-u2f'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/permits exactly one/);
  });

  it('refuses an attestation certificate that is not P-256', async () => {
    // §8.6 fixes the curve. There is no `alg` field here to negotiate with, so
    // a certificate on another curve is a certificate this format cannot use.
    const authenticator = await VirtualAuthenticator.create();
    const root = u2fRoot();
    const wrongCurve = createCertificate({
      subject: 'Wrong Curve',
      issuer: root,
      keyPair: generateKeyPairSync('ec', { namedCurve: 'P-384' }),
    });

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      u2fAttestation: { root, leaf: wrongCurve },
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: { formats: ['fido-u2f'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/is not P-256/);
  });

  it('refuses a credential key that is not P-256', async () => {
    // The other half of the same rule: U2F keys are P-256, and a statement
    // presented beside an Ed25519 credential is describing something U2F
    // could not have produced.
    const ed = await VirtualAuthenticator.create(EdDSA);
    const root = u2fRoot();
    const leaf = createCertificate({ subject: 'Ninsho U2F Attestation', issuer: root });

    const challenge = challengeBytes();
    const response = await ed.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      attestationFormat: 'fido-u2f',
    });

    const decoded = decodeCbor(response.attestationObject) as Map<string, unknown>;
    const swapped = encodeCbor(
      new Map<string, Encodable>([
        ['fmt', 'fido-u2f'],
        [
          'attStmt',
          new Map<string | number, Encodable>([
            // Never checked: the curve rule is reached first, which is the
            // point — the credential is refused for what it is, not for a
            // signature that happens not to verify.
            ['sig', new Uint8Array(64)],
            ['x5c', [leaf.der]],
          ]),
        ],
        ['authData', decoded.get('authData') as Uint8Array],
      ]),
    );

    const error = await rejection(
      verifyRegistration(
        { clientDataJSON: response.clientDataJSON, attestationObject: swapped },
        expectations(challenge, {
          attestation: { formats: ['fido-u2f'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/P-256 only/);
  });

  it('refuses a statement with no signature', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const root = u2fRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      u2fAttestation: { root },
    });

    const decoded = decodeCbor(response.attestationObject) as Map<string, unknown>;
    const attStmt = decoded.get('attStmt') as Map<string | number, unknown>;

    const swapped = encodeCbor(
      new Map<string, Encodable>([
        ['fmt', 'fido-u2f'],
        ['attStmt', new Map<string | number, Encodable>([['x5c', [(attStmt.get('x5c') as Uint8Array[])[0] as Uint8Array]]])],
        ['authData', decoded.get('authData') as Uint8Array],
      ]),
    );

    const error = await rejection(
      verifyRegistration(
        { clientDataJSON: response.clientDataJSON, attestationObject: swapped },
        expectations(challenge, {
          attestation: { formats: ['fido-u2f'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/no signature/);
  });

  it('refuses a statement with no x5c chain', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const root = u2fRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      u2fAttestation: { root },
    });

    const decoded = decodeCbor(response.attestationObject) as Map<string, unknown>;
    const attStmt = decoded.get('attStmt') as Map<string | number, unknown>;

    const swapped = encodeCbor(
      new Map<string, Encodable>([
        ['fmt', 'fido-u2f'],
        ['attStmt', new Map<string | number, Encodable>([['sig', attStmt.get('sig') as Uint8Array]])],
        ['authData', decoded.get('authData') as Uint8Array],
      ]),
    );

    const error = await rejection(
      verifyRegistration(
        { clientDataJSON: response.clientDataJSON, attestationObject: swapped },
        expectations(challenge, {
          attestation: { formats: ['fido-u2f'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/requires an x5c chain/);
  });

  it('refuses fido-u2f when the policy does not list the format', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const root = u2fRoot();

    const challenge = challengeBytes();
    const response = await authenticator.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      u2fAttestation: { root },
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: { formats: ['packed'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/is not accepted/);
  });
});

/**
 * Android Keystore attestation — WebAuthn §8.4.
 *
 * The signature is over the ceremony and the certificate holds the credential
 * key, which on its own is what any self-signed chain can manage. What makes
 * the format mean something is the extension Keystore writes: the challenge
 * fixed when the key was *generated*, and the authorization list saying the
 * key was generated in the keystore, is a signing key, and is not usable by
 * every application on the device. Most of what follows is about those.
 */
describe('android-key attestation', () => {
  const keystoreRoot = (): GeneratedCertificate =>
    createCertificate({ subject: 'Android Keystore Root', isCa: true });

  const run = async (
    device: VirtualAuthenticator,
    root: GeneratedCertificate,
    spec: Record<string, unknown> = {},
    policy: Record<string, unknown> = {},
  ) => {
    const challenge = challengeBytes();
    const response = await device.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      androidKeyAttestation: { root, ...spec },
    });
    return {
      response,
      verify: () =>
        verifyRegistration(
          response,
          expectations(challenge, {
            attestation: { formats: ['android-key'], trustAnchors: [root.der], ...policy },
          }),
        ),
      challenge,
    };
  };

  it('verifies a genuine hardware-backed statement', async () => {
    const device = await VirtualAuthenticator.create();
    const root = keystoreRoot();

    const verified = await (await run(device, root)).verify();

    expect(verified.attestationFormat).toBe('android-key');
    expect(verified.attestationType).toBe('basic');
    expect(verified.aaguidVerified).toBe(true);
    expect(verified.attestationSubject).toContain('Android Keystore Key');
  });

  it('accepts the credential the ceremony produced', async () => {
    const device = await VirtualAuthenticator.create();
    const root = keystoreRoot();
    const verified = await (await run(device, root)).verify();

    const { verifyAuthentication } = await import('./ceremony.js');
    const assertionChallenge = challengeBytes();
    const assertion = await device.authenticate({
      challenge: assertionChallenge,
      origin: ORIGIN,
      rpId: RP_ID,
    });

    await expect(
      verifyAuthentication(assertion, {
        rpId: RP_ID,
        origin: ORIGIN,
        challenge: b64u(assertionChallenge),
        credential: {
          credentialId: verified.credentialId,
          publicKey: verified.credentialPublicKey,
          signCount: verified.signCount,
        },
      }),
    ).resolves.toBeTruthy();
  });

  it('refuses a tampered signature', async () => {
    const device = await VirtualAuthenticator.create();
    const root = keystoreRoot();

    const challenge = challengeBytes();
    const response = await device.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      androidKeyAttestation: { root },
      breakAttestationSignature: true,
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: { formats: ['android-key'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/signature did not verify/);
  });

  it('refuses a chain that reaches no configured root', async () => {
    const device = await VirtualAuthenticator.create();
    const attackerRoot = createCertificate({ subject: 'Not Google', isCa: true });
    const realRoot = keystoreRoot();

    const challenge = challengeBytes();
    const response = await device.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      androidKeyAttestation: { root: attackerRoot },
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: { formats: ['android-key'], trustAnchors: [realRoot.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/does not reach a trusted root/);
  });

  it('refuses android-key with no trust anchors configured', async () => {
    const device = await VirtualAuthenticator.create();
    const root = keystoreRoot();

    const challenge = challengeBytes();
    const response = await device.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      androidKeyAttestation: { root },
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, { attestation: { formats: ['android-key'] } }),
      ),
    );
    expect(error.detail).toMatch(/requires trustAnchors/);
  });

  it('refuses a challenge belonging to another ceremony', async () => {
    // The binding. Keystore fixes the challenge when the key is generated, so
    // a certificate carrying someone else's hash is a certificate minted for
    // someone else's registration.
    const device = await VirtualAuthenticator.create();
    const root = keystoreRoot();
    const { verify } = await run(device, root, { challengeOverride: new Uint8Array(32) });

    const error = await rejection(verify());
    expect(error.detail).toMatch(/attestation challenge is not this ceremony/);
  });

  it('refuses a certificate carrying no key attestation extension', async () => {
    // Without it the format degrades to "someone holds a certificate", which
    // is what any self-signed chain can say.
    const device = await VirtualAuthenticator.create();
    const root = keystoreRoot();

    const challenge = challengeBytes();
    const response = await device.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      androidKeyAttestation: { root },
    });

    const bare = createCertificate({
      subject: 'No Extension',
      issuer: root,
      keyPair: device.nodeKeyPair(),
    });

    const { fields, authData } = statementParts(response.attestationObject);
    fields.set('x5c', [bare.der]);

    const error = await rejection(
      verifyRegistration(
        {
          clientDataJSON: response.clientDataJSON,
          attestationObject: packStatement('android-key', fields, authData),
        },
        expectations(challenge, {
          attestation: { formats: ['android-key'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/no Android key attestation extension/);
  });

  it('refuses a certificate whose key is not the credential key', async () => {
    // The check that keeps a genuine Keystore certificate from vouching for a
    // key the attacker generated. The impostor signs the ceremony itself, so
    // only the key comparison can catch it.
    const device = await VirtualAuthenticator.create();
    const root = keystoreRoot();

    const challenge = challengeBytes();
    const response = await device.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      androidKeyAttestation: { root },
    });

    const clientDataHash = new Uint8Array(
      await crypto.subtle.digest('SHA-256', response.clientDataJSON),
    );
    const { fields, authData } = statementParts(response.attestationObject);

    const impostorKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const impostor = createCertificate({
      subject: 'Right Extension, Wrong Key',
      issuer: root,
      keyPair: impostorKey,
      androidKey: { challenge: clientDataHash },
    });

    const signedData = new Uint8Array(authData.length + clientDataHash.length);
    signedData.set(authData, 0);
    signedData.set(clientDataHash, authData.length);

    fields.set('sig', new Uint8Array(createSign('SHA256').update(signedData).sign(impostorKey.privateKey)));
    fields.set('x5c', [impostor.der]);

    const error = await rejection(
      verifyRegistration(
        {
          clientDataJSON: response.clientDataJSON,
          attestationObject: packStatement('android-key', fields, authData),
        },
        expectations(challenge, {
          attestation: { formats: ['android-key'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/does not match the attestation certificate/);
  });

  it.each([
    ['teeEnforced', { teeEnforced: { purposes: [2], origin: 0, allApplications: true } }],
    ['softwareEnforced', { softwareEnforced: { allApplications: true } }],
  ])('refuses allApplications in %s', async (_where, spec) => {
    // A key every application on the device can sign with is not scoped to
    // this relying party, and a credential another app can use is not a
    // credential.
    const device = await VirtualAuthenticator.create();
    const root = keystoreRoot();
    const { verify } = await run(device, root, spec);

    const error = await rejection(verify());
    expect(error.detail).toMatch(/usable by every application/);
  });

  it('refuses a key that was imported rather than generated', async () => {
    // KM_ORIGIN_IMPORTED. A key the keystore was handed is a key that existed
    // outside it first, which is the opposite of what attestation is for.
    const device = await VirtualAuthenticator.create();
    const root = keystoreRoot();
    const { verify } = await run(device, root, { teeEnforced: { purposes: [2], origin: 1 } });

    const error = await rejection(verify());
    expect(error.detail).toMatch(/not generated in the keystore/);
  });

  it('refuses a key not authorized for signing', async () => {
    const device = await VirtualAuthenticator.create();
    const root = keystoreRoot();
    // KM_PURPOSE_VERIFY only.
    const { verify } = await run(device, root, { teeEnforced: { purposes: [3], origin: 0 } });

    const error = await rejection(verify());
    expect(error.detail).toMatch(/not authorized for signing/);
  });

  it('refuses properties asserted only by software', async () => {
    // The default reading. A software-enforced authorization list is the OS
    // vouching for itself, and if that were enough there would be no reason to
    // be doing attestation.
    const device = await VirtualAuthenticator.create();
    const root = keystoreRoot();
    const { verify } = await run(device, root, {
      softwareEnforced: { purposes: [2], origin: 0 },
      teeEnforced: {},
    });

    const error = await rejection(verify());
    expect(error.detail).toMatch(/no hardware-enforced origin/);
  });

  it('accepts software-enforced properties when the caller opts in', async () => {
    // §8.4 permits it, so it is available — but it has to be asked for, and
    // what comes back is no longer a hardware claim.
    const device = await VirtualAuthenticator.create();
    const root = keystoreRoot();
    const { verify } = await run(
      device,
      root,
      { softwareEnforced: { purposes: [2], origin: 0 }, teeEnforced: {} },
      { allowSoftwareEnforcedAndroidKey: true },
    );

    await expect(verify()).resolves.toMatchObject({ attestationFormat: 'android-key' });
  });

  it('still refuses allApplications when software enforcement is allowed', async () => {
    const device = await VirtualAuthenticator.create();
    const root = keystoreRoot();
    const { verify } = await run(
      device,
      root,
      { softwareEnforced: { purposes: [2], origin: 0, allApplications: true }, teeEnforced: {} },
      { allowSoftwareEnforcedAndroidKey: true },
    );

    const error = await rejection(verify());
    expect(error.detail).toMatch(/usable by every application/);
  });

  it('refuses a truncated key description', async () => {
    const device = await VirtualAuthenticator.create();
    const root = keystoreRoot();
    const { verify } = await run(device, root, { fieldCount: 6 });

    const error = await rejection(verify());
    expect(error.detail).toMatch(/KeyDescription has 8 fields/);
  });

  it('refuses an unsupported attestation algorithm', async () => {
    const device = await VirtualAuthenticator.create();
    const root = keystoreRoot();

    const challenge = challengeBytes();
    const response = await device.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      androidKeyAttestation: { root },
    });

    const { fields, authData } = statementParts(response.attestationObject);
    fields.set('alg', -8); // EdDSA

    const error = await rejection(
      verifyRegistration(
        {
          clientDataJSON: response.clientDataJSON,
          attestationObject: packStatement('android-key', fields, authData),
        },
        expectations(challenge, {
          attestation: { formats: ['android-key'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/unsupported android-key attestation algorithm/);
  });

  it.each([['sig'], ['x5c']])('refuses a statement with no %s', async (field) => {
    const device = await VirtualAuthenticator.create();
    const root = keystoreRoot();

    const challenge = challengeBytes();
    const response = await device.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      androidKeyAttestation: { root },
    });

    const { fields, authData } = statementParts(response.attestationObject);
    fields.delete(field);

    const error = await rejection(
      verifyRegistration(
        {
          clientDataJSON: response.clientDataJSON,
          attestationObject: packStatement('android-key', fields, authData),
        },
        expectations(challenge, {
          attestation: { formats: ['android-key'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(field === 'sig' ? /has no signature/ : /requires an x5c chain/);
  });

  it('enforces an AAGUID allowlist', async () => {
    const device = await VirtualAuthenticator.create();
    const root = keystoreRoot();
    const { verify } = await run(device, root, {}, { allowedAaguids: ['0'.repeat(32)] });

    const error = await rejection(verify());
    expect(error.detail).toMatch(/is not on the allowed list/);
  });
});

/**
 * SafetyNet attestation — WebAuthn §8.5.
 *
 * The odd one out. Every other format is signed by the authenticator or by the
 * hardware holding the key; this one forwards a document *Google* composed
 * about the device, and the only thread back to this registration is a nonce.
 * So the tests are mostly about that thread, about the verdicts inside the
 * document, and about the header not being allowed to choose its own
 * algorithm.
 */
describe('android-safetynet attestation', () => {
  const googleRoot = (): GeneratedCertificate =>
    createCertificate({ subject: 'Google Attestation Root', isCa: true });

  const run = async (
    device: VirtualAuthenticator,
    root: GeneratedCertificate,
    spec: Record<string, unknown> = {},
    policy: Record<string, unknown> = {},
  ) => {
    const challenge = challengeBytes();
    const response = await device.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      safetyNetAttestation: { root, ...spec },
    });
    return {
      response,
      challenge,
      verify: () =>
        verifyRegistration(
          response,
          expectations(challenge, {
            attestation: {
              formats: ['android-safetynet'],
              trustAnchors: [root.der],
              ...policy,
            },
          }),
        ),
    };
  };

  it('verifies a genuine SafetyNet response', async () => {
    const device = await VirtualAuthenticator.create();
    const root = googleRoot();

    const verified = await (await run(device, root)).verify();

    expect(verified.attestationFormat).toBe('android-safetynet');
    expect(verified.attestationType).toBe('basic');
    expect(verified.attestationSubject).toContain('attest.android.com');
  });

  it('reports no verified AAGUID, because Google vouched for a device', async () => {
    // The claim to be careful with. Google inspected the device; nothing in
    // its reply says which authenticator model produced the credential, or
    // that the key lives in hardware at all.
    const device = await VirtualAuthenticator.create();
    const root = googleRoot();

    const verified = await (await run(device, root)).verify();
    expect(verified.aaguidVerified).toBe(false);
  });

  it('refuses an AAGUID allowlist rather than failing it obscurely', async () => {
    const device = await VirtualAuthenticator.create();
    const root = googleRoot();
    const { verify } = await run(device, root, {}, { allowedAaguids: ['0'.repeat(32)] });

    const error = await rejection(verify());
    expect(error.detail).toMatch(/cannot be enforced on android-safetynet/);
  });

  it('accepts the credential the ceremony produced', async () => {
    const device = await VirtualAuthenticator.create();
    const root = googleRoot();
    const verified = await (await run(device, root)).verify();

    const { verifyAuthentication } = await import('./ceremony.js');
    const assertionChallenge = challengeBytes();
    const assertion = await device.authenticate({
      challenge: assertionChallenge,
      origin: ORIGIN,
      rpId: RP_ID,
    });

    await expect(
      verifyAuthentication(assertion, {
        rpId: RP_ID,
        origin: ORIGIN,
        challenge: b64u(assertionChallenge),
        credential: {
          credentialId: verified.credentialId,
          publicKey: verified.credentialPublicKey,
          signCount: verified.signCount,
        },
      }),
    ).resolves.toBeTruthy();
  });

  it('refuses a tampered signature', async () => {
    const device = await VirtualAuthenticator.create();
    const root = googleRoot();

    const challenge = challengeBytes();
    const response = await device.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      safetyNetAttestation: { root },
      breakAttestationSignature: true,
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: { formats: ['android-safetynet'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/signature did not verify/);
  });

  it('refuses a nonce belonging to another ceremony', async () => {
    // The whole binding. Without it, one SafetyNet response would vouch for
    // every registration a device ever performs.
    const device = await VirtualAuthenticator.create();
    const root = googleRoot();
    const { verify } = await run(device, root, {
      nonceOverride: Buffer.alloc(32).toString('base64'),
    });

    const error = await rejection(verify());
    expect(error.detail).toMatch(/nonce does not hash this ceremony/);
  });

  it('refuses a response signed by a certificate for another host', async () => {
    // Google's verdict is Google's only because Google's certificate signed
    // it, and that certificate is the one issued to this hostname.
    const device = await VirtualAuthenticator.create();
    const root = googleRoot();
    const { verify } = await run(device, root, { hostname: 'attest.example.com' });

    const error = await rejection(verify());
    expect(error.detail).toMatch(/not issued to attest\.android\.com/);
  });

  it('refuses a device that failed the compatibility test suite', async () => {
    // `ctsProfileMatch: false` is a rooted or unlocked device — which is
    // exactly the device an attacker controls.
    const device = await VirtualAuthenticator.create();
    const root = googleRoot();
    const { verify } = await run(device, root, { ctsProfileMatch: false });

    const error = await rejection(verify());
    expect(error.detail).toMatch(/did not pass the compatibility test suite/);
  });

  it('refuses a device passing basicIntegrity alone', async () => {
    // The distinction that matters: a rooted phone can still report
    // `basicIntegrity: true`, so accepting on that would accept the case the
    // check exists for.
    const device = await VirtualAuthenticator.create();
    const root = googleRoot();
    const { verify } = await run(device, root, {
      ctsProfileMatch: false,
      basicIntegrity: true,
    });

    const error = await rejection(verify());
    expect(error.detail).toMatch(/did not pass the compatibility test suite/);
  });

  it('refuses a response captured from an earlier session', async () => {
    const device = await VirtualAuthenticator.create();
    const root = googleRoot();
    const { verify } = await run(device, root, {
      timestampMs: Date.now() - 40 * 60 * 1000,
    });

    const error = await rejection(verify());
    expect(error.detail).toMatch(/is \d+s old/);
  });

  it('refuses a response timestamped in the future', async () => {
    const device = await VirtualAuthenticator.create();
    const root = googleRoot();
    const { verify } = await run(device, root, { timestampMs: Date.now() + 10 * 60 * 1000 });

    const error = await rejection(verify());
    expect(error.detail).toMatch(/timestamped in the future/);
  });

  it.each([['none'], ['HS256'], ['ES256'], ['RS512']])(
    'refuses a JWS header naming alg %s',
    async (alg) => {
      // The header names its own algorithm, which is the shape every
      // algorithm-confusion attack is built on. SafetyNet is signed with RSA
      // and nothing else is accepted — an allowlist of exactly one.
      const device = await VirtualAuthenticator.create();
      const root = googleRoot();
      const { verify } = await run(device, root, { algOverride: alg });

      const error = await rejection(verify());
      expect(error.detail).toMatch(/unsupported SafetyNet algorithm/);
    },
  );

  it('refuses a chain that reaches no configured root', async () => {
    const device = await VirtualAuthenticator.create();
    const attackerRoot = createCertificate({ subject: 'Not Google', isCa: true });
    const realRoot = googleRoot();

    const challenge = challengeBytes();
    const response = await device.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      safetyNetAttestation: { root: attackerRoot },
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, {
          attestation: { formats: ['android-safetynet'], trustAnchors: [realRoot.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(/does not reach a trusted root/);
  });

  it('refuses android-safetynet with no trust anchors configured', async () => {
    const device = await VirtualAuthenticator.create();
    const root = googleRoot();

    const challenge = challengeBytes();
    const response = await device.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      safetyNetAttestation: { root },
    });

    const error = await rejection(
      verifyRegistration(
        response,
        expectations(challenge, { attestation: { formats: ['android-safetynet'] } }),
      ),
    );
    expect(error.detail).toMatch(/requires trustAnchors/);
  });

  it.each([['ver'], ['response']])('refuses a statement with no %s', async (field) => {
    const device = await VirtualAuthenticator.create();
    const root = googleRoot();

    const challenge = challengeBytes();
    const response = await device.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      safetyNetAttestation: { root },
    });

    const { fields, authData } = statementParts(response.attestationObject);
    fields.delete(field);

    const error = await rejection(
      verifyRegistration(
        {
          clientDataJSON: response.clientDataJSON,
          attestationObject: packStatement('android-safetynet', fields, authData),
        },
        expectations(challenge, {
          attestation: { formats: ['android-safetynet'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toMatch(field === 'ver' ? /no Play Services version/ : /carries no response/);
  });

  it.each([
    ['a response that is not a JWS', 'not.a.jws.at.all'],
    ['a JWS with two segments', 'aGVhZGVy.cGF5bG9hZA'],
    ['a header that is not base64url', 'he@der.cGF5bG9hZA.c2ln'],
    ['a header that is not JSON', 'bm90IGpzb24.cGF5bG9hZA.c2ln'],
  ])('refuses %s', async (_label, text) => {
    const device = await VirtualAuthenticator.create();
    const root = googleRoot();

    const challenge = challengeBytes();
    const response = await device.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      safetyNetAttestation: { root },
    });

    const { fields, authData } = statementParts(response.attestationObject);
    fields.set('response', new TextEncoder().encode(text));

    const error = await rejection(
      verifyRegistration(
        {
          clientDataJSON: response.clientDataJSON,
          attestationObject: packStatement('android-safetynet', fields, authData),
        },
        expectations(challenge, {
          attestation: { formats: ['android-safetynet'], trustAnchors: [root.der] },
        }),
      ),
    );
    expect(error.detail).toBeTruthy();
    expect(error.detail).not.toMatch(/Cannot read|undefined is not/);
  });

  it('never throws anything but a controlled error on random responses', async () => {
    // The response is a text document from a browser, parsed before anything
    // about it is trusted. An uncontrolled throw here would be a parser bug
    // reaching the caller as a 500 rather than a refusal.
    const device = await VirtualAuthenticator.create();
    const root = googleRoot();

    const challenge = challengeBytes();
    const response = await device.register({
      challenge,
      origin: ORIGIN,
      rpId: RP_ID,
      safetyNetAttestation: { root },
    });
    const { fields, authData } = statementParts(response.attestationObject);

    for (let i = 0; i < 300; i += 1) {
      const junk = new Uint8Array(Math.floor(Math.random() * 120));
      crypto.getRandomValues(junk);
      fields.set('response', junk);

      const error = await rejection(
        verifyRegistration(
          {
            clientDataJSON: response.clientDataJSON,
            attestationObject: packStatement('android-safetynet', fields, authData),
          },
          expectations(challenge, {
            attestation: { formats: ['android-safetynet'], trustAnchors: [root.der] },
          }),
        ),
      );
      expect(error.name).toBe('WebAuthnError');
    }
  });
});
