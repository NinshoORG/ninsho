import { describe, it, expect } from 'vitest';
import {
  MetadataError,
  parseMetadataBlob,
  toAttestationPolicy,
  type MetadataBlob,
} from './mds.js';
import { verifyRegistration } from './ceremony.js';
import { VirtualAuthenticator, buildMetadataBlob, createCertificate } from './testing.js';

/**
 * The FIDO Metadata Service — the answer to "where do the trust anchors come
 * from", and a document whose *contents* are a security decision rather than
 * data. An entry says which roots to trust for a model; a status report says
 * whether that model's attestation key is known to be in someone else's hands.
 * Reading either carelessly turns a safety mechanism into a list of devices an
 * attacker would like you to trust.
 */

const RP_ID = 'example.com';
const ORIGIN = 'https://example.com';

const challengeBytes = (): Uint8Array => {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytes;
};

const b64u = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');
const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

function caught(fn: () => unknown): Error {
  try {
    fn();
  } catch (error) {
    return error as Error;
  }
  throw new Error('expected the call to throw');
}

const fidoRoot = () => createCertificate({ subject: 'FIDO Alliance Root', isCa: true });

describe('parsing a metadata BLOB', () => {
  it('verifies a BLOB signed by a chain reaching the configured root', () => {
    const root = fidoRoot();
    const vendor = createCertificate({ subject: 'Vendor Root', isCa: true });

    const blob = buildMetadataBlob({
      root,
      number: 91,
      entries: [
        {
          aaguid: '0132d110-bf4e-4208-a403-ab4f5f12efe5',
          description: 'A Certified Key',
          attestationRootCertificates: [vendor.der],
        },
      ],
    });

    const parsed = parseMetadataBlob(blob, { trustAnchors: [root.der] });

    expect(parsed.number).toBe(91);
    expect(parsed.entries).toHaveLength(1);
    expect(parsed.entries[0]?.aaguid).toBe('0132d110bf4e4208a403ab4f5f12efe5');
    expect(parsed.entries[0]?.description).toBe('A Certified Key');
    expect(parsed.entries[0]?.attestationRootCertificates).toHaveLength(1);
  });

  it('refuses a BLOB with no trust anchors configured', () => {
    // An unrooted list of trusted devices is a list anyone can write.
    const root = fidoRoot();
    const blob = buildMetadataBlob({ root, entries: [] });

    const error = caught(() => parseMetadataBlob(blob, { trustAnchors: [] }));
    expect(error.message).toMatch(/requires trustAnchors/);
  });

  it('refuses a BLOB signed by a chain reaching no configured root', () => {
    const root = fidoRoot();
    const impostorRoot = createCertificate({ subject: 'Not FIDO', isCa: true });
    const blob = buildMetadataBlob({ root: impostorRoot, entries: [] });

    const error = caught(() => parseMetadataBlob(blob, { trustAnchors: [root.der] }));
    expect(error.message).toMatch(/does not reach a trusted root/);
  });

  it('refuses a tampered signature', () => {
    const root = fidoRoot();
    const blob = buildMetadataBlob({ root, entries: [], breakSignature: true });

    const error = caught(() => parseMetadataBlob(blob, { trustAnchors: [root.der] }));
    expect(error.message).toMatch(/signature did not verify/);
  });

  it.each([['none'], ['HS256'], ['ES256'], ['RS512']])(
    'refuses a header naming alg %s',
    (alg) => {
      // A JWS header names its own algorithm. FIDO signs with RSA, so the
      // allowlist has one entry and the document has nothing to negotiate.
      const root = fidoRoot();
      const blob = buildMetadataBlob({ root, entries: [], algOverride: alg });

      const error = caught(() => parseMetadataBlob(blob, { trustAnchors: [root.der] }));
      expect(error.message).toMatch(/unsupported metadata BLOB algorithm/);
    },
  );

  it('refuses a BLOB that was due to be replaced', () => {
    // The failure mode that matters. A stale BLOB still verifies and still
    // looks authoritative — and is missing every compromise published since.
    const root = fidoRoot();
    const blob = buildMetadataBlob({ root, entries: [], nextUpdate: '2020-01-01' });

    const error = caught(() => parseMetadataBlob(blob, { trustAnchors: [root.der] }));
    expect(error.message).toMatch(/due to be replaced on 2020-01-01/);
  });

  it('accepts a stale BLOB only when told to', () => {
    const root = fidoRoot();
    const blob = buildMetadataBlob({ root, entries: [], nextUpdate: '2020-01-01' });

    expect(
      parseMetadataBlob(blob, { trustAnchors: [root.der], allowStale: true }).nextUpdate,
    ).toBe('2020-01-01');
  });

  it('reads the clock from options, so freshness is testable', () => {
    const root = fidoRoot();
    const blob = buildMetadataBlob({ root, entries: [], nextUpdate: '2030-06-01' });

    expect(
      parseMetadataBlob(blob, {
        trustAnchors: [root.der],
        now: new Date('2030-05-31T00:00:00Z'),
      }).number,
    ).toBe(76);

    const error = caught(() =>
      parseMetadataBlob(blob, {
        trustAnchors: [root.der],
        now: new Date('2030-06-02T00:00:00Z'),
      }),
    );
    expect(error.message).toMatch(/due to be replaced/);
  });

  it.each([
    ['a document that is not a JWS', 'nope'],
    ['a header that is not base64url', 'he@der.cGF5bG9hZA.c2ln'],
    ['a header that is not JSON', 'bm90IGpzb24.cGF5bG9hZA.c2ln'],
  ])('refuses %s', (_label, text) => {
    const root = fidoRoot();
    const error = caught(() => parseMetadataBlob(text, { trustAnchors: [root.der] }));
    expect(error).toBeInstanceOf(MetadataError);
  });

  it('never throws anything but MetadataError on random input', () => {
    const root = fidoRoot();
    for (let i = 0; i < 500; i += 1) {
      const bytes = new Uint8Array(Math.floor(Math.random() * 90));
      crypto.getRandomValues(bytes);
      try {
        parseMetadataBlob(bytes, { trustAnchors: [root.der] });
      } catch (error) {
        if (!(error instanceof MetadataError)) {
          throw new Error(`uncontrolled ${(error as Error).constructor.name}`);
        }
      }
    }
  });

  it('orders status reports newest first, with undated ones last', () => {
    // The current status is read from the front of this list, so an undated
    // report must not become one by sorting to the top.
    const root = fidoRoot();
    const vendor = createCertificate({ subject: 'Vendor Root', isCa: true });
    const blob = buildMetadataBlob({
      root,
      entries: [
        {
          aaguid: '0132d110-bf4e-4208-a403-ab4f5f12efe5',
          attestationRootCertificates: [vendor.der],
          statusReports: [
            { status: 'FIDO_CERTIFIED_L1', effectiveDate: '2020-01-01' },
            { status: 'FIDO_CERTIFIED_L2', effectiveDate: '2023-01-01' },
            { status: 'NOT_FIDO_CERTIFIED' },
          ],
        },
      ],
    });

    const parsed = parseMetadataBlob(blob, { trustAnchors: [root.der] });
    expect(parsed.entries[0]?.statusReports.map((r) => r.status)).toEqual([
      'FIDO_CERTIFIED_L2',
      'FIDO_CERTIFIED_L1',
      'NOT_FIDO_CERTIFIED',
    ]);
  });
});

describe('building an attestation policy from metadata', () => {
  const withEntries = (
    root: ReturnType<typeof createCertificate>,
    entries: Parameters<typeof buildMetadataBlob>[0]['entries'],
  ): MetadataBlob =>
    parseMetadataBlob(buildMetadataBlob({ root, entries }), { trustAnchors: [root.der] });

  it('collects roots and AAGUIDs from certified entries', () => {
    const root = fidoRoot();
    const vendorA = createCertificate({ subject: 'Vendor A', isCa: true });
    const vendorB = createCertificate({ subject: 'Vendor B', isCa: true });

    const policy = toAttestationPolicy(
      withEntries(root, [
        { aaguid: '00000000-0000-0000-0000-00000000000a', attestationRootCertificates: [vendorA.der] },
        { aaguid: '00000000-0000-0000-0000-00000000000b', attestationRootCertificates: [vendorB.der] },
      ]),
    );

    expect(policy.allowedAaguids).toEqual([
      '0000000000000000000000000000000a',
      '0000000000000000000000000000000b',
    ]);
    expect(policy.trustAnchors).toHaveLength(2);
  });

  it.each([
    ['ATTESTATION_KEY_COMPROMISE'],
    ['USER_VERIFICATION_BYPASS'],
    ['USER_KEY_REMOTE_COMPROMISE'],
    ['USER_KEY_PHYSICAL_COMPROMISE'],
    ['REVOKED'],
  ])('drops an entry whose history contains %s', (status) => {
    // The check with teeth. A compromise anywhere in the history disqualifies
    // the model, because a later certification does not un-leak the key that
    // vouches for every unit ever made.
    const root = fidoRoot();
    const vendor = createCertificate({ subject: 'Vendor', isCa: true });

    const policy = toAttestationPolicy(
      withEntries(root, [
        {
          aaguid: '00000000-0000-0000-0000-00000000000a',
          attestationRootCertificates: [vendor.der],
          statusReports: [
            { status, effectiveDate: '2021-01-01' },
            { status: 'FIDO_CERTIFIED_L2', effectiveDate: '2023-01-01' },
          ],
        },
      ]),
    );

    expect(policy.allowedAaguids).toEqual([]);
    expect(policy.trustAnchors).toEqual([]);
  });

  it('drops an entry whose current status is not accepted', () => {
    const root = fidoRoot();
    const vendor = createCertificate({ subject: 'Vendor', isCa: true });

    const policy = toAttestationPolicy(
      withEntries(root, [
        {
          aaguid: '00000000-0000-0000-0000-00000000000a',
          attestationRootCertificates: [vendor.der],
          statusReports: [{ status: 'SELF_ASSERTION_SUBMITTED', effectiveDate: '2023-01-01' }],
        },
      ]),
    );

    expect(policy.allowedAaguids).toEqual([]);
  });

  it('drops an entry carrying no roots', () => {
    // Including it would put an AAGUID on the allowlist that no chain could
    // ever satisfy — a policy that refuses a device for the wrong reason.
    const root = fidoRoot();

    const policy = toAttestationPolicy(
      withEntries(root, [{ aaguid: '00000000-0000-0000-0000-00000000000a' }]),
    );

    expect(policy.allowedAaguids).toEqual([]);
  });

  it('deduplicates a root shared by several models', () => {
    const root = fidoRoot();
    const vendor = createCertificate({ subject: 'Vendor', isCa: true });

    const policy = toAttestationPolicy(
      withEntries(root, [
        { aaguid: '00000000-0000-0000-0000-00000000000a', attestationRootCertificates: [vendor.der] },
        { aaguid: '00000000-0000-0000-0000-00000000000b', attestationRootCertificates: [vendor.der] },
      ]),
    );

    expect(policy.allowedAaguids).toHaveLength(2);
    expect(policy.trustAnchors).toHaveLength(1);
  });

  it('narrows to the models you name', () => {
    const root = fidoRoot();
    const vendorA = createCertificate({ subject: 'Vendor A', isCa: true });
    const vendorB = createCertificate({ subject: 'Vendor B', isCa: true });

    const policy = toAttestationPolicy(
      withEntries(root, [
        { aaguid: '00000000-0000-0000-0000-00000000000a', attestationRootCertificates: [vendorA.der] },
        { aaguid: '00000000-0000-0000-0000-00000000000b', attestationRootCertificates: [vendorB.der] },
      ]),
      { aaguids: ['0000000000000000000000000000000a'] },
    );

    expect(policy.allowedAaguids).toEqual(['0000000000000000000000000000000a']);
    expect(policy.trustAnchors).toHaveLength(1);
  });
});

/**
 * The point of all of it: a policy built from metadata has to be a policy the
 * verifier actually enforces. A parser that produced a plausible-looking object
 * the ceremony then ignored would be worse than no parser.
 */
describe('a metadata policy drives real verification', () => {
  it('admits the model the BLOB certifies, and refuses one it does not', async () => {
    const root = fidoRoot();
    const vendor = createCertificate({ subject: 'Vendor Root', isCa: true });

    const approved = await VirtualAuthenticator.create();
    const stranger = await VirtualAuthenticator.create();

    const policy = toAttestationPolicy(
      parseMetadataBlob(
        buildMetadataBlob({
          root,
          entries: [
            {
              aaguid: toHex(approved.aaguid),
              attestationRootCertificates: [vendor.der],
            },
          ],
        }),
        { trustAnchors: [root.der] },
      ),
    );

    const register = async (device: VirtualAuthenticator) => {
      const challenge = challengeBytes();
      const leaf = createCertificate({
        subject: 'Certified Authenticator',
        issuer: vendor,
        aaguid: device.aaguid,
      });
      const response = await device.register({
        challenge,
        origin: ORIGIN,
        rpId: RP_ID,
        attestationChain: { root: vendor, leaf },
      });
      return verifyRegistration(response, {
        rpId: RP_ID,
        origin: ORIGIN,
        challenge: b64u(challenge),
        attestation: policy,
      });
    };

    const verified = await register(approved);
    expect(verified.aaguidVerified).toBe(true);
    expect(toHex(verified.aaguid)).toBe(toHex(approved.aaguid));

    await expect(register(stranger)).rejects.toThrow();
  });

  it('stops admitting a model once the BLOB reports it compromised', async () => {
    // The whole reason to read status reports rather than only roots: the
    // chain still verifies, the certificate is still genuine, and the model is
    // no longer one to accept.
    const root = fidoRoot();
    const vendor = createCertificate({ subject: 'Vendor Root', isCa: true });
    const device = await VirtualAuthenticator.create();

    const register = async (policy: ReturnType<typeof toAttestationPolicy>) => {
      const challenge = challengeBytes();
      const leaf = createCertificate({
        subject: 'Certified Authenticator',
        issuer: vendor,
        aaguid: device.aaguid,
      });
      const response = await device.register({
        challenge,
        origin: ORIGIN,
        rpId: RP_ID,
        attestationChain: { root: vendor, leaf },
      });
      return verifyRegistration(response, {
        rpId: RP_ID,
        origin: ORIGIN,
        challenge: b64u(challenge),
        attestation: policy,
      });
    };

    const entry = {
      aaguid: toHex(device.aaguid),
      attestationRootCertificates: [vendor.der],
    };

    const before = toAttestationPolicy(
      parseMetadataBlob(buildMetadataBlob({ root, entries: [entry] }), {
        trustAnchors: [root.der],
      }),
    );
    await expect(register(before)).resolves.toBeTruthy();

    const after = toAttestationPolicy(
      parseMetadataBlob(
        buildMetadataBlob({
          root,
          entries: [
            {
              ...entry,
              statusReports: [
                { status: 'FIDO_CERTIFIED_L1', effectiveDate: '2023-01-01' },
                { status: 'ATTESTATION_KEY_COMPROMISE', effectiveDate: '2024-06-01' },
              ],
            },
          ],
        }),
        { trustAnchors: [root.der] },
      ),
    );
    await expect(register(after)).rejects.toThrow();
  });
});
