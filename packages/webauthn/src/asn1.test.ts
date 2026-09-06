import { describe, it, expect } from 'vitest';
import { X509Certificate } from 'node:crypto';
import { Asn1Error, encodeOid, findExtension, readTlv } from './asn1.js';
import { FIDO_AAGUID_OID, createCertificate, createChain } from './x509-fixtures.js';

const hex = (value: string): Uint8Array =>
  new Uint8Array((value.match(/../g) ?? []).map((b) => Number.parseInt(b, 16)));

const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

describe('OID encoding', () => {
  it.each([
    // The first two components pack into one byte as 40*a + b.
    ['2.5.29.19 (basicConstraints)', '2.5.29.19', '551d13'],
    ['2.5.4.3 (commonName)', '2.5.4.3', '550403'],
    ['1.2.840.10045.4.3.2 (ecdsa-with-SHA256)', '1.2.840.10045.4.3.2', '2a8648ce3d040302'],
    ['1.2.840.113549.1.1.11 (sha256WithRSA)', '1.2.840.113549.1.1.11', '2a864886f70d01010b'],
    // 45724 needs three base-128 groups, which is the case that catches an
    // encoder that only handles one continuation byte.
    ['the FIDO AAGUID OID', '1.3.6.1.4.1.45724.1.1.4', '2b060104018' + '2e51c010104'],
  ])('encodes %s', (_label, dotted, expected) => {
    expect(toHex(encodeOid(dotted))).toBe(expected);
  });

  it.each([['a single component', '1'], ['an empty string', ''], ['a negative component', '1.-2']])(
    'refuses %s',
    (_label, dotted) => {
      expect(() => encodeOid(dotted)).toThrow(Asn1Error);
    },
  );
});

describe('reading TLVs', () => {
  it('reads a short-form length', () => {
    const tlv = readTlv(hex('0403010203'), 0);
    expect(tlv.tag).toBe(0x04);
    expect(tlv.end - tlv.start).toBe(3);
    expect(tlv.next).toBe(5);
  });

  it('reads a long-form length', () => {
    // 0x81 0x80 = one length byte, value 128.
    const body = '04'.repeat(128);
    const tlv = readTlv(hex(`048180${body}`), 0);
    expect(tlv.end - tlv.start).toBe(128);
  });

  it.each([
    ['indefinite length', '0480'],
    ['the reserved length form', '04ff'],
    ['a non-minimal long form', '048101'],
    ['a redundant leading zero in the length', '04820080'],
    ['a tag number written in the long form when the short form would do', '1f0100'],
    ['a tag number with a zero leading group', 'bf800100'],
    ['a tag number needing more than three groups', 'bf8180808001 00'.replace(/ /g, '')],
    ['a truncated multi-byte tag', 'bf84'],
    ['a length wider than any certificate field', '0484ffffffff'],
    ['content running past the end', '040aff'],
    ['a truncated header', '04'],
  ])('refuses %s', (_label, encoded) => {
    expect(() => readTlv(hex(encoded), 0)).toThrow(Asn1Error);
  });

  it('reads a high-tag-number tag', () => {
    // `[600] EXPLICIT`, which is where Android's key attestation extension
    // puts `allApplications`. Refusing the form would mean refusing to read a
    // structure that is perfectly valid DER.
    const tlv = readTlv(hex('bf84580100'), 0);
    expect(tlv.number).toBe(600);
    expect(tlv.tag).toBe(0xbf);
    expect(tlv.end - tlv.start).toBe(1);
  });

  it('reports the tag number for the ordinary short form too', () => {
    expect(readTlv(hex('300100'), 0).number).toBe(0x10);
    expect(readTlv(hex('a30100'), 0).number).toBe(3);
  });

  it('never throws anything but Asn1Error on random input', () => {
    for (let i = 0; i < 3000; i += 1) {
      const bytes = new Uint8Array(Math.floor(Math.random() * 30));
      crypto.getRandomValues(bytes);
      try {
        readTlv(bytes, 0);
      } catch (error) {
        if (!(error instanceof Asn1Error)) {
          throw new Error(`uncontrolled ${(error as Error).constructor.name} for ${toHex(bytes)}`);
        }
      }
    }
  });
});

/**
 * The fixture generator has to produce real certificates, not merely
 * self-consistent ones. Node's X509Certificate is an independent parser: if
 * this encoder were wrong, it would reject the output.
 */
describe('the generated certificates are real certificates', () => {
  it('parses as X.509 in Node', () => {
    const cert = createCertificate({ subject: 'Ninsho Test Leaf' });
    const parsed = new X509Certificate(Buffer.from(cert.der));

    expect(parsed.subject).toContain('Ninsho Test Leaf');
    expect(parsed.publicKey.asymmetricKeyType).toBe('ec');
  });

  it('produces a chain whose signature Node verifies', () => {
    // The real test of the encoder: the TBS bytes it hashed must be exactly
    // the bytes Node re-reads and verifies.
    const { root, leaf } = createChain();
    const rootCert = new X509Certificate(Buffer.from(root.der));
    const leafCert = new X509Certificate(Buffer.from(leaf.der));

    expect(leafCert.verify(rootCert.publicKey)).toBe(true);
    expect(leafCert.checkIssued(rootCert)).toBe(true);
  });

  it('marks a CA as a CA and a leaf as not', () => {
    const { root, leaf } = createChain();
    expect(new X509Certificate(Buffer.from(root.der)).ca).toBe(true);
    expect(new X509Certificate(Buffer.from(leaf.der)).ca).toBe(false);
  });

  it('does not verify against an unrelated key', () => {
    const { leaf } = createChain();
    const stranger = createCertificate({ subject: 'Someone Else', isCa: true });

    expect(
      new X509Certificate(Buffer.from(leaf.der)).verify(
        new X509Certificate(Buffer.from(stranger.der)).publicKey,
      ),
    ).toBe(false);
  });

  it('produces a leaf that fails verification when signed by the wrong key', () => {
    const root = createCertificate({ subject: 'Root', isCa: true });
    const impostor = createCertificate({ subject: 'Impostor', isCa: true });
    const leaf = createCertificate({
      subject: 'Leaf',
      issuer: root,
      signWith: impostor.privateKey, // claims Root as issuer, signed by another
    });

    expect(
      new X509Certificate(Buffer.from(leaf.der)).verify(
        new X509Certificate(Buffer.from(root.der)).publicKey,
      ),
    ).toBe(false);
  });

  it('honours the validity window it was given', () => {
    const cert = createCertificate({
      subject: 'Dated',
      notBefore: new Date('2021-06-01T00:00:00Z'),
      notAfter: new Date('2031-06-01T00:00:00Z'),
    });
    const parsed = new X509Certificate(Buffer.from(cert.der));

    expect(parsed.validFromDate.getUTCFullYear()).toBe(2021);
    expect(parsed.validToDate.getUTCFullYear()).toBe(2031);
  });
});

describe('finding an extension by OID', () => {
  it('reads the AAGUID a certificate carries', () => {
    const aaguid = new Uint8Array(16).fill(0xab);
    const { leaf } = createChain({ aaguid });

    const value = findExtension(leaf.der, FIDO_AAGUID_OID);
    expect(value).toBeDefined();
    // The extension value is itself an OCTET STRING wrapping the 16 bytes.
    expect(toHex(value as Uint8Array)).toBe(`0410${toHex(aaguid)}`);
  });

  it('returns undefined when the certificate has no such extension', () => {
    const { leaf } = createChain(); // no aaguid
    expect(findExtension(leaf.der, FIDO_AAGUID_OID)).toBeUndefined();
  });

  it('finds an extension that is not the first one', () => {
    // basicConstraints is written first, so locating the AAGUID proves the
    // walk iterates rather than reading a fixed index.
    const aaguid = new Uint8Array(16).fill(0x11);
    const { leaf } = createChain({ aaguid });
    expect(findExtension(leaf.der, FIDO_AAGUID_OID)).toBeDefined();
    expect(findExtension(leaf.der, '2.5.29.19')).toBeDefined();
  });

  it('skips the optional critical BOOLEAN when reading a value', () => {
    // basicConstraints is written critical, so its value sits after a BOOLEAN.
    const { leaf } = createChain();
    const value = findExtension(leaf.der, '2.5.29.19');
    // An empty SEQUENCE — cA absent, therefore false.
    expect(toHex(value as Uint8Array)).toBe('3000');
  });

  it('does not confuse one OID for another with a shared prefix', () => {
    const aaguid = new Uint8Array(16).fill(7);
    const { leaf } = createChain({ aaguid });
    // A prefix of the FIDO OID must not match it.
    expect(findExtension(leaf.der, '1.3.6.1.4.1.45724.1.1')).toBeUndefined();
  });

  it.each([
    ['not a SEQUENCE', '020101'],
    ['an empty buffer', ''],
    ['a SEQUENCE containing no TBSCertificate', '3000'],
    ['a truncated certificate', '308201'],
  ])('refuses a certificate that is %s', (_label, encoded) => {
    expect(() => findExtension(hex(encoded), FIDO_AAGUID_OID)).toThrow(Asn1Error);
  });

  it('never throws anything but Asn1Error on a mutated certificate', () => {
    // Every single-byte mutation of a real certificate must either parse or be
    // refused cleanly — never crash the walk.
    const { leaf } = createChain({ aaguid: new Uint8Array(16).fill(3) });

    for (let i = 0; i < 400; i += 1) {
      const mutated = new Uint8Array(leaf.der);
      const index = Math.floor(Math.random() * mutated.length);
      mutated[index] = (mutated[index] as number) ^ (1 << Math.floor(Math.random() * 8));

      try {
        findExtension(mutated, FIDO_AAGUID_OID);
      } catch (error) {
        if (!(error instanceof Asn1Error)) {
          throw new Error(
            `uncontrolled ${(error as Error).constructor.name} at byte ${index}: ` +
              `${(error as Error).message}`,
          );
        }
      }
    }
  });
});
