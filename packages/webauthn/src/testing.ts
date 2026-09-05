/**
 * Test support — a CBOR encoder and a virtual authenticator.
 *
 * Published separately as `@ninsho/webauthn/testing`, so it is never pulled
 * into an application bundle that only imports the verifier.
 *
 * ─── Why this ships at all ────────────────────────────────────────────────
 * Testing a passkey integration otherwise means a physical authenticator and a
 * human finger, which is to say it does not get tested. `VirtualAuthenticator`
 * holds a real key pair and produces genuinely signed responses, so an
 * end-to-end test exercises the real verifier against real signatures.
 *
 * The encoder is here for the same reason it exists internally: the decoder
 * must be tested against inputs it did not produce, including inputs no real
 * authenticator would ever emit.
 *
 * ─── Why a production guard ───────────────────────────────────────────────
 * The precedent is `MemoryStore`: a test double may ship as long as it must be
 * named explicitly and cannot be selected by an environment variable. This one
 * gets the same `NODE_ENV=production` refusal, and it matters more here.
 *
 * A `VirtualAuthenticator` running server-side would mean the *server* holds
 * the credential's private key — which defeats the whole point of WebAuthn,
 * quietly, while every signature still verifies. That failure has no symptom
 * to notice, so it is refused rather than documented.
 * ──────────────────────────────────────────────────────────────────────────
 */

import { createSign, KeyObject, type webcrypto } from 'node:crypto';
import { ES256, EdDSA, RS256, type CoseAlgorithm } from './cose.js';
import { createCertificate, type CertificateChain, type GeneratedCertificate } from './x509-fixtures.js';

// ─── CBOR encoding ─────────────────────────────────────────────────────────

export type Encodable =
  | number
  | string
  | Uint8Array
  | boolean
  | null
  | Encodable[]
  | Map<string | number, Encodable>;

function head(major: number, argument: number): Uint8Array {
  if (argument < 24) return new Uint8Array([(major << 5) | argument]);
  if (argument < 0x100) return new Uint8Array([(major << 5) | 24, argument]);
  if (argument < 0x10000) {
    return new Uint8Array([(major << 5) | 25, argument >> 8, argument & 0xff]);
  }
  return new Uint8Array([
    (major << 5) | 26,
    (argument >>> 24) & 0xff,
    (argument >>> 16) & 0xff,
    (argument >>> 8) & 0xff,
    argument & 0xff,
  ]);
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/** Encodes the CBOR subset this package decodes. Definite lengths only. */
export function encodeCbor(value: Encodable): Uint8Array {
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new Error('only integers are encodable');
    return value >= 0 ? head(0, value) : head(1, -1 - value);
  }
  if (value instanceof Uint8Array) return concat([head(2, value.length), value]);
  if (typeof value === 'string') {
    const bytes = new TextEncoder().encode(value);
    return concat([head(3, bytes.length), bytes]);
  }
  if (Array.isArray(value)) {
    return concat([head(4, value.length), ...value.map(encodeCbor)]);
  }
  if (value instanceof Map) {
    const pairs = [...value.entries()].flatMap(([k, v]) => [encodeCbor(k), encodeCbor(v)]);
    return concat([head(5, value.size), ...pairs]);
  }
  if (value === false) return new Uint8Array([0xf4]);
  if (value === true) return new Uint8Array([0xf5]);
  if (value === null) return new Uint8Array([0xf6]);
  throw new Error(`not encodable: ${String(value)}`);
}

// ─── COSE key construction ─────────────────────────────────────────────────

const b64u = (value: string): Uint8Array => new Uint8Array(Buffer.from(value, 'base64url'));

/** Builds the COSE key map for a public key, as an authenticator would. */
export function coseKeyFromJwk(jwk: webcrypto.JsonWebKey, alg: CoseAlgorithm): Uint8Array {
  const map = new Map<number, Encodable>();

  if (alg === ES256) {
    map.set(1, 2); // kty: EC2
    map.set(3, alg);
    map.set(-1, 1); // crv: P-256
    map.set(-2, b64u(jwk.x as string));
    map.set(-3, b64u(jwk.y as string));
  } else if (alg === EdDSA) {
    map.set(1, 1); // kty: OKP
    map.set(3, alg);
    map.set(-1, 6); // crv: Ed25519
    map.set(-2, b64u(jwk.x as string));
  } else {
    map.set(1, 3); // kty: RSA
    map.set(3, alg);
    map.set(-1, b64u(jwk.n as string));
    map.set(-2, b64u(jwk.e as string));
  }

  return encodeCbor(map);
}

// ─── Virtual authenticator ─────────────────────────────────────────────────

const GENERATE_PARAMS: Record<CoseAlgorithm, webcrypto.EcKeyGenParams | webcrypto.RsaHashedKeyGenParams | string> = {
  [ES256]: { name: 'ECDSA', namedCurve: 'P-256' },
  [EdDSA]: 'Ed25519',
  [RS256]: {
    name: 'RSASSA-PKCS1-v1_5',
    // The smallest size the verifier accepts. Generating 4096-bit keys in a
    // test suite costs seconds per key for no extra coverage.
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: 'SHA-256',
  },
};

const SIGN_PARAMS: Record<CoseAlgorithm, webcrypto.EcdsaParams | string> = {
  [ES256]: { name: 'ECDSA', hash: 'SHA-256' },
  [EdDSA]: 'Ed25519',
  [RS256]: 'RSASSA-PKCS1-v1_5',
};

/**
 * Re-encodes a raw `r || s` ECDSA signature as ASN.1 DER, minimally.
 *
 * This is the inverse of what `der.ts` does, written independently so the two
 * are not the same code checking itself.
 */
export function rawToDerSignature(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;

  const integer = (value: Uint8Array): Uint8Array => {
    let start = 0;
    while (start < value.length - 1 && value[start] === 0) start += 1;
    let digits = value.subarray(start);
    // DER INTEGERs are signed, so a set high bit needs a zero byte in front.
    if ((digits[0] as number) & 0x80) {
      const padded = new Uint8Array(digits.length + 1);
      padded.set(digits, 1);
      digits = padded;
    }
    return concat([new Uint8Array([0x02, digits.length]), digits]);
  };

  const body = concat([integer(raw.subarray(0, half)), integer(raw.subarray(half))]);
  const header =
    body.length < 0x80
      ? new Uint8Array([0x30, body.length])
      : new Uint8Array([0x30, 0x81, body.length]);
  return concat([header, body]);
}

// ─── TPM structures, for the attestation fixtures ──────────────────────────

/** Big-endian u16, as every TPM length field is. */
function u16(value: number): Uint8Array {
  return new Uint8Array([(value >> 8) & 0xff, value & 0xff]);
}

/** Big-endian u32. */
function u32(value: number): Uint8Array {
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

/** A `TPM2B_*`: a two-byte length followed by the bytes. */
function sized(bytes: Uint8Array): Uint8Array {
  return concat([u16(bytes.length), bytes]);
}

/**
 * Builds a `TPMT_PUBLIC` describing a P-256 key.
 *
 * Written out rather than captured from a device, so the tests exercise the
 * parser against a structure whose every field is known — including the ones
 * the parser skips, which is where an offset error would hide.
 */
export function buildTpmPublic(x: Uint8Array, y: Uint8Array): Uint8Array {
  const TPM_ALG_ECC = 0x0023;
  const TPM_ALG_SHA256 = 0x000b;
  const TPM_ALG_NULL = 0x0010;
  const TPM_ECC_NIST_P256 = 0x0003;

  return concat([
    u16(TPM_ALG_ECC), // type
    u16(TPM_ALG_SHA256), // nameAlg
    u32(0x00050472), // objectAttributes — not consulted, but realistic
    sized(new Uint8Array(0)), // authPolicy
    u16(TPM_ALG_NULL), // symmetric
    u16(TPM_ALG_NULL), // scheme
    u16(TPM_ECC_NIST_P256), // curveID
    u16(TPM_ALG_NULL), // kdf
    sized(x),
    sized(y),
  ]);
}

/** Builds a `TPMS_ATTEST` certifying `pubArea` for one ceremony. */
export async function buildTpmCertInfo(
  pubArea: Uint8Array,
  attToBeSigned: Uint8Array,
): Promise<Uint8Array> {
  const TPM_GENERATED = 0xff544347;
  const TPM_ST_ATTEST_CERTIFY = 0x8017;
  const TPM_ALG_SHA256 = 0x000b;

  const extraData = new Uint8Array(await crypto.subtle.digest('SHA-256', attToBeSigned));
  // The name is `nameAlg || digest(pubArea)` — the tie between this statement
  // and a particular key.
  const nameDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', pubArea));
  const attestedName = concat([u16(TPM_ALG_SHA256), nameDigest]);

  return concat([
    u32(TPM_GENERATED),
    u16(TPM_ST_ATTEST_CERTIFY),
    sized(new Uint8Array(2)), // qualifiedSigner
    sized(extraData),
    new Uint8Array(17), // clockInfo
    new Uint8Array(8), // firmwareVersion
    sized(attestedName),
    sized(new Uint8Array(0)), // qualifiedName
  ]);
}

/** Authenticator data flags, WebAuthn §6.1. */
export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_BE = 0x08;
export const FLAG_BS = 0x10;
export const FLAG_AT = 0x40;
export const FLAG_ED = 0x80;

export interface AuthenticatorDataOptions {
  readonly rpId: string;
  readonly flags: number;
  readonly signCount: number;
  /** Present only when FLAG_AT is set. */
  readonly attestedCredential?: {
    readonly aaguid: Uint8Array;
    readonly credentialId: Uint8Array;
    readonly credentialPublicKey: Uint8Array;
  };
  readonly extensions?: Uint8Array;
  /** Overrides the computed RP ID hash, for tests that need a wrong one. */
  readonly rpIdHashOverride?: Uint8Array;
}

/** Builds authenticator data exactly as WebAuthn §6.1 lays it out. */
export async function buildAuthenticatorData(
  options: AuthenticatorDataOptions,
): Promise<Uint8Array> {
  const rpIdHash =
    options.rpIdHashOverride ??
    new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode(options.rpId)),
    );

  const counter = new Uint8Array(4);
  new DataView(counter.buffer).setUint32(0, options.signCount, false);

  const chunks: Uint8Array[] = [rpIdHash, new Uint8Array([options.flags]), counter];

  if (options.attestedCredential) {
    const { aaguid, credentialId, credentialPublicKey } = options.attestedCredential;
    const idLength = new Uint8Array(2);
    new DataView(idLength.buffer).setUint16(0, credentialId.length, false);
    chunks.push(aaguid, idLength, credentialId, credentialPublicKey);
  }

  if (options.extensions) chunks.push(options.extensions);

  return concat(chunks);
}

export interface RegistrationResult {
  readonly credentialId: Uint8Array;
  readonly attestationObject: Uint8Array;
  readonly clientDataJSON: Uint8Array;
}

export interface AssertionResult {
  readonly credentialId: Uint8Array;
  readonly authenticatorData: Uint8Array;
  readonly clientDataJSON: Uint8Array;
  readonly signature: Uint8Array;
  readonly userHandle: Uint8Array | undefined;
}

/**
 * A software authenticator that produces genuinely signed responses.
 *
 * It holds a real key pair and signs real data, so a verifier that accepts its
 * output has verified an actual signature. Every field a test might need to
 * corrupt is overridable, which is what makes the negative cases meaningful:
 * the only difference between the accepted case and the rejected one is the
 * single field under test.
 */
export class VirtualAuthenticator {
  readonly aaguid: Uint8Array;
  readonly credentialId: Uint8Array;
  #keyPair!: webcrypto.CryptoKeyPair;
  #signCount: number;

  private constructor(
    readonly alg: CoseAlgorithm,
    signCount: number,
  ) {
    this.aaguid = new Uint8Array(16);
    crypto.getRandomValues(this.aaguid);
    this.credentialId = new Uint8Array(32);
    crypto.getRandomValues(this.credentialId);
    this.#signCount = signCount;
  }

  static async create(alg: CoseAlgorithm = ES256, signCount = 0): Promise<VirtualAuthenticator> {
    if (process.env['NODE_ENV'] === 'production') {
      throw new Error(
        'VirtualAuthenticator cannot be used in production. It holds the ' +
          'credential private key on the server, which defeats the purpose of ' +
          'WebAuthn while every signature still verifies.',
      );
    }

    const authenticator = new VirtualAuthenticator(alg, signCount);
    authenticator.#keyPair = (await crypto.subtle.generateKey(
      GENERATE_PARAMS[alg] as webcrypto.EcKeyGenParams,
      true,
      ['sign', 'verify'],
    )) as webcrypto.CryptoKeyPair;
    return authenticator;
  }

  get signCount(): number {
    return this.#signCount;
  }

  set signCount(value: number) {
    this.#signCount = value;
  }

  /** The COSE-encoded public key, as it appears in attested credential data. */
  async coseKey(): Promise<Uint8Array> {
    const jwk = await crypto.subtle.exportKey('jwk', this.#keyPair.publicKey);
    return coseKeyFromJwk(jwk, this.alg);
  }

  /** Confirms the import parameters round-trip, used by the key tests. */
  async publicKeyJwk(): Promise<webcrypto.JsonWebKey> {
    return crypto.subtle.exportKey('jwk', this.#keyPair.publicKey);
  }

  /**
   * Signs as a real authenticator would.
   *
   * The DER re-encoding for ES256 is the whole point of this method. WebCrypto
   * produces raw `r || s`, but every real WebAuthn authenticator emits ASN.1
   * DER — so a harness that signed raw would make the verifier look correct
   * while it was in fact incompatible with all production hardware.
   */
  async sign(data: Uint8Array): Promise<Uint8Array> {
    const signature = new Uint8Array(
      await crypto.subtle.sign(SIGN_PARAMS[this.alg] as webcrypto.EcdsaParams, this.#keyPair.privateKey, data),
    );
    return this.alg === ES256 ? rawToDerSignature(signature) : signature;
  }

  clientData(type: string, challenge: Uint8Array, origin: string, extra?: object): Uint8Array {
    return new TextEncoder().encode(
      JSON.stringify({
        type,
        challenge: Buffer.from(challenge).toString('base64url'),
        origin,
        crossOrigin: false,
        ...extra,
      }),
    );
  }

  /**
   * Produces a registration response.
   *
   * Defaults to `none` attestation — a passkey. Pass `attestationChain` to
   * produce a genuine `packed` statement signed by that chain's leaf, or
   * `selfAttested` to have the credential key sign for itself.
   */
  async register(options: {
    challenge: Uint8Array;
    origin: string;
    rpId: string;
    flags?: number;
    clientDataOverride?: Uint8Array;
    rpIdHashOverride?: Uint8Array;
    attestationFormat?: string;
    /** Signs a packed statement with this chain's leaf certificate. */
    attestationChain?: CertificateChain;
    /**
     * Extra certificates to append to `x5c`, leaf-first.
     *
     * Real authenticators ship the intermediates alongside the leaf and leave
     * the root to be configured out of band, so a chain deeper than two links
     * needs them supplied here.
     */
    attestationIntermediates?: readonly Uint8Array[];
    /** Signs a packed statement with the credential key itself. */
    selfAttested?: boolean;
    /** Corrupts the attestation signature, to test that it is checked. */
    breakAttestationSignature?: boolean;
    /**
     * Produces an Apple Anonymous Attestation instead.
     *
     * Apple's format carries no signature: a certificate is minted for this
     * ceremony with `SHA-256(authData || clientDataHash)` in its nonce
     * extension, and the credential's own public key as its subject key. Both
     * are built here rather than faked, so the verifier is exercised against
     * the shape it will really see.
     */
    appleAttestation?: { root: GeneratedCertificate };
    /**
     * Produces a TPM attestation instead.
     *
     * A TPM signs a statement *about* a key rather than the ceremony, so the
     * fixture builds both structures: a TPMT_PUBLIC describing the credential
     * key, and a TPMS_ATTEST certifying it whose extraData hashes this
     * ceremony. The AIK signs the statement.
     *
     * `aik` overrides the attestation identity key, so a test can present one
     * that breaks a §8.3.1 requirement while everything else stays genuine.
     */
    tpmAttestation?: { root: GeneratedCertificate; aik?: GeneratedCertificate };
    /**
     * Produces a FIDO U2F attestation instead — the shape a CTAP1 security key
     * gives.
     *
     * The signature is over a flat concatenation naming the credential
     * explicitly, and the AAGUID is zeroed, because U2F has no model
     * identifier and the browser does not invent one.
     */
    u2fAttestation?: { root: GeneratedCertificate; leaf?: GeneratedCertificate };
  }): Promise<RegistrationResult> {
    const authData = await buildAuthenticatorData({
      rpId: options.rpId,
      flags: options.flags ?? FLAG_UP | FLAG_UV | FLAG_AT,
      signCount: this.#signCount,
      attestedCredential: {
        // U2F has no model identifier; the browser zeroes the field rather
        // than inventing one, and the fixture does the same.
        aaguid: options.u2fAttestation ? new Uint8Array(16) : this.aaguid,
        credentialId: this.credentialId,
        credentialPublicKey: await this.coseKey(),
      },
      ...(options.rpIdHashOverride ? { rpIdHashOverride: options.rpIdHashOverride } : {}),
    });

    const clientDataJSON =
      options.clientDataOverride ??
      this.clientData('webauthn.create', options.challenge, options.origin);

    // The statement is signed over authData || SHA-256(clientDataJSON), so the
    // client data has to exist before the attestation can.
    const clientDataHash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientDataJSON));
    const signedData = concat([authData, clientDataHash]);

    const attStmt = new Map<string | number, Encodable>();
    let format = options.attestationFormat ?? 'none';

    if (options.appleAttestation) {
      const nonce = new Uint8Array(await crypto.subtle.digest('SHA-256', signedData));
      // The certificate's subject key *is* the credential key — the check a
      // verifier must make, and one an implementation can silently skip.
      // The certificate builder works in node KeyObjects; the authenticator
      // holds WebCrypto CryptoKeys. `KeyObject.from` is the bridge, and it
      // keeps the *same* key rather than generating a parallel one — which is
      // the whole point of this check.
      const credentialKey = {
        privateKey: KeyObject.from(this.#keyPair.privateKey),
        publicKey: KeyObject.from(this.#keyPair.publicKey),
      };
      const credCert = createCertificate({
        subject: 'Apple Anonymous Attestation',
        issuer: options.appleAttestation.root,
        keyPair: credentialKey,
        appleNonce: nonce,
      });

      format = options.attestationFormat ?? 'apple';
      attStmt.set('x5c', [credCert.der]);
    }

    if (options.u2fAttestation) {
      const jwk = await crypto.subtle.exportKey('jwk', this.#keyPair.publicKey);
      const publicKeyU2F = concat([
        new Uint8Array([0x04]),
        new Uint8Array(Buffer.from(jwk.x as string, 'base64url')),
        new Uint8Array(Buffer.from(jwk.y as string, 'base64url')),
      ]);

      // §8.6: a flat concatenation, not `authData`. The leading zero is a
      // reserved constant that keeps this from being replayable as a U2F
      // authentication response.
      const verificationData = concat([
        new Uint8Array([0x00]),
        authData.subarray(0, 32),
        clientDataHash,
        this.credentialId,
        publicKeyU2F,
      ]);

      const attCert =
        options.u2fAttestation.leaf ??
        createCertificate({
          subject: 'Ninsho U2F Attestation',
          issuer: options.u2fAttestation.root,
        });

      const signature = new Uint8Array(
        createSign('SHA256').update(verificationData).sign(attCert.privateKey),
      );
      if (options.breakAttestationSignature) signature[0] = (signature[0] as number) ^ 0xff;

      format = options.attestationFormat ?? 'fido-u2f';
      attStmt.set('sig', signature);
      attStmt.set('x5c', [attCert.der]);
    }

    if (options.tpmAttestation) {
      const jwk = await crypto.subtle.exportKey('jwk', this.#keyPair.publicKey);
      const x = new Uint8Array(Buffer.from(jwk.x as string, 'base64url'));
      const y = new Uint8Array(Buffer.from(jwk.y as string, 'base64url'));

      const pubArea = buildTpmPublic(x, y);
      const certInfo = await buildTpmCertInfo(pubArea, signedData);

      // The attestation identity key is separate from the credential key —
      // that is the point of a TPM: a device key certifies keys it generated.
      const aik =
        options.tpmAttestation.aik ??
        createCertificate({
          subject: '',
          issuer: options.tpmAttestation.root,
          extendedKeyUsage: ['2.23.133.8.3'],
        });

      const signature = new Uint8Array(
        createSign('SHA256').update(certInfo).sign(aik.privateKey),
      );
      if (options.breakAttestationSignature) signature[0] = (signature[0] as number) ^ 0xff;

      format = options.attestationFormat ?? 'tpm';
      attStmt.set('ver', '2.0');
      attStmt.set('alg', ES256);
      attStmt.set('sig', signature);
      attStmt.set('certInfo', certInfo);
      attStmt.set('pubArea', pubArea);
      attStmt.set('x5c', [aik.der]);
    } else if (options.appleAttestation || options.u2fAttestation) {
      // Already assembled above.
    } else if (options.attestationChain) {
      format = options.attestationFormat ?? 'packed';
      const signature = new Uint8Array(
        createSign('SHA256').update(signedData).sign(options.attestationChain.leaf.privateKey),
      );
      if (options.breakAttestationSignature) signature[0] = (signature[0] as number) ^ 0xff;

      attStmt.set('alg', ES256);
      attStmt.set('sig', signature);
      attStmt.set('x5c', [
        options.attestationChain.leaf.der,
        ...(options.attestationIntermediates ?? []),
      ]);
    } else if (options.selfAttested) {
      format = options.attestationFormat ?? 'packed';
      const signature = await this.sign(signedData);
      if (options.breakAttestationSignature) signature[0] = (signature[0] as number) ^ 0xff;

      attStmt.set('alg', this.alg);
      attStmt.set('sig', signature);
    }

    const attestationObject = encodeCbor(
      new Map<string, Encodable>([
        ['fmt', format],
        ['attStmt', attStmt],
        ['authData', authData],
      ]),
    );

    return { credentialId: this.credentialId, attestationObject, clientDataJSON };
  }

  /** Produces an authentication assertion, signed over authData || hash(clientData). */
  async authenticate(options: {
    challenge: Uint8Array;
    origin: string;
    rpId: string;
    flags?: number;
    signCount?: number;
    userHandle?: Uint8Array;
    clientDataOverride?: Uint8Array;
    rpIdHashOverride?: Uint8Array;
    signatureOverride?: Uint8Array;
  }): Promise<AssertionResult> {
    const authData = await buildAuthenticatorData({
      rpId: options.rpId,
      flags: options.flags ?? FLAG_UP | FLAG_UV,
      signCount: options.signCount ?? ++this.#signCount,
      ...(options.rpIdHashOverride ? { rpIdHashOverride: options.rpIdHashOverride } : {}),
    });

    const clientDataJSON =
      options.clientDataOverride ??
      this.clientData('webauthn.get', options.challenge, options.origin);

    const clientDataHash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientDataJSON));
    const signed = concat([authData, clientDataHash]);

    return {
      credentialId: this.credentialId,
      authenticatorData: authData,
      clientDataJSON,
      signature: options.signatureOverride ?? (await this.sign(signed)),
      userHandle: options.userHandle,
    };
  }
}

// ─── X.509 fixtures ────────────────────────────────────────────────────────
export {
  createCertificate,
  createChain,
  FIDO_AAGUID_OID,
  type CertificateChain,
  type GeneratedCertificate,
  type CreateCertificateOptions,
} from './x509-fixtures.js';
