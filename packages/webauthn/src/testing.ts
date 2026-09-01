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

import type { webcrypto } from 'node:crypto';
import { ES256, EdDSA, RS256, type CoseAlgorithm } from './cose.js';

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

  /** Produces a registration response with `none` attestation — a passkey. */
  async register(options: {
    challenge: Uint8Array;
    origin: string;
    rpId: string;
    flags?: number;
    clientDataOverride?: Uint8Array;
    rpIdHashOverride?: Uint8Array;
    attestationFormat?: string;
  }): Promise<RegistrationResult> {
    const authData = await buildAuthenticatorData({
      rpId: options.rpId,
      flags: options.flags ?? FLAG_UP | FLAG_UV | FLAG_AT,
      signCount: this.#signCount,
      attestedCredential: {
        aaguid: this.aaguid,
        credentialId: this.credentialId,
        credentialPublicKey: await this.coseKey(),
      },
      ...(options.rpIdHashOverride ? { rpIdHashOverride: options.rpIdHashOverride } : {}),
    });

    const attestationObject = encodeCbor(
      new Map<string, Encodable>([
        ['fmt', options.attestationFormat ?? 'none'],
        ['attStmt', new Map<string | number, Encodable>()],
        ['authData', authData],
      ]),
    );

    return {
      credentialId: this.credentialId,
      attestationObject,
      clientDataJSON:
        options.clientDataOverride ??
        this.clientData('webauthn.create', options.challenge, options.origin),
    };
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
