/**
 * FIDO Metadata Service — turning a published BLOB into an attestation policy.
 *
 * ─── The gap this closes, and the one it deliberately leaves ──────────────
 * Attestation is refused without trust anchors, which is correct and leaves a
 * relying party holding a question: where do the roots come from? FIDO
 * publishes them. The Metadata Service is a signed document listing every
 * certified authenticator — its AAGUID, its attestation roots, and whether it
 * has since been found compromised.
 *
 * Verifying that document is library work: it is a signature, a chain and a
 * set of rules about what a status report means, and getting any of them wrong
 * is a security bug. *Fetching* it is not. A library that reaches out to the
 * network on your behalf decides your caching, your failure mode when the
 * service is down, and your update cadence — and it does so at exactly the
 * moment you least want a surprise. So this parses and verifies a blob you
 * hand it, and does no I/O at all.
 *
 * ─── Why compromise is permanent here ─────────────────────────────────────
 * An entry carries a history of status reports. FIDO can certify an
 * authenticator, later mark its attestation key compromised, and later still
 * certify a new revision. Reading only the latest status would quietly
 * re-admit a model whose attestation key is known to be in someone else's
 * hands — the key that vouches for every unit ever made. So a compromise or
 * revocation anywhere in an entry's history disqualifies it, and the newest
 * status must also be acceptable on its own.
 *
 * ─── RS256 only ───────────────────────────────────────────────────────────
 * The BLOB is a JWS, and a JWS header names its own algorithm. FIDO signs with
 * RSA. Accepting anything else would mean letting a document say how it should
 * be checked, which is the shape of every algorithm-confusion attack; if FIDO
 * ever changes, this should change deliberately rather than by default.
 * ──────────────────────────────────────────────────────────────────────────
 */

import { X509Certificate } from 'node:crypto';
import { RS256 } from './cose.js';
import { chainReachesAnchor, verifySignature, type AttestationPolicy } from './attestation.js';

/** Raised for a metadata BLOB this parser will not accept. */
export class MetadataError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MetadataError';
  }
}

/**
 * Statuses that disqualify an authenticator wherever they appear in its
 * history.
 *
 * The first four are compromise: the attestation key, or user keys, are known
 * to be in someone else's hands. `REVOKED` is FIDO withdrawing the
 * certification outright. None of these is undone by a later report, because
 * the compromised key does not stop being compromised.
 */
export const DISQUALIFYING_STATUSES: readonly string[] = [
  'ATTESTATION_KEY_COMPROMISE',
  'USER_VERIFICATION_BYPASS',
  'USER_KEY_REMOTE_COMPROMISE',
  'USER_KEY_PHYSICAL_COMPROMISE',
  'REVOKED',
];

/**
 * Statuses acceptable as an entry's *current* one.
 *
 * `NOT_FIDO_CERTIFIED` and `SELF_ASSERTION_SUBMITTED` are absent on purpose:
 * they mean the vendor filled in a form. Drawing trust anchors from an entry
 * on that basis would make the metadata service a directory of people who
 * asked to be trusted.
 */
export const DEFAULT_ACCEPTED_STATUSES: readonly string[] = [
  'FIDO_CERTIFIED',
  'FIDO_CERTIFIED_L1',
  'FIDO_CERTIFIED_L1plus',
  'FIDO_CERTIFIED_L2',
  'FIDO_CERTIFIED_L2plus',
  'FIDO_CERTIFIED_L3',
  'FIDO_CERTIFIED_L3plus',
];

export interface MetadataStatusReport {
  readonly status: string;
  /** ISO date, when FIDO published it. Absent on some historical entries. */
  readonly effectiveDate: string | undefined;
}

export interface MetadataEntry {
  /** Lowercase hex without separators, matching `VerifiedRegistration.aaguid`. */
  readonly aaguid: string | undefined;
  readonly description: string | undefined;
  /** DER roots this model's attestation chains reach. */
  readonly attestationRootCertificates: readonly Uint8Array[];
  /** Newest first, as this parser orders them. */
  readonly statusReports: readonly MetadataStatusReport[];
}

export interface MetadataBlob {
  /** The BLOB's sequence number, `no`. Rises with every publication. */
  readonly number: number;
  /** ISO date by which FIDO expects to have published a newer one. */
  readonly nextUpdate: string;
  readonly entries: readonly MetadataEntry[];
}

export interface ParseMetadataOptions {
  /** DER roots the BLOB's own signing chain must reach. Required. */
  readonly trustAnchors: readonly Uint8Array[];
  /**
   * Accept a BLOB whose `nextUpdate` has passed. Default `false`.
   *
   * A stale BLOB is the failure mode that matters: it still verifies, it still
   * looks authoritative, and it is missing every compromise FIDO has published
   * since. Refusing by default means a fetch that has been quietly failing for
   * months announces itself.
   */
  readonly allowStale?: boolean;
  /** Overrides the clock, for tests. */
  readonly now?: Date;
}

/** Decodes canonical base64url. */
function b64uDecode(value: string, what: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new MetadataError(`${what} is not base64url`);
  }
  const bytes = new Uint8Array(Buffer.from(value, 'base64url'));
  if (Buffer.from(bytes).toString('base64url') !== value) {
    throw new MetadataError(`${what} is not canonically encoded`);
  }
  return bytes;
}

/** Decodes canonical, padded standard base64 — the spelling `x5c` uses. */
function b64Decode(value: string, what: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new MetadataError(`${what} is not base64`);
  }
  const bytes = new Uint8Array(Buffer.from(value, 'base64'));
  if (Buffer.from(bytes).toString('base64') !== value) {
    throw new MetadataError(`${what} is not canonically encoded`);
  }
  return bytes;
}

/** Parses JSON without letting a key called `__proto__` reach an object. */
function parseJson(bytes: Uint8Array, what: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes), (key, entry) =>
      key === '__proto__' ? undefined : (entry as unknown),
    );
  } catch {
    throw new MetadataError(`${what} is not valid JSON`);
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new MetadataError(`${what} is not a JSON object`);
  }
  return value as Record<string, unknown>;
}

/** Normalises an AAGUID to the lowercase hex a verified registration reports. */
function normaliseAaguid(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const hex = value.replace(/-/g, '').toLowerCase();
  return /^[0-9a-f]{32}$/.test(hex) ? hex : undefined;
}

function readStatusReports(value: unknown): MetadataStatusReport[] {
  if (!Array.isArray(value)) return [];

  const reports: MetadataStatusReport[] = [];
  for (const raw of value) {
    if (typeof raw !== 'object' || raw === null) continue;
    const record = raw as Record<string, unknown>;
    const status = record['status'];
    if (typeof status !== 'string') continue;
    const effectiveDate = record['effectiveDate'];
    reports.push({
      status,
      effectiveDate: typeof effectiveDate === 'string' ? effectiveDate : undefined,
    });
  }

  // Newest first. An undated report sorts last rather than first: a report
  // whose date nobody recorded should not become the current status.
  return reports.sort((a, b) => (b.effectiveDate ?? '').localeCompare(a.effectiveDate ?? ''));
}

function readEntry(raw: unknown): MetadataEntry | undefined {
  if (typeof raw !== 'object' || raw === null) return undefined;
  const record = raw as Record<string, unknown>;

  const statement = record['metadataStatement'];
  const statementRecord =
    typeof statement === 'object' && statement !== null
      ? (statement as Record<string, unknown>)
      : {};

  const rootsRaw = statementRecord['attestationRootCertificates'];
  const roots: Uint8Array[] = [];
  if (Array.isArray(rootsRaw)) {
    for (const [index, entry] of rootsRaw.entries()) {
      if (typeof entry !== 'string') {
        throw new MetadataError(`attestationRootCertificates[${index}] is not a string`);
      }
      // Whitespace is stripped because FIDO's own BLOB wraps some of these at
      // 64 columns, which is PEM habit rather than a different value.
      roots.push(b64Decode(entry.replace(/\s/g, ''), `attestationRootCertificates[${index}]`));
    }
  }

  const description = statementRecord['description'];

  return {
    aaguid: normaliseAaguid(record['aaguid'] ?? statementRecord['aaguid']),
    description: typeof description === 'string' ? description : undefined,
    attestationRootCertificates: roots,
    statusReports: readStatusReports(record['statusReports']),
  };
}

/**
 * Verifies a FIDO Metadata Service BLOB and returns what it says.
 *
 * The signing chain is verified to `trustAnchors` — FIDO's root, which you
 * supply for the same reason you supply attestation roots: a chain checked
 * against no root proves nothing, and a metadata service that vouched for
 * itself would be a list of authenticators anyone could write.
 */
export function parseMetadataBlob(
  blob: string | Uint8Array,
  options: ParseMetadataOptions,
): MetadataBlob {
  if (options.trustAnchors.length === 0) {
    throw new MetadataError(
      'a metadata BLOB requires trustAnchors; an unrooted list of trusted devices is a list anyone can write',
    );
  }

  let text: string;
  if (typeof blob === 'string') {
    text = blob;
  } else {
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(blob);
    } catch {
      throw new MetadataError('the metadata BLOB is not UTF-8');
    }
  }

  const parts = text.trim().split('.');
  if (parts.length !== 3) {
    throw new MetadataError(`a JWS has three segments, not ${parts.length}`);
  }
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];

  const header = parseJson(b64uDecode(headerPart, 'the BLOB header'), 'the BLOB header');
  if (header['alg'] !== 'RS256') {
    throw new MetadataError(`unsupported metadata BLOB algorithm: ${String(header['alg'])}`);
  }

  const x5c = header['x5c'];
  if (!Array.isArray(x5c) || x5c.length === 0) {
    throw new MetadataError('the BLOB header carries no x5c chain');
  }
  if (x5c.length > 8) {
    throw new MetadataError(`the BLOB header carries ${x5c.length} certificates`);
  }

  let chain: X509Certificate[];
  let anchors: X509Certificate[];
  try {
    chain = x5c.map((entry, index) => {
      if (typeof entry !== 'string') {
        throw new MetadataError(`x5c entry ${index} is not a string`);
      }
      return new X509Certificate(
        Buffer.from(b64Decode(entry.replace(/\s/g, ''), `x5c entry ${index}`)),
      );
    });
  } catch (error) {
    if (error instanceof MetadataError) throw error;
    throw new MetadataError('the BLOB chain holds something that is not a certificate');
  }
  try {
    anchors = options.trustAnchors.map((der) => new X509Certificate(Buffer.from(der)));
  } catch {
    throw new MetadataError('a configured trust anchor is not a valid certificate');
  }

  const signingInput = new TextEncoder().encode(`${headerPart}.${payloadPart}`);
  const signature = b64uDecode(signaturePart, 'the BLOB signature');

  // Signature before chain, and both before the payload is read: a document
  // nobody signed should not have its contents parsed at all.
  if (!verifySignature(RS256, (chain[0] as X509Certificate).publicKey, signingInput, signature)) {
    throw new MetadataError('the metadata BLOB signature did not verify');
  }
  if (!chainReachesAnchor(chain, anchors)) {
    throw new MetadataError('the metadata BLOB chain does not reach a trusted root');
  }

  const payload = parseJson(b64uDecode(payloadPart, 'the BLOB payload'), 'the BLOB payload');

  const number = payload['no'];
  if (typeof number !== 'number' || !Number.isInteger(number)) {
    throw new MetadataError('the metadata BLOB carries no sequence number');
  }

  const nextUpdate = payload['nextUpdate'];
  if (typeof nextUpdate !== 'string' || nextUpdate.length === 0) {
    throw new MetadataError('the metadata BLOB carries no nextUpdate');
  }

  if (options.allowStale !== true) {
    const due = Date.parse(`${nextUpdate}T00:00:00Z`);
    if (Number.isNaN(due)) {
      throw new MetadataError(`the metadata BLOB nextUpdate is unreadable: ${nextUpdate}`);
    }
    const now = (options.now ?? new Date()).getTime();
    if (now > due) {
      throw new MetadataError(
        `the metadata BLOB was due to be replaced on ${nextUpdate}; it is missing every compromise published since`,
      );
    }
  }

  const rawEntries = payload['entries'];
  if (!Array.isArray(rawEntries)) {
    throw new MetadataError('the metadata BLOB carries no entries');
  }

  const entries: MetadataEntry[] = [];
  for (const raw of rawEntries) {
    const entry = readEntry(raw);
    if (entry !== undefined) entries.push(entry);
  }

  return { number, nextUpdate, entries };
}

export interface PolicyFromMetadataOptions {
  /** Attestation formats to accept. Defaults to every format that carries a chain. */
  readonly formats?: readonly string[];
  /** Statuses acceptable as an entry's current one. */
  readonly acceptedStatuses?: readonly string[];
  /**
   * Restrict the policy to these AAGUIDs, lowercase hex.
   *
   * Without it the policy trusts every certified authenticator in the BLOB,
   * which is the right default for "any FIDO-certified key" and the wrong one
   * for "the model we issued".
   */
  readonly aaguids?: readonly string[];
}

/**
 * Builds an `AttestationPolicy` from a verified BLOB.
 *
 * Entries with a compromise or revocation anywhere in their history are left
 * out, as are entries whose newest status is not one you accept — and so are
 * entries carrying no roots, since including them would put an AAGUID on the
 * allowlist that no chain could ever satisfy.
 */
export function toAttestationPolicy(
  blob: MetadataBlob,
  options: PolicyFromMetadataOptions = {},
): AttestationPolicy {
  const accepted = options.acceptedStatuses ?? DEFAULT_ACCEPTED_STATUSES;
  const wanted = options.aaguids === undefined ? undefined : new Set(options.aaguids);

  const trustAnchors: Uint8Array[] = [];
  const allowedAaguids: string[] = [];
  const seen = new Set<string>();

  for (const entry of blob.entries) {
    if (entry.aaguid === undefined) continue;
    if (wanted !== undefined && !wanted.has(entry.aaguid)) continue;
    if (entry.attestationRootCertificates.length === 0) continue;

    if (entry.statusReports.some((report) => DISQUALIFYING_STATUSES.includes(report.status))) {
      continue;
    }
    const current = entry.statusReports[0];
    if (current === undefined || !accepted.includes(current.status)) continue;

    allowedAaguids.push(entry.aaguid);
    for (const root of entry.attestationRootCertificates) {
      const key = Buffer.from(root).toString('base64');
      if (seen.has(key)) continue;
      seen.add(key);
      trustAnchors.push(root);
    }
  }

  return {
    formats: options.formats ?? ['packed', 'apple', 'tpm', 'fido-u2f', 'android-key'],
    trustAnchors,
    allowedAaguids,
  };
}
