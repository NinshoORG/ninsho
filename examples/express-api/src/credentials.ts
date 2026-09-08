/**
 * An in-memory passkey directory, standing in for your database.
 *
 * ─── What is worth copying here ───────────────────────────────────────────
 * The shape of the record, and the fact that `signCount` is written back after
 * every successful authentication. Everything else — where records live, how
 * they are indexed — is application concern.
 *
 * Credential storage belongs in your own database, next to the user it
 * identifies. `@ninshorg/webauthn` deliberately does not own it: owning
 * credential storage would mean owning your user model.
 * ──────────────────────────────────────────────────────────────────────────
 */

export interface StoredPasskey {
  /** The lookup key. Stored as base64url so it can index a Map or a column. */
  readonly credentialId: string;
  /**
   * The COSE public key, base64url of the bytes `verifyRegistration` returned.
   *
   * Store it verbatim. It is re-imported on every authentication, so any
   * re-encoding — a "cleanup" that strips or reorders something — breaks every
   * future sign-in for that credential.
   */
  readonly publicKey: string;
  /**
   * The counter as of the last successful authentication.
   *
   * This must be written back after every success. A counter that never
   * advances in the database makes clone detection silently stop working: the
   * check still runs, and always compares against the same stale value.
   */
  signCount: number;
  readonly userId: string;
  /** Whether the credential is a synced (multi-device) passkey. */
  readonly backedUp: boolean;
  readonly createdAt: string;
}

const byCredentialId = new Map<string, StoredPasskey>();

export const toBase64Url = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString('base64url');

export const fromBase64Url = (value: string): Uint8Array =>
  new Uint8Array(Buffer.from(value, 'base64url'));

export function saveCredential(input: {
  credentialId: Uint8Array;
  publicKey: Uint8Array;
  signCount: number;
  userId: string;
  backedUp: boolean;
}): StoredPasskey {
  const credential: StoredPasskey = {
    credentialId: toBase64Url(input.credentialId),
    publicKey: toBase64Url(input.publicKey),
    signCount: input.signCount,
    userId: input.userId,
    backedUp: input.backedUp,
    createdAt: new Date().toISOString(),
  };

  byCredentialId.set(credential.credentialId, credential);
  return credential;
}

export function findByCredentialId(credentialId: string): StoredPasskey | undefined {
  return byCredentialId.get(credentialId);
}

export function listForUser(userId: string): readonly StoredPasskey[] {
  return [...byCredentialId.values()].filter((credential) => credential.userId === userId);
}

/**
 * Records the new counter.
 *
 * Called on every successful authentication, including the ones where the
 * counter did not change — an authenticator that reports 0 forever is normal
 * and is not a clone signal.
 */
export function updateSignCount(credentialId: string, signCount: number): void {
  const credential = byCredentialId.get(credentialId);
  if (credential) credential.signCount = signCount;
}

/** Test affordance. Not something a real directory would expose. */
export function resetCredentials(): void {
  byCredentialId.clear();
}
