import { describe, it, expect } from 'vitest';
import {
  buildAuthenticationOptions,
  buildRegistrationOptions,
  type BuildRegistrationOptionsInput,
} from './options.js';
import { DEFAULT_ALGORITHMS, ES256, EdDSA, RS256 } from './cose.js';
import { MemoryStore } from '@ninsho/server';
import { WebAuthnServer } from './server.js';
import { VirtualAuthenticator } from './testing.js';

/**
 * Ceremony options.
 *
 * These are not a security boundary — a client can ignore every field, and
 * verification never trusts what comes back. What they decide is what the
 * *honest* client does, and two of those decisions are load-bearing in a way
 * that shows up much later:
 *
 *   - `requireResidentKey` and `residentKey` disagreeing turns a discoverable
 *     credential into a non-discoverable one on older authenticators, which
 *     surfaces as a user who cannot sign in without typing a username they
 *     were never asked for.
 *   - `pubKeyCredParams` naming an algorithm the verifier will not accept
 *     produces a credential that registers and then fails at every sign-in.
 *
 * Neither is visible in a passing ceremony test, because the virtual
 * authenticator does what it is told. So they are asserted here directly.
 */

const RP_ID = 'example.com';

const registrationInput = (
  overrides: Partial<BuildRegistrationOptionsInput> = {},
): BuildRegistrationOptionsInput => ({
  rpId: RP_ID,
  rpName: 'Example',
  userId: new TextEncoder().encode('usr_alice'),
  userName: 'alice@example.com',
  challenge: 'Y2hhbGxlbmdl',
  timeoutMs: 60_000,
  ...overrides,
});

describe('buildRegistrationOptions', () => {
  it('produces the JSON shape a browser parses without translation', () => {
    const options = buildRegistrationOptions(registrationInput());

    expect(options.rp).toEqual({ id: RP_ID, name: 'Example' });
    expect(options.challenge).toBe('Y2hhbGxlbmdl');
    expect(options.timeout).toBe(60_000);
    // The user handle is base64url of the bytes given, never the raw string.
    expect(options.user.id).toBe(Buffer.from('usr_alice').toString('base64url'));
    expect(options.user.name).toBe('alice@example.com');
  });

  it('falls back to the user name for the display name', () => {
    expect(buildRegistrationOptions(registrationInput()).user.displayName).toBe(
      'alice@example.com',
    );
    expect(
      buildRegistrationOptions(registrationInput({ displayName: 'Alice' })).user.displayName,
    ).toBe('Alice');
  });

  it.each([
    ['discouraged', false],
    ['preferred', false],
    ['required', true],
  ] as const)('keeps requireResidentKey in step with residentKey %s', (residentKey, expected) => {
    // The deprecated boolean is what older authenticators read. Letting the
    // two disagree is how a credential the relying party asked to be
    // discoverable quietly is not — and nothing at verification time would
    // say so, because the ceremony succeeds either way.
    const options = buildRegistrationOptions(registrationInput({ residentKey }));

    expect(options.authenticatorSelection.residentKey).toBe(residentKey);
    expect(options.authenticatorSelection.requireResidentKey).toBe(expected);
  });

  it('defaults to a discoverable-preferred, user-verified, unattested ceremony', () => {
    // The defaults are the whole point of the builder: a relying party that
    // hand-rolls this JSON is one typo away from a policy it did not intend.
    const options = buildRegistrationOptions(registrationInput());

    expect(options.authenticatorSelection.residentKey).toBe('preferred');
    expect(options.authenticatorSelection.requireResidentKey).toBe(false);
    expect(options.authenticatorSelection.userVerification).toBe('preferred');
    expect(options.attestation).toBe('none');
  });

  it('omits authenticatorAttachment rather than guessing one', () => {
    // Naming either value narrows what the user may register with. Absent
    // means "any", which is the only honest default.
    const options = buildRegistrationOptions(registrationInput());
    expect(options.authenticatorSelection.authenticatorAttachment).toBeUndefined();
    expect('authenticatorAttachment' in options.authenticatorSelection).toBe(false);

    const platform = buildRegistrationOptions(
      registrationInput({ authenticatorAttachment: 'platform' }),
    );
    expect(platform.authenticatorSelection.authenticatorAttachment).toBe('platform');
  });

  it('offers the package default algorithms when none are named', () => {
    const options = buildRegistrationOptions(registrationInput());

    expect(options.pubKeyCredParams.map((p) => p.alg)).toEqual([...DEFAULT_ALGORITHMS]);
    expect(options.pubKeyCredParams.every((p) => p.type === 'public-key')).toBe(true);
  });

  it('offers exactly the algorithms named, in order', () => {
    // Order is preference order to the browser, so it is data rather than a
    // set.
    const options = buildRegistrationOptions(
      registrationInput({ algorithms: [EdDSA, ES256] }),
    );
    expect(options.pubKeyCredParams.map((p) => p.alg)).toEqual([EdDSA, ES256]);
  });

  it('excludes the credentials the user already has', () => {
    // Without this the authenticator happily makes a second credential for the
    // same account on the same device, and the user ends up with two passkeys,
    // uses whichever the browser offers, and cannot tell why one stopped
    // working.
    const options = buildRegistrationOptions(
      registrationInput({
        existingCredentials: [
          { credentialId: new Uint8Array([1, 2, 3]), transports: ['internal'] },
          { credentialId: new Uint8Array([4, 5, 6]) },
        ],
      }),
    );

    expect(options.excludeCredentials).toEqual([
      {
        type: 'public-key',
        id: Buffer.from([1, 2, 3]).toString('base64url'),
        transports: ['internal'],
      },
      { type: 'public-key', id: Buffer.from([4, 5, 6]).toString('base64url') },
    ]);
  });

  it('sends an empty exclude list rather than omitting the field', () => {
    expect(buildRegistrationOptions(registrationInput()).excludeCredentials).toEqual([]);
  });
});

describe('buildAuthenticationOptions', () => {
  it('produces the JSON shape a browser parses without translation', () => {
    const options = buildAuthenticationOptions({
      rpId: RP_ID,
      challenge: 'Y2hhbGxlbmdl',
      timeoutMs: 60_000,
    });

    expect(options).toEqual({
      challenge: 'Y2hhbGxlbmdl',
      timeout: 60_000,
      rpId: RP_ID,
      allowCredentials: [],
      userVerification: 'preferred',
    });
  });

  it('leaves allowCredentials empty for a usernameless flow', () => {
    // Empty is meaningful here: it tells the authenticator to offer whatever
    // discoverable credentials it holds, which is the whole passkey flow.
    const options = buildAuthenticationOptions({
      rpId: RP_ID,
      challenge: 'c',
      timeoutMs: 1,
    });
    expect(options.allowCredentials).toEqual([]);
  });

  it('names the credentials a known user may use', () => {
    const options = buildAuthenticationOptions({
      rpId: RP_ID,
      challenge: 'c',
      timeoutMs: 1,
      allowCredentials: [{ credentialId: new Uint8Array([9]), transports: ['hybrid', 'usb'] }],
    });

    expect(options.allowCredentials).toEqual([
      { type: 'public-key', id: Buffer.from([9]).toString('base64url'), transports: ['hybrid', 'usb'] },
    ]);
  });

  it('carries a stricter user-verification requirement through', () => {
    const options = buildAuthenticationOptions({
      rpId: RP_ID,
      challenge: 'c',
      timeoutMs: 1,
      userVerification: 'required',
    });
    expect(options.userVerification).toBe('required');
  });
});

/**
 * What the relying party *asks* for and what it will *accept* have to be the
 * same list.
 *
 * They are set in two different places — `pubKeyCredParams` in the options and
 * `allowedAlgorithms` at verification — and `WebAuthnServer` wires both from
 * one setting. Nothing asserted that until now, so a default added to one side
 * and not the other would have produced credentials that register and then
 * fail at every sign-in, with no test objecting.
 */
describe('the algorithms offered are the algorithms accepted', () => {
  const server = (algorithms?: readonly number[]): WebAuthnServer =>
    new WebAuthnServer({
      rpId: RP_ID,
      rpName: 'Example',
      origin: `https://${RP_ID}`,
      store: new MemoryStore(),
      ...(algorithms ? { algorithms: algorithms as never } : {}),
    });

  it('offers exactly the configured set', async () => {
    const options = await server([EdDSA]).startRegistration({
      userId: 'usr_alice',
      userName: 'alice@example.com',
    });

    expect(options.pubKeyCredParams.map((p) => p.alg)).toEqual([EdDSA]);
  });

  it('accepts a credential using an offered algorithm', async () => {
    const rp = server([EdDSA, ES256]);
    const device = await VirtualAuthenticator.create(EdDSA);

    const options = await rp.startRegistration({
      userId: 'usr_alice',
      userName: 'alice@example.com',
    });
    expect(options.pubKeyCredParams.map((p) => p.alg)).toContain(EdDSA);

    const response = await device.register({
      challenge: new Uint8Array(Buffer.from(options.challenge, 'base64url')),
      origin: `https://${RP_ID}`,
      rpId: RP_ID,
    });

    await expect(rp.finishRegistration(response)).resolves.toMatchObject({ algorithm: EdDSA });
  });

  it('refuses a credential using an algorithm it never offered', async () => {
    // The other half of the same rule. A relying party that narrowed its
    // offer must not then accept something outside it, or the narrowing was
    // decoration.
    const rp = server([EdDSA]);
    const device = await VirtualAuthenticator.create(RS256);

    const options = await rp.startRegistration({
      userId: 'usr_alice',
      userName: 'alice@example.com',
    });
    expect(options.pubKeyCredParams.map((p) => p.alg)).not.toContain(RS256);

    const response = await device.register({
      challenge: new Uint8Array(Buffer.from(options.challenge, 'base64url')),
      origin: `https://${RP_ID}`,
      rpId: RP_ID,
    });

    await expect(rp.finishRegistration(response)).rejects.toThrow();
  });

  it('offers the package defaults when nothing is configured, and accepts them all', async () => {
    for (const alg of DEFAULT_ALGORITHMS) {
      const rp = server();
      const device = await VirtualAuthenticator.create(alg);

      const options = await rp.startRegistration({
        userId: 'usr_alice',
        userName: 'alice@example.com',
      });
      expect(options.pubKeyCredParams.map((p) => p.alg)).toContain(alg);

      const response = await device.register({
        challenge: new Uint8Array(Buffer.from(options.challenge, 'base64url')),
        origin: `https://${RP_ID}`,
        rpId: RP_ID,
      });

      await expect(rp.finishRegistration(response)).resolves.toMatchObject({ algorithm: alg });
    }
  });
});

/**
 * Asking for attestation you cannot check collects a statement nobody
 * verifies, so the conveyance follows the policy rather than being configured
 * beside it.
 */
describe('attestation conveyance follows the attestation policy', () => {
  const server = (attestation?: { formats: readonly string[] }): WebAuthnServer =>
    new WebAuthnServer({
      rpId: RP_ID,
      rpName: 'Example',
      origin: `https://${RP_ID}`,
      store: new MemoryStore(),
      ...(attestation ? { attestation: attestation as never } : {}),
    });

  const start = (rp: WebAuthnServer) =>
    rp.startRegistration({ userId: 'usr_alice', userName: 'alice@example.com' });

  it('asks for none when no format beyond none is accepted', async () => {
    expect((await start(server())).attestation).toBe('none');
    expect((await start(server({ formats: ['none'] }))).attestation).toBe('none');
  });

  it.each([['packed'], ['tpm'], ['apple'], ['android-key'], ['fido-u2f'], ['android-safetynet']])(
    'asks for direct when %s is accepted',
    async (format) => {
      expect((await start(server({ formats: ['none', format] }))).attestation).toBe('direct');
    },
  );
});
