/**
 * SECURITY TEST SCRIPT: 02-signature-tampering
 * Target: http://localhost:4000 (playground)
 *
 * Demonstrates that presenting synthetic PASETO tokens or truncated signatures
 * to an opaque-configured engine results in immediate rejection without
 * algorithm confusion or parser exploitation.
 */

const BASE_URL = 'http://localhost:4000';

async function run(): Promise<void> {
  console.log('[SECURITY TEST] 02-signature-tampering: Testing Algorithm Confusion & Signature Rejection...');

  // 1. Send truncated signature (< 64 bytes)
  console.log('[*] Testing truncated signature...');
  const truncatedRes = await fetch(`${BASE_URL}/api/session/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: 'v4.public.dGVzdA' }),
  });

  const truncatedData = await truncatedRes.json() as { ok: boolean; code?: string; message?: string };
  console.log(`[*] Truncated token response:`, truncatedData);
  if (truncatedData.ok !== false) {
    console.error('[FAIL] Truncated token was accepted!');
    process.exit(1);
  }

  // 2. Send synthetic token with invalid Ed25519 signature
  console.log('[*] Testing corrupted 64-byte signature...');
  const fakeSig = Buffer.alloc(64, 0xaa).toString('base64url');
  const fakePayload = Buffer.from(JSON.stringify({ sub: 'admin', roles: ['admin'] })).toString('base64url');
  const forgedToken = `v4.public.${fakePayload}${fakeSig}`;

  const forgedRes = await fetch(`${BASE_URL}/api/session/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: forgedToken }),
  });

  const forgedData = await forgedRes.json() as { ok: boolean; code?: string; message?: string };
  console.log(`[*] Forged signature response:`, forgedData);

  if (forgedData.ok === false && forgedData.code === 'TOKEN_INVALID') {
    console.log('[PASS] Algorithm confusion and signature tampering cleanly rejected with TOKEN_INVALID.');
  } else {
    console.error('[FAIL] Unexpected response for signature tampering:', forgedData);
    process.exit(1);
  }
}

run().catch((err) => {
  console.error('[ERROR] Attack script error:', err.message);
  process.exit(1);
});
