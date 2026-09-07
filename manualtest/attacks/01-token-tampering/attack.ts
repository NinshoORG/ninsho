/**
 * SECURITY TEST SCRIPT: 01-token-tampering
 * Target: http://localhost:3000 (express-api)
 *
 * Demonstrates that tampering with an opaque access token results in HTTP 401
 * rejection and does not grant unauthorized access or reveal store internals.
 */

const BASE_URL = 'http://localhost:3000';

async function run(): Promise<void> {
  console.log('[SECURITY TEST] 01-token-tampering: Testing Opaque Token Tamper Resistance...');

  // 1. Obtain valid session
  const testEmail = `tamper_${Date.now()}@example.com`;
  const registerRes = await fetch(`${BASE_URL}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: testEmail, password: 'SecurePassword123!' }),
  });

  if (!registerRes.ok && registerRes.status !== 201) {
    console.error(`[-] Failed to establish test session. Status: ${registerRes.status}`);
    process.exit(1);
  }

  const { accessToken } = await registerRes.json() as { accessToken: string };
  console.log(`[+] Obtained valid access token: ${accessToken.slice(0, 10)}... (length: ${accessToken.length})`);

  // 2. Test valid access
  const validRes = await fetch(`${BASE_URL}/me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  console.log(`[+] Genuine token verification HTTP status: ${validRes.status}`);
  if (validRes.status !== 200) {
    console.error('[-] Expected 200 OK for genuine token');
    process.exit(1);
  }

  // 3. Tamper with token (mutate characters in the random entropy portion)
  const lastChar = accessToken.slice(-1);
  const replacement = lastChar === 'a' ? 'b' : 'a';
  const tamperedToken = accessToken.slice(0, -1) + replacement;
  console.log(`[*] Sending tampered token: ${tamperedToken.slice(0, 10)}...`);

  const tamperedRes = await fetch(`${BASE_URL}/me`, {
    headers: { Authorization: `Bearer ${tamperedToken}` },
  });
  const tamperedBody = await tamperedRes.text();

  console.log(`[*] Tampered token response HTTP status: ${tamperedRes.status}`);
  console.log(`[*] Tampered token response body: ${tamperedBody}`);

  if (tamperedRes.status === 401) {
    console.log('[PASS] Server correctly rejected tampered token with HTTP 401 Unauthorized.');
  } else {
    console.error(`[FAIL] Unexpected response: ${tamperedRes.status}`);
    process.exit(1);
  }
}

run().catch((err) => {
  console.error('[ERROR] Attack script failed to execute:', err.message);
  process.exit(1);
});
