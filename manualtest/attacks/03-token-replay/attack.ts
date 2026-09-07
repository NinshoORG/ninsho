/**
 * SECURITY TEST SCRIPT: 03-token-replay
 * Target: http://localhost:3000 (express-api)
 *
 * Verifies that a revoked access token cannot be replayed after logout.
 */

const BASE_URL = 'http://localhost:3000';

async function run(): Promise<void> {
  console.log('[SECURITY TEST] 03-token-replay: Testing Replay of Revoked Token...');

  const testEmail = `replay_${Date.now()}@example.com`;
  const registerRes = await fetch(`${BASE_URL}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: testEmail, password: 'SecurePassword123!' }),
  });

  const { accessToken } = await registerRes.json() as { accessToken: string };
  console.log(`[+] Authenticated session token: ${accessToken.slice(0, 12)}...`);

  // Verify token works
  const preLogoutRes = await fetch(`${BASE_URL}/me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  console.log(`[+] Pre-logout /me response status: ${preLogoutRes.status}`);

  // Logout
  console.log('[*] Performing logout...');
  const logoutRes = await fetch(`${BASE_URL}/auth/logout`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  console.log(`[+] Logout response status: ${logoutRes.status}`);

  // Replay token
  console.log('[*] Replaying access token on /me post-logout...');
  const replayRes = await fetch(`${BASE_URL}/me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const replayBody = await replayRes.text();

  console.log(`[*] Replay response status: ${replayRes.status}`);
  console.log(`[*] Replay response body: ${replayBody}`);

  if (replayRes.status === 401) {
    console.log('[PASS] Replayed token was refused with HTTP 401.');
  } else {
    console.error(`[FAIL] Expected 401 but got: ${replayRes.status}`);
    process.exit(1);
  }
}

run().catch((err) => {
  console.error('[ERROR] Attack script error:', err.message);
  process.exit(1);
});
