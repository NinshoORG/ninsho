/**
 * SECURITY TEST SCRIPT: 04-logout-revocation
 * Target: http://localhost:3000 (express-api)
 *
 * Verifies that /auth/logout-all terminates all sessions across all devices.
 */

const BASE_URL = 'http://localhost:3000';

async function run(): Promise<void> {
  console.log('[SECURITY TEST] 04-logout-revocation: Testing Global Revocation Cascade...');

  const email = `logoutall_${Date.now()}@example.com`;
  const password = 'StrongPassword123!';

  // Register
  const regRes = await fetch(`${BASE_URL}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const { accessToken: tokenA } = await regRes.json() as { accessToken: string };
  console.log(`[+] Device A session obtained: ${tokenA.slice(0, 10)}...`);

  // Second login (Device B)
  const loginRes = await fetch(`${BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const { accessToken: tokenB } = await loginRes.json() as { accessToken: string };
  console.log(`[+] Device B session obtained: ${tokenB.slice(0, 10)}...`);

  // Verify both active
  const checkA1 = await fetch(`${BASE_URL}/me`, { headers: { Authorization: `Bearer ${tokenA}` } });
  const checkB1 = await fetch(`${BASE_URL}/me`, { headers: { Authorization: `Bearer ${tokenB}` } });
  if (checkA1.status !== 200 || checkB1.status !== 200) {
    console.error('[-] Precondition failed: sessions not active');
    process.exit(1);
  }
  console.log('[+] Verified both sessions A and B are active (200 OK).');

  // Trigger logout-all from Device A
  console.log('[*] Device A calls /auth/logout-all...');
  const logoutRes = await fetch(`${BASE_URL}/auth/logout-all`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${tokenA}` },
  });
  console.log(`[+] logout-all response status: ${logoutRes.status}`);

  // Test Device B
  console.log('[*] Testing Device B access on /me...');
  const checkB2 = await fetch(`${BASE_URL}/me`, { headers: { Authorization: `Bearer ${tokenB}` } });
  console.log(`[*] Device B /me response status: ${checkB2.status}`);

  // Test Device A
  console.log('[*] Testing Device A access on /me...');
  const checkA2 = await fetch(`${BASE_URL}/me`, { headers: { Authorization: `Bearer ${tokenA}` } });
  console.log(`[*] Device A /me response status: ${checkA2.status}`);

  if (checkA2.status === 401 && checkB2.status === 401) {
    console.log('[PASS] All user sessions successfully revoked on all devices.');
  } else {
    console.error(`[FAIL] Sessions still active! Device A: ${checkA2.status}, Device B: ${checkB2.status}`);
    process.exit(1);
  }
}

run().catch((err) => {
  console.error('[ERROR] Attack script error:', err.message);
  process.exit(1);
});
