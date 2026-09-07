/**
 * SECURITY TEST SCRIPT: 05-refresh-replay
 * Target: http://localhost:3000 (express-api)
 *
 * Verifies that replaying a rotated refresh token triggers reuse detection
 * and revokes the session family.
 */

const BASE_URL = 'http://localhost:3000';

function extractCookie(headers: Headers, name: string): string | undefined {
  const setCookie = headers.get('set-cookie');
  if (!setCookie) return undefined;
  const match = setCookie.match(new RegExp(`${name}=([^;]+)`));
  return match ? match[1] : undefined;
}

async function run(): Promise<void> {
  console.log('[SECURITY TEST] 05-refresh-replay: Testing Refresh Reuse Detection...');

  const email = `refresh_reuse_${Date.now()}@example.com`;
  const password = 'StrongPassword123!';

  // 1. Register & get RT1
  const regRes = await fetch(`${BASE_URL}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  const rt1 = extractCookie(regRes.headers, 'ninsho_rt');
  if (!rt1) {
    console.error('[-] Could not extract initial refresh cookie ninsho_rt');
    process.exit(1);
  }
  console.log(`[+] Initial refresh token (RT1): ${rt1.slice(0, 15)}...`);

  // 2. Legitimate rotation: Use RT1 to obtain RT2
  console.log('[*] Performing legitimate refresh using RT1...');
  const refresh1Res = await fetch(`${BASE_URL}/auth/refresh`, {
    method: 'POST',
    headers: { Cookie: `ninsho_rt=${rt1}` },
  });
  console.log(`[+] Refresh 1 status: ${refresh1Res.status}`);
  const rt2 = extractCookie(refresh1Res.headers, 'ninsho_rt');
  if (!rt2) {
    console.error('[-] Could not extract rotated refresh cookie RT2');
    process.exit(1);
  }
  console.log(`[+] Rotated refresh token (RT2): ${rt2.slice(0, 15)}...`);

  // 3. Attack: Replay spent RT1
  console.log('[*] Attacker replays already-spent RT1...');
  const replayRes = await fetch(`${BASE_URL}/auth/refresh`, {
    method: 'POST',
    headers: { Cookie: `ninsho_rt=${rt1}` },
  });
  console.log(`[*] Replay RT1 status: ${replayRes.status}`);
  const replayBody = await replayRes.text();
  console.log(`[*] Replay RT1 body: ${replayBody}`);

  // 4. Test if legitimate RT2 was invalidated by the breach response
  console.log('[*] Testing if legitimate RT2 was invalidated by reuse alarm...');
  const checkRt2Res = await fetch(`${BASE_URL}/auth/refresh`, {
    method: 'POST',
    headers: { Cookie: `ninsho_rt=${rt2}` },
  });
  console.log(`[*] Check RT2 status: ${checkRt2Res.status}`);

  if (replayRes.status === 401 && checkRt2Res.status === 401) {
    console.log('[PASS] Refresh token reuse correctly detected: attacker refused and session family revoked.');
  } else {
    console.error(`[FAIL] Unexpected status: replay=${replayRes.status}, rt2=${checkRt2Res.status}`);
    process.exit(1);
  }
}

run().catch((err) => {
  console.error('[ERROR] Attack script error:', err.message);
  process.exit(1);
});
