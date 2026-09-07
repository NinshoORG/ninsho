/**
 * SECURITY TEST SCRIPT: 11-malformed-input
 * Target: http://localhost:3000 (express-api)
 *
 * Verifies that oversized payloads and malformed cookies are handled
 * safely without process crashes or information disclosure.
 */

const BASE_URL = 'http://localhost:3000';

async function run(): Promise<void> {
  console.log('[SECURITY TEST] 11-malformed-input: Testing Parser Resilience & Body Limits...');

  // 1. Oversized body test (> 16 KB)
  console.log('[*] Sending 32 KB payload to /auth/login (limit is 16 KB)...');
  const oversizedPayload = JSON.stringify({
    email: 'attacker@example.com',
    password: 'A'.repeat(32768),
  });

  const bodyRes = await fetch(`${BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: oversizedPayload,
  });

  console.log(`[*] Oversized payload status: ${bodyRes.status}`);
  const bodyText = await bodyRes.text();
  console.log(`[*] Oversized payload body: ${bodyText}`);

  const bodyPassed = bodyRes.status === 413 || bodyRes.status === 400;

  // 2. Malformed URI cookie escape test (ninsho_rt=%)
  console.log('[*] Sending malformed URI escape cookie (ninsho_rt=%)...');
  const cookieRes = await fetch(`${BASE_URL}/auth/refresh`, {
    method: 'POST',
    headers: { Cookie: 'ninsho_rt=%' },
  });

  console.log(`[*] Malformed cookie status: ${cookieRes.status}`);
  const cookieText = await cookieRes.text();
  console.log(`[*] Malformed cookie body: ${cookieText}`);

  const cookiePassed = cookieRes.status === 401;

  // 3. Verify server health
  console.log('[*] Verifying server health...');
  const healthRes = await fetch(`${BASE_URL}/health`);
  console.log(`[*] Health status: ${healthRes.status}`);

  if (bodyPassed && cookiePassed && healthRes.status === 200) {
    console.log('[PASS] Server handled malformed inputs safely without crash or 500 error.');
  } else {
    console.error(`[FAIL] Issues detected: bodyPassed=${bodyPassed}, cookiePassed=${cookiePassed}`);
    process.exit(1);
  }
}

run().catch((err) => {
  console.error('[ERROR] Attack script error:', err.message);
  process.exit(1);
});
