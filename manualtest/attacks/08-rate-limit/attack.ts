/**
 * SECURITY TEST SCRIPT: 08-rate-limit
 * Target: http://localhost:3000 (express-api)
 *
 * Verifies that the sliding window rate limiter blocks brute-force login attempts
 * with HTTP 429 Too Many Requests.
 */

const BASE_URL = 'http://localhost:3000';

async function run(): Promise<void> {
  console.log('[SECURITY TEST] 08-rate-limit: Testing Brute-Force Rate Limiting...');

  const targetEmail = `bruteforce_target_${Date.now()}@example.com`;
  console.log(`[*] Targeting account: ${targetEmail}`);

  let triggered429 = false;

  for (let i = 1; i <= 7; i++) {
    const res = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        // Attempt spoofing X-Forwarded-For
        'X-Forwarded-For': `198.51.100.${i}`,
      },
      body: JSON.stringify({ email: targetEmail, password: `WrongGuess${i}!` }),
    });

    const status = res.status;
    const retryAfter = res.headers.get('retry-after');
    console.log(`[*] Request ${i}: status=${status} ${retryAfter ? `(Retry-After: ${retryAfter}s)` : ''}`);

    if (status === 429) {
      triggered429 = true;
      const body = await res.text();
      console.log(`[+] Rate limit response body: ${body}`);
      break;
    }
  }

  if (triggered429) {
    console.log('[PASS] Rate limiter correctly throttled attacker with HTTP 429.');
  } else {
    console.error('[FAIL] Rate limiter was not triggered within expected request threshold!');
    process.exit(1);
  }
}

run().catch((err) => {
  console.error('[ERROR] Attack script error:', err.message);
  process.exit(1);
});
