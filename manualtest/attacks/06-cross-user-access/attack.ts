/**
 * SECURITY TEST SCRIPT: 06-cross-user-access
 * Target: http://localhost:3000 (express-api)
 *
 * Verifies that requireOwner prevents Broken Object Level Authorization (IDOR).
 */

const BASE_URL = 'http://localhost:3000';

async function run(): Promise<void> {
  console.log('[SECURITY TEST] 06-cross-user-access: Testing BOLA / IDOR Defense...');

  // 1. Register Alice
  const aliceEmail = `alice_${Date.now()}@example.com`;
  const regAlice = await fetch(`${BASE_URL}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: aliceEmail, password: 'AlicePassword123!' }),
  });
  const aliceData = await regAlice.json() as { accessToken: string; user: { id: string } };
  console.log(`[+] Alice created: ID=${aliceData.user.id}`);

  // 2. Register Bob
  const bobEmail = `bob_${Date.now()}@example.com`;
  const regBob = await fetch(`${BASE_URL}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: bobEmail, password: 'BobPassword123!' }),
  });
  const bobData = await regBob.json() as { accessToken: string; user: { id: string } };
  console.log(`[+] Bob created: ID=${bobData.user.id}`);

  // 3. Alice accesses her own orders
  const aliceOwnRes = await fetch(`${BASE_URL}/users/${aliceData.user.id}/orders`, {
    headers: { Authorization: `Bearer ${aliceData.accessToken}` },
  });
  console.log(`[+] Alice accessing her own orders status: ${aliceOwnRes.status}`);

  // 4. Alice attempts to access Bob's orders
  console.log(`[*] Alice attempting to access Bob's orders (/users/${bobData.user.id}/orders)...`);
  const idorRes = await fetch(`${BASE_URL}/users/${bobData.user.id}/orders`, {
    headers: { Authorization: `Bearer ${aliceData.accessToken}` },
  });
  const idorBody = await idorRes.text();

  console.log(`[*] IDOR attempt response status: ${idorRes.status}`);
  console.log(`[*] IDOR attempt response body: ${idorBody}`);

  if (aliceOwnRes.status === 200 && idorRes.status === 403) {
    console.log('[PASS] BOLA/IDOR attempt successfully blocked with HTTP 403 Forbidden.');
  } else {
    console.error(`[FAIL] Unexpected status: own=${aliceOwnRes.status}, idor=${idorRes.status}`);
    process.exit(1);
  }
}

run().catch((err) => {
  console.error('[ERROR] Attack script error:', err.message);
  process.exit(1);
});
