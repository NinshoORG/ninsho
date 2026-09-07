/**
 * SECURITY TEST SCRIPT: 07-rbac-escalation
 * Target: http://localhost:3000 (express-api)
 *
 * Verifies that role-based access control blocks unauthorized callers
 * and properly differentiates 401 Unauthorized from 403 Forbidden.
 */

const BASE_URL = 'http://localhost:3000';

async function run(): Promise<void> {
  console.log('[SECURITY TEST] 07-rbac-escalation: Testing RBAC Role Enforcement...');

  // 1. Register normal user
  const email = `user_${Date.now()}@example.com`;
  const regRes = await fetch(`${BASE_URL}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: 'UserPassword123!' }),
  });
  const { accessToken } = await regRes.json() as { accessToken: string };
  console.log(`[+] Standard user token: ${accessToken.slice(0, 10)}...`);

  // 2. Anonymous attempt to /admin/reports
  console.log('[*] Anonymous request to /admin/reports...');
  const anonRes = await fetch(`${BASE_URL}/admin/reports`);
  console.log(`[*] Anonymous status: ${anonRes.status}`);

  // 3. Authenticated standard user attempt to /admin/reports
  console.log('[*] Standard user request to /admin/reports...');
  const userRes = await fetch(`${BASE_URL}/admin/reports`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const userBody = await userRes.text();
  console.log(`[*] Standard user status: ${userRes.status}`);
  console.log(`[*] Standard user body: ${userBody}`);

  if (anonRes.status === 401 && userRes.status === 403) {
    console.log('[PASS] RBAC properly distinguished 401 (unauthenticated) from 403 (unauthorized role).');
  } else {
    console.error(`[FAIL] Unexpected statuses: anon=${anonRes.status}, user=${userRes.status}`);
    process.exit(1);
  }
}

run().catch((err) => {
  console.error('[ERROR] Attack script error:', err.message);
  process.exit(1);
});
