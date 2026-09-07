/**
 * SECURITY TEST SCRIPT: 10-claims
 * Target: http://localhost:4000 (playground)
 *
 * Verifies that requireFreshAuth enforces genuine re-authentication freshness
 * and rejects stale or refreshed sessions.
 */

const BASE_URL = 'http://localhost:4000';

interface StepUpCheck {
  guard: string;
  expected: 'allowed' | 'refused';
  allowed: boolean;
  status: number;
  auditReason?: string;
}

async function run(): Promise<void> {
  console.log('[SECURITY TEST] 10-claims: Testing Step-Up Fresh Authentication...');

  console.log('[*] Invoking /api/authz/step-up...');
  const res = await fetch(`${BASE_URL}/api/authz/step-up`, {
    method: 'POST',
  });

  const data = await res.json() as {
    claim?: { passed: boolean };
    checks?: StepUpCheck[];
    timeline?: string[];
  };

  console.log(`[+] Step-up test completed. Claim passed: ${data.claim?.passed}`);

  if (data.checks && data.checks.length > 0) {
    for (const check of data.checks) {
      console.log(`  - Guard: ${check.guard} | Expected: ${check.expected} | Got Allowed: ${check.allowed} (HTTP ${check.status})`);
    }
  }

  if (data.claim?.passed === true) {
    console.log('[PASS] Step-up authentication correctly refused stale and refreshed sessions.');
  } else {
    console.error('[FAIL] Step-up freshness check did not pass!');
    process.exit(1);
  }
}

run().catch((err) => {
  console.error('[ERROR] Attack script error:', err.message);
  process.exit(1);
});
