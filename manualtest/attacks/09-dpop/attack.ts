/**
 * SECURITY TEST SCRIPT: 09-dpop
 * Target: http://localhost:4000 (playground)
 *
 * Demonstrates that DPoP-bound tokens cannot be used without proof of possession.
 */

const BASE_URL = 'http://localhost:4000';

async function run(): Promise<void> {
  console.log('[SECURITY TEST] 09-dpop: Testing Proof-of-Possession Enforcement...');

  const thumbprint = `tb_${Date.now()}`;

  // 1. Bind session to thumbprint
  console.log(`[*] Binding session to thumbprint: ${thumbprint}...`);
  const bindRes = await fetch(`${BASE_URL}/api/dpop/bind`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ thumbprint }),
  });
  const bindData = await bindRes.json() as { ok: boolean; accessToken?: string };
  console.log(`[+] Bind response ok=${bindData.ok}`);

  // 2. Present token with omitProof: true (stolen token attack)
  console.log('[*] Simulating token theft: Presenting bound token without DPoP proof...');
  const stolenRes = await fetch(`${BASE_URL}/api/dpop/call`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ thumbprint, omitProof: true }),
  });
  const stolenData = await stolenRes.json() as { accepted: boolean; message?: string };
  console.log(`[*] Stolen token result:`, stolenData);

  // 3. Present invalid/empty proof
  console.log('[*] Presenting invalid DPoP proof...');
  const invalidRes = await fetch(`${BASE_URL}/api/dpop/call`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ thumbprint, proof: 'invalid.jwt.proof' }),
  });
  const invalidData = await invalidRes.json() as { accepted: boolean; message?: string };
  console.log(`[*] Invalid proof result:`, invalidData);

  if (stolenData.accepted === false && invalidData.accepted === false) {
    console.log('[PASS] Proof-of-possession successfully enforced: calls without valid proof rejected.');
  } else {
    console.error('[FAIL] DPoP protection was bypassed!');
    process.exit(1);
  }
}

run().catch((err) => {
  console.error('[ERROR] Attack script error:', err.message);
  process.exit(1);
});
