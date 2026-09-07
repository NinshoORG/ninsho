import fs from 'node:fs';

async function run() {
  // Test A: Oversized payload (32 KB to /auth/login, limit is 16 KB)
  const oversizedPayload = JSON.stringify({
    email: 'test@example.com',
    password: 'A'.repeat(32768),
  });
  const bodyRes = await fetch('http://localhost:3000/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: oversizedPayload,
  });
  const bodyStatus = bodyRes.status;
  const bodyText = await bodyRes.text();

  // Test B: Malformed URI escape in Cookie header (ninsho_rt=%)
  const cookieRes = await fetch('http://localhost:3000/auth/refresh', {
    method: 'POST',
    headers: { 'Cookie': 'ninsho_rt=%' },
  });
  const cookieStatus = cookieRes.status;
  const cookieText = await cookieRes.text();

  // Test C: Corrupted / Non-Base64 token in Authorization header
  const nonB64Res = await fetch('http://localhost:3000/me', {
    headers: { 'Authorization': 'Bearer !@#$%^&*()_+~' },
  });
  const nonB64Status = nonB64Res.status;
  const nonB64Text = await nonB64Res.text();

  // Test D: Verify health check
  const healthRes = await fetch('http://localhost:3000/health');
  const healthStatus = healthRes.status;
  const healthText = await healthRes.text();

  const passed = (bodyStatus === 413 || bodyStatus === 400) &&
                 cookieStatus === 401 &&
                 nonB64Status === 401 &&
                 healthStatus === 200;

  const evidence = [
    '=== MT-20 EVIDENCE: MALFORMED TOKEN STRUCTURES & RESILIENCE ===',
    `Timestamp: ${new Date().toISOString()}`,
    'Target Endpoints: POST /auth/login, POST /auth/refresh, GET /me, GET /health',
    '',
    '1. Oversized Request Body (32 KB vs 16 KB limit):',
    `   Status: ${bodyStatus} (Expected: 413 or 400)`,
    `   Body: ${bodyText}`,
    '',
    '2. Malformed URI Escape in Cookie (ninsho_rt=%):',
    `   Status: ${cookieStatus} (Expected: 401, no 500 URIError)`,
    `   Body: ${cookieText}`,
    '',
    '3. Corrupted / Non-Base64 Token in Authorization Header:',
    `   Status: ${nonB64Status} (Expected: 401)`,
    `   Body: ${nonB64Text}`,
    '',
    '4. Process Liveness / Health Check Post-Attack:',
    `   Status: ${healthStatus}`,
    `   Body: ${healthText}`,
    '',
    '--- Evaluation ---',
    'Requirement: All malformed inputs safely rejected with 4xx, no process crash, health check 200 OK',
    `Observed: bodyStatus=${bodyStatus}, cookieStatus=${cookieStatus}, nonB64Status=${nonB64Status}, healthStatus=${healthStatus}`,
    `Result: ${passed ? 'PASS' : 'FAIL'}`
  ].join('\n');

  fs.writeFileSync('manualtest/evidence/MT-20-malformed-tokens.txt', evidence);
  console.log(evidence);
}

run().catch(console.error);
