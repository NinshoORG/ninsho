import fs from 'node:fs';
import { generateDpopKeyPair, createDpopProof, jwkThumbprint } from '@ninshorg/server';

function getCookie(headers: Headers): string | null {
  const sc = headers.get('set-cookie');
  if (!sc) return null;
  const match = sc.match(/ninsho_playground=([^;]+)/);
  // A matched group is `string | undefined` under noUncheckedIndexedAccess:
  // the regex guarantees group 1 exists, the type system does not.
  return match?.[1] ?? null;
}

async function run() {
  const keyPair = await generateDpopKeyPair();
  const thumbprint = await jwkThumbprint(keyPair.publicJwk);

  const bindRes = await fetch('http://localhost:4000/api/dpop/bind', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ thumbprint }),
  });
  const visitorCookie = getCookie(bindRes.headers);
  const cookieHeaders = {
    'Content-Type': 'application/json',
    'Cookie': `ninsho_playground=${visitorCookie}`,
  };
  const bindData = await bindRes.json() as { ok: boolean; accessToken: string };
  const accessToken = bindData.accessToken;
  const endpointUrl = 'http://localhost:4000/api/dpop/call';

  // MT-14: Missing Proof
  const missingRes = await fetch(endpointUrl, {
    method: 'POST',
    headers: cookieHeaders,
    body: JSON.stringify({ thumbprint, omitProof: true }),
  });
  const missingData = await missingRes.json() as { accepted: boolean; code: string };
  fs.writeFileSync('manualtest/evidence/MT-14-missing-dpop.txt', [
    '=== MT-14 EVIDENCE: MISSING DPOP PROOF ===',
    `Timestamp: ${new Date().toISOString()}`,
    `Target Endpoint: POST ${endpointUrl}`,
    `Thumbprint: ${thumbprint}`,
    'Request Body: {"thumbprint":"...", "omitProof":true}',
    `Response: ${JSON.stringify(missingData, null, 2)}`,
    `Evaluation: ${missingData.accepted === false && missingData.code === 'TOKEN_MISSING' ? 'PASS' : 'FAIL'}`
  ].join('\n'));

  // MT-15: HTTP Method Mismatch
  const wrongMethodProof = createDpopProof(keyPair, { method: 'GET', url: endpointUrl, accessToken });
  const wrongMethodRes = await fetch(endpointUrl, {
    method: 'POST',
    headers: cookieHeaders,
    body: JSON.stringify({ thumbprint, proof: wrongMethodProof }),
  });
  const wrongMethodData = await wrongMethodRes.json() as { accepted: boolean; detail?: string };
  fs.writeFileSync('manualtest/evidence/MT-15-dpop-method-mismatch.txt', [
    '=== MT-15 EVIDENCE: DPOP HTTP-METHOD MISMATCH ===',
    `Timestamp: ${new Date().toISOString()}`,
    `Target Endpoint: POST ${endpointUrl}`,
    'Proof Method: GET (Request Method: POST)',
    `Response: ${JSON.stringify(wrongMethodData, null, 2)}`,
    `Evaluation: ${wrongMethodData.accepted === false && wrongMethodData.detail?.includes('htm mismatch') ? 'PASS' : 'FAIL'}`
  ].join('\n'));

  // MT-16: URL Mismatch
  const wrongUrlProof = createDpopProof(keyPair, { method: 'POST', url: 'http://localhost:4000/api/other-resource', accessToken });
  const wrongUrlRes = await fetch(endpointUrl, {
    method: 'POST',
    headers: cookieHeaders,
    body: JSON.stringify({ thumbprint, proof: wrongUrlProof }),
  });
  const wrongUrlData = await wrongUrlRes.json() as { accepted: boolean; detail?: string };
  fs.writeFileSync('manualtest/evidence/MT-16-dpop-url-mismatch.txt', [
    '=== MT-16 EVIDENCE: DPOP URL MISMATCH ===',
    `Timestamp: ${new Date().toISOString()}`,
    `Target Endpoint: POST ${endpointUrl}`,
    'Proof URL: http://localhost:4000/api/other-resource (Request URL: /api/dpop/call)',
    `Response: ${JSON.stringify(wrongUrlData, null, 2)}`,
    `Evaluation: ${wrongUrlData.accepted === false && wrongUrlData.detail?.includes('htu does not match') ? 'PASS' : 'FAIL'}`
  ].join('\n'));

  // MT-17: Proof Replay
  const validProof = createDpopProof(keyPair, { method: 'POST', url: endpointUrl, accessToken });
  const call1 = await fetch(endpointUrl, {
    method: 'POST',
    headers: cookieHeaders,
    body: JSON.stringify({ thumbprint, proof: validProof }),
  });
  const call1Data = await call1.json() as { accepted: boolean };

  const call2 = await fetch(endpointUrl, {
    method: 'POST',
    headers: cookieHeaders,
    body: JSON.stringify({ thumbprint, proof: validProof }),
  });
  const call2Data = await call2.json() as { accepted: boolean; code: string };
  fs.writeFileSync('manualtest/evidence/MT-17-dpop-replay.txt', [
    '=== MT-17 EVIDENCE: DPOP PROOF REPLAY ===',
    `Timestamp: ${new Date().toISOString()}`,
    `Target Endpoint: POST ${endpointUrl}`,
    `Call 1 (Initial Presentation): ${JSON.stringify(call1Data, null, 2)}`,
    `Call 2 (Replayed Proof Presentation): ${JSON.stringify(call2Data, null, 2)}`,
    `Evaluation: ${call1Data.accepted === true && call2Data.accepted === false ? 'PASS' : 'FAIL'}`
  ].join('\n'));

  console.log('Successfully executed and generated evidence for MT-14, MT-15, MT-16, and MT-17.');
}

run().catch(console.error);
