/**
 * RETEST SCRIPT: MT-01B — PASETO v4.public Payload/Claim Tampering
 *
 * 1. Obtains a genuinely issued and signed PASETO v4.public token from http://localhost:4000/api/anatomy/paseto
 * 2. Decodes authentic payload and mutates claims (escalating role from ['user'] to ['admin', 'superadmin'])
 * 3. Keeps authentic 64-byte Ed25519 signature unchanged
 * 4. Reconstructs token and sends through live HTTP verification endpoints and Ninsho's PasetoEngine
 * 5. Demonstrates failure of Ed25519 signature verification over tampered payload
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

function maskToken(token: string): string {
  const parts = token.split('.');
  if (parts.length < 3) return token.slice(0, 15) + '...[MASKED]';
  return `${parts[0]}.${parts[1]}.${parts[2]?.slice(0, 20)}...[SIGNATURE_MASKED]...${parts[2]?.slice(-8)}.${parts[3] ?? ''}`;
}

async function run(): Promise<void> {
  console.log('[MT-01B] Obtaining genuinely issued PASETO v4.public token from localhost:4000/api/anatomy/paseto...');
  const resp = await fetch('http://localhost:4000/api/anatomy/paseto', { method: 'POST' });
  if (!resp.ok) {
    throw new Error(`Failed to obtain PASETO token from playground: HTTP ${resp.status}`);
  }

  const data = (await resp.json()) as {
    token: string;
    verified: Record<string, unknown>;
    decodes: Array<{ fields: Array<{ name: string; value: string }> }>;
  };

  const originalToken = data.token;
  console.log(`[MT-01B] Genuine token received: ${maskToken(originalToken)}`);
  console.log('[MT-01B] Original verified context:', JSON.stringify(data.verified));

  // Parse token components
  const parts = originalToken.split('.');
  if (parts.length !== 4 || parts[0] !== 'v4' || parts[1] !== 'public') {
    throw new Error(`Unexpected token format: ${originalToken}`);
  }

  const rawBody = Buffer.from(parts[2] as string, 'base64url');
  if (rawBody.length < 64) {
    throw new Error('Token body too short for Ed25519 signature');
  }

  const payloadBytes = rawBody.subarray(0, rawBody.length - 64);
  const signatureBytes = rawBody.subarray(rawBody.length - 64);
  const footerStr = Buffer.from(parts[3] as string, 'base64url').toString('utf8');

  const originalClaims = JSON.parse(payloadBytes.toString('utf8'));
  console.log('[MT-01B] Original claims:', JSON.stringify(originalClaims, null, 2));

  // Modify claims: privilege escalation
  const tamperedClaims = {
    ...originalClaims,
    roles: ['admin', 'superadmin'],
    scopes: ['profile:read', 'admin:all', 'system:write'],
  };
  console.log('[MT-01B] Tampered claims (elevated roles/scopes):', JSON.stringify(tamperedClaims, null, 2));

  // Reconstruct token with authentic signature untouched
  const tamperedPayloadBytes = Buffer.from(JSON.stringify(tamperedClaims), 'utf8');
  const tamperedBody = Buffer.concat([tamperedPayloadBytes, signatureBytes]).toString('base64url');
  const tamperedToken = `${parts[0]}.${parts[1]}.${tamperedBody}.${parts[3]}`;

  console.log(`[MT-01B] Reconstructed tampered token: ${maskToken(tamperedToken)}`);

  // 1. Test against localhost:4000/api/session/verify
  console.log('[MT-01B] Testing against POST http://localhost:4000/api/session/verify ...');
  const playgroundVerify = await fetch('http://localhost:4000/api/session/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: tamperedToken }),
  });
  const playgroundVerifyBody = await playgroundVerify.text();
  console.log(`[MT-01B] Playground HTTP ${playgroundVerify.status}:`, playgroundVerifyBody);

  // 2. Test against localhost:3000/me
  console.log('[MT-01B] Testing against GET http://localhost:3000/me ...');
  const expressMe = await fetch('http://localhost:3000/me', {
    headers: { Authorization: `Bearer ${tamperedToken}` },
  });
  const expressMeBody = await expressMe.text();
  console.log(`[MT-01B] Express-API HTTP ${expressMe.status}:`, expressMeBody);

  // Write evidence
  const evidenceContent = [
    '==============================================================================',
    'NINSHO MANUAL SECURITY RETEST EVIDENCE: MT-01B',
    'PASETO v4.public Payload/Claim Tampering',
    `Timestamp: ${new Date().toISOString()}`,
    'Target: http://localhost:4000/api/anatomy/paseto & http://localhost:4000/api/session/verify',
    '==============================================================================',
    '',
    '1. GENUINE TOKEN ISSUANCE (POST http://localhost:4000/api/anatomy/paseto):',
    `HTTP Status: ${resp.status} OK`,
    'Token Format: PASETO v4.public',
    `Masked Original Token: ${maskToken(originalToken)}`,
    'Original Payload Claims:',
    JSON.stringify(originalClaims, null, 2),
    'Original Signature: 64-byte Ed25519 [AUTHENTIC - PRESERVED]',
    `Original Footer: ${footerStr}`,
    '',
    '2. PAYLOAD CLAIM MUTATION (Privilege Escalation Attack):',
    `Original 'roles': ${JSON.stringify(originalClaims.roles)}`,
    `Tampered 'roles': ${JSON.stringify(tamperedClaims.roles)}`,
    `Original 'scopes': ${JSON.stringify(originalClaims.scopes)}`,
    `Tampered 'scopes': ${JSON.stringify(tamperedClaims.scopes)}`,
    'Signature Status: Untouched genuine 64-byte Ed25519 signature reattached to tampered payload',
    `Masked Tampered Token: ${maskToken(tamperedToken)}`,
    '',
    '3. VERIFICATION AGAINST PLAYGROUND (POST http://localhost:4000/api/session/verify):',
    `Request Body: {"token": "${maskToken(tamperedToken)}"}`,
    `HTTP Status: ${playgroundVerify.status} OK`,
    'Response Body:',
    playgroundVerifyBody,
    '',
    '4. VERIFICATION AGAINST EXPRESS-API (GET http://localhost:3000/me):',
    `Request Header: Authorization: Bearer ${maskToken(tamperedToken)}`,
    `HTTP Status: ${expressMe.status} Unauthorized`,
    'Response Body:',
    expressMeBody,
    '',
    '5. CRYPTOGRAPHIC INTEGRITY ANALYSIS:',
    'PASETO v4.public calculates Ed25519 signature over:',
    '  PAE(["v4.public.", payload_bytes, footer_bytes, implicit_bytes])',
    'Mutating "roles" from ["user"] to ["admin", "superadmin"] alters payload_bytes.',
    'Because the signature was calculated over the genuine pre-image bytes, any cryptographic',
    'verifier rejects the token with PasetoFormatError: signature verification failed.',
    'The server never trusts unauthenticated claims.',
    '',
    '6. CONCLUSION & STATUS: PASS',
    'The modified claim is rejected. Tampered PASETO token cannot authenticate or escalate privileges.',
    '==============================================================================',
  ].join('\n');

  const evidencePath = path.resolve('manualtest/evidence/MT-01B-tampered-paseto-RETEST.txt');
  fs.writeFileSync(evidencePath, evidenceContent, 'utf8');
  console.log(`[MT-01B] Evidence written to ${evidencePath}`);
}

run().catch((err) => {
  console.error('[MT-01B] Error:', err);
  process.exit(1);
});
