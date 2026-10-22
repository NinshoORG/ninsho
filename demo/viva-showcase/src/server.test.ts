import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Server } from 'node:http';
import { generateDpopKeyPair, createDpopProof } from '@ninshorg/server';
import { createShowcaseApp, type ShowcaseServer } from './server.js';

describe('SecureShop Viva Showcase Integration Tests', () => {
  const REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
  let showcase: ReturnType<typeof createShowcaseApp>;
  let server: Server;
  let baseUrl: string;

  beforeAll(async () => {
    showcase = createShowcaseApp(REDIS_URL);
    await new Promise<void>((resolve) => {
      server = showcase.app.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        if (typeof addr === 'object' && addr !== null) {
          baseUrl = `http://127.0.0.1:${addr.port}`;
        }
        resolve();
      });
    });
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    if (showcase) {
      await showcase.close();
    }
  });

  // ── Comparison A: Stateless JWT Baseline ───────────────────────────────────

  describe('Comparison A: Stateless JWT Baseline', () => {
    it('accepts valid JWT, but STILL accepts a copied token after logout (stateless limitation)', async () => {
      // 1. Login
      const loginRes = await fetch(`${baseUrl}/api/jwt/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'alice@example.com', password: 'password123' }),
      });
      expect(loginRes.status).toBe(200);
      const loginData = (await loginRes.json()) as { token: string };
      const copiedToken = loginData.token;
      expect(copiedToken).toBeTruthy();

      // 2. Fetch dashboard
      const dashRes = await fetch(`${baseUrl}/api/jwt/dashboard`, {
        headers: { Authorization: `Bearer ${copiedToken}` },
      });
      expect(dashRes.status).toBe(200);
      const dashData = (await dashRes.json()) as { user: { email: string } };
      expect(dashData.user.email).toBe('alice@example.com');

      // 3. Perform logout
      const logoutRes = await fetch(`${baseUrl}/api/jwt/logout`, { method: 'POST' });
      expect(logoutRes.status).toBe(200);

      // 4. THE CRITICAL EXPERIMENT: Replay the copied token against protected route.
      // Because this baseline is pure stateless JWT, the server has no record of the logout
      // and STILL accepts the token before its natural expiry!
      const replayRes = await fetch(`${baseUrl}/api/jwt/dashboard`, {
        headers: { Authorization: `Bearer ${copiedToken}` },
      });
      expect(replayRes.status).toBe(200);
      const replayData = (await replayRes.json()) as { user: { email: string } };
      expect(replayData.user.email).toBe('alice@example.com');
    });
  });

  // ── Comparison B: Ninsho Opaque Dual-Instance Sessions ──────────────────────

  describe('Comparison B: Ninsho Opaque Dual-Instance Sessions', () => {
    it('verifies across both instances, and instantly revokes on both after logout', async () => {
      // 1. Login on Instance A
      const loginRes = await fetch(`${baseUrl}/api/opaque/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'alice@example.com', password: 'password123' }),
      });
      expect(loginRes.status).toBe(200);
      const loginData = (await loginRes.json()) as {
        accessToken: string;
        sessionId: string;
      };
      const copiedToken = loginData.accessToken;
      const sessionId = loginData.sessionId;

      // 2. Request through Instance A
      const resA = await fetch(`${baseUrl}/api/opaque/instance-a/orders`, {
        headers: { Authorization: `Bearer ${copiedToken}` },
      });
      expect(resA.status).toBe(200);
      const dataA = (await resA.json()) as { verifiedBy: string };
      expect(dataA.verifiedBy).toContain('Instance A');

      // 3. Request through Instance B (shared store)
      const resB = await fetch(`${baseUrl}/api/opaque/instance-b/orders`, {
        headers: { Authorization: `Bearer ${copiedToken}` },
      });
      expect(resB.status).toBe(200);
      const dataB = (await resB.json()) as { verifiedBy: string };
      expect(dataB.verifiedBy).toContain('Instance B');

      // 4. Logout via Instance A
      const logoutRes = await fetch(`${baseUrl}/api/opaque/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId }),
      });
      expect(logoutRes.status).toBe(200);

      // 5. THE CRITICAL EXPERIMENT: Replay copied token on Instance A -> REJECTED 401
      const replayResA = await fetch(`${baseUrl}/api/opaque/instance-a/orders`, {
        headers: { Authorization: `Bearer ${copiedToken}` },
      });
      expect(replayResA.status).toBe(401);

      // 6. Replay copied token on Instance B -> ALSO REJECTED 401 IMMEDIATELY
      const replayResB = await fetch(`${baseUrl}/api/opaque/instance-b/orders`, {
        headers: { Authorization: `Bearer ${copiedToken}` },
      });
      expect(replayResB.status).toBe(401);
    });
  });

  // ── Comparison C: Ninsho DPoP Browser Client ───────────────────────────────

  describe('Comparison C: Ninsho DPoP Proof of Possession', () => {
    it('accepts bound proof, rejects token-only replay, rejects wrong-key, and rejects proof replay', async () => {
      // Generate client key pair
      const clientKeyPair = generateDpopKeyPair('ES256');

      // 1. Create DPoP login proof
      const loginProof = createDpopProof(clientKeyPair, {
        method: 'POST',
        url: `${baseUrl}/api/dpop/login`,
      });

      const loginRes = await fetch(`${baseUrl}/api/dpop/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          DPoP: loginProof,
        },
        body: JSON.stringify({ email: 'bob@example.com', password: 'password123' }),
      });
      expect(loginRes.status).toBe(200);
      const loginData = (await loginRes.json()) as { accessToken: string };
      const accessToken = loginData.accessToken;

      // 2. Legitimate request with fresh DPoP proof
      const legitimateProof = createDpopProof(clientKeyPair, {
        method: 'GET',
        url: `${baseUrl}/api/dpop/orders`,
        accessToken,
      });

      const okRes = await fetch(`${baseUrl}/api/dpop/orders`, {
        headers: {
          Authorization: `DPoP ${accessToken}`,
          DPoP: legitimateProof,
        },
      });
      expect(okRes.status).toBe(200);

      // 3. THE TOKEN-ONLY REPLAY ATTACK:
      // An attacker steals the raw access token and presents it as a normal Bearer token
      // or DPoP token WITHOUT a valid DPoP proof header.
      const tokenOnlyRes = await fetch(`${baseUrl}/api/dpop/orders`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });
      expect(tokenOnlyRes.status).toBe(401);

      // 4. WRONG-KEY PROOF ATTACK:
      // An attacker presents their own key's proof with the victim's token.
      const attackerKeyPair = generateDpopKeyPair('ES256');
      const wrongKeyProof = createDpopProof(attackerKeyPair, {
        method: 'GET',
        url: `${baseUrl}/api/dpop/orders`,
        accessToken,
      });

      const wrongKeyRes = await fetch(`${baseUrl}/api/dpop/orders`, {
        headers: {
          Authorization: `DPoP ${accessToken}`,
          DPoP: wrongKeyProof,
        },
      });
      expect(wrongKeyRes.status).toBe(401);

      // 5. PROOF REPLAY ATTACK:
      // An attacker replays the exact same proof header that was already accepted in step 2.
      const replayedProofRes = await fetch(`${baseUrl}/api/dpop/orders`, {
        headers: {
          Authorization: `DPoP ${accessToken}`,
          DPoP: legitimateProof, // Already claimed jti
        },
      });
      expect(replayedProofRes.status).toBe(401);
    });

    it('revokes the server session on logout, so neither the access token nor the refresh cookie still works', async () => {
      // REGRESSION. The logout route passed the raw refresh-token cookie to
      // revokeSession(), which takes a session id. Nothing was revoked, the
      // response still said "server session revoked", and both credentials
      // kept working. Found by the second model-assisted review (B-12).
      const key = generateDpopKeyPair('ES256');
      const loginRes = await fetch(`${baseUrl}/api/dpop/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          DPoP: createDpopProof(key, { method: 'POST', url: `${baseUrl}/api/dpop/login` }),
        },
        body: JSON.stringify({ email: 'bob@example.com', password: 'password123' }),
      });
      expect(loginRes.status).toBe(200);
      const { accessToken } = (await loginRes.json()) as { accessToken: string };
      const refreshCookie = (loginRes.headers.get('set-cookie') ?? '').split(';')[0] ?? '';
      expect(refreshCookie.startsWith('ninsho_dpop_rt=')).toBe(true);

      const logoutRes = await fetch(`${baseUrl}/api/dpop/logout`, {
        method: 'POST',
        headers: {
          Authorization: `DPoP ${accessToken}`,
          DPoP: createDpopProof(key, { method: 'POST', url: `${baseUrl}/api/dpop/logout`, accessToken }),
          Cookie: refreshCookie,
        },
      });
      expect(logoutRes.status).toBe(200);

      // The access token, presented with a fresh and valid proof by the key holder.
      const afterAccess = await fetch(`${baseUrl}/api/dpop/orders`, {
        headers: {
          Authorization: `DPoP ${accessToken}`,
          DPoP: createDpopProof(key, { method: 'GET', url: `${baseUrl}/api/dpop/orders`, accessToken }),
        },
      });
      expect(afterAccess.status).toBe(401);

      // The refresh cookie a copied browser profile would still hold.
      const afterRefresh = await fetch(`${baseUrl}/api/dpop/refresh`, {
        method: 'POST',
        headers: {
          DPoP: createDpopProof(key, { method: 'POST', url: `${baseUrl}/api/dpop/refresh` }),
          Cookie: refreshCookie,
        },
      });
      expect(afterRefresh.status).toBe(401);
    });
  });
});
