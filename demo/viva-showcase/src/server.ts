import express, { type Request, type Response, type NextFunction } from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { getAuth, isNinshoError, toErrorResponse } from '@ninshorg/server';
import {
  DEMO_USERS,
  DEMO_PRODUCTS,
  getOrdersForUser,
  verifyUserPassword,
} from './services/mock-data.js';
import {
  issueStatelessJwt,
  verifyStatelessJwt,
} from './services/jwt-baseline.js';
import {
  createOpaqueInstances,
  loginOpaque,
  type OpaqueInstances,
} from './services/ninsho-opaque.js';
import {
  createDpopService,
  toNinshoRequest,
  type DpopService,
} from './services/ninsho-dpop.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export interface ShowcaseServer {
  readonly app: express.Express;
  close(): Promise<void>;
}

export function createShowcaseApp(redisUrl = process.env.REDIS_URL || 'redis://127.0.0.1:6379'): {
  app: express.Express;
  opaque: OpaqueInstances;
  dpop: DpopService;
  close(): Promise<void>;
} {
  const app = express();
  app.use(express.json());
  app.use(cookieParser());
  app.use(cors());

  // Serve client distribution from installed node_modules
  const clientDist = join(__dirname, '../node_modules/@ninshorg/client/dist');
  app.use('/vendor/@ninshorg/client', express.static(clientDist));

  // Serve static UI assets
  const publicDir = join(__dirname, '../public');
  app.use(express.static(publicDir));

  // Initialize Ninsho services
  const opaque = createOpaqueInstances(redisUrl);
  const dpop = createDpopService(redisUrl);

  // ── Public Routes ──────────────────────────────────────────────────────────

  app.get('/api/products', (_req: Request, res: Response) => {
    res.json({ products: DEMO_PRODUCTS });
  });

  app.get('/api/health', async (_req: Request, res: Response) => {
    try {
      const okA = await opaque.instanceA.health();
      const okB = await opaque.instanceB.health();
      const okD = await dpop.auth.health();
      res.json({
        status: 'healthy',
        redis: { instanceA: okA, instanceB: okB, dpop: okD },
        packageVersions: {
          server: '0.1.1',
          client: '0.1.1',
          core: '0.1.1',
        },
      });
    } catch (err) {
      res.status(503).json({
        status: 'degraded',
        error: err instanceof Error ? err.message : String(err),
      });
    }
  });

  // ── Comparison A: Stateless JWT Baseline ───────────────────────────────────

  app.post('/api/jwt/login', async (req: Request, res: Response) => {
    const { email, password } = req.body || {};
    const user = verifyUserPassword(email, password);
    if (!user) {
      return res.status(401).json({
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password for demo user',
        },
      });
    }

    const { token, expiresInSeconds } = await issueStatelessJwt(user);
    res.json({
      token,
      expiresInSeconds,
      user,
      comparison: 'stateless-jwt-baseline',
      notice: 'Token is signed with HS256. Stored in localStorage by client.',
    });
  });

  app.get('/api/jwt/dashboard', async (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: {
          code: 'TOKEN_MISSING',
          message: 'Authorization header with Bearer token required',
        },
      });
    }

    const rawToken = authHeader.slice(7).trim();
    try {
      const payload = await verifyStatelessJwt(rawToken);
      const orders = getOrdersForUser(payload.sub);
      res.json({
        user: {
          id: payload.sub,
          email: payload.email,
          name: payload.name,
          role: payload.role,
        },
        orders,
        verifiedBy: 'Stateless JWT Verifier (jose)',
        securityModel: 'Pure signature & exp check; no server-side denylist',
        tokenClaims: {
          sub: payload.sub,
          iat: payload.iat,
          exp: payload.exp,
        },
      });
    } catch (err) {
      res.status(401).json({
        error: {
          code: 'TOKEN_INVALID',
          message: err instanceof Error ? err.message : 'Invalid or expired JWT',
        },
      });
    }
  });

  app.post('/api/jwt/logout', (_req: Request, res: Response) => {
    // In a stateless JWT system, the server retains no record.
    // Logout is simulated on the client by deleting the token from localStorage.
    res.json({
      ok: true,
      message: 'Client removed token from localStorage. Server retains no revocation state.',
      warning: 'Any captured copy of this token remains valid at the server until expiry!',
    });
  });

  // ── Comparison B: Ninsho Opaque Dual-Instance Sessions ──────────────────────

  app.post('/api/opaque/login', async (req: Request, res: Response) => {
    const { email, password } = req.body || {};
    const user = verifyUserPassword(email, password);
    if (!user) {
      return res.status(401).json({
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password',
        },
      });
    }

    try {
      const session = await loginOpaque(opaque.instanceA, user);
      res.json({
        accessToken: session.accessToken,
        sessionId: session.sessionId,
        expiresInSeconds: session.expiresInSeconds,
        user,
        issuedBy: 'Ninsho Instance A',
        comparison: 'ninsho-opaque-sessions',
      });
    } catch (err) {
      if (isNinshoError(err)) {
        const { status, body } = toErrorResponse(err);
        return res.status(status).json(body);
      }
      res.status(500).json({ error: { message: 'Failed to create opaque session' } });
    }
  });

  app.get(
    '/api/opaque/instance-a/orders',
    opaque.instanceA.verify(),
    (req: Request, res: Response) => {
      const auth = getAuth(req);
      const orders = getOrdersForUser(auth.userId);
      res.json({
        verifiedBy: 'Ninsho Instance A (Active Connection 1)',
        user: auth,
        orders,
        sharedStore: 'Redis (secureshop:opaque: namespace)',
      });
    },
  );

  app.get(
    '/api/opaque/instance-b/orders',
    opaque.instanceB.verify(),
    (req: Request, res: Response) => {
      const auth = getAuth(req);
      const orders = getOrdersForUser(auth.userId);
      res.json({
        verifiedBy: 'Ninsho Instance B (Active Connection 2)',
        user: auth,
        orders,
        sharedStore: 'Redis (secureshop:opaque: namespace)',
      });
    },
  );

  app.post('/api/opaque/logout', async (req: Request, res: Response) => {
    const sessionId = (req.body?.sessionId as string) || '';
    if (!sessionId) {
      return res.status(400).json({
        error: { code: 'MISSING_SESSION_ID', message: 'sessionId required for revocation' },
      });
    }

    try {
      // Revoke via Instance A on the shared store
      await opaque.instanceA.revokeSession(sessionId, 'logout');
      res.json({
        ok: true,
        revokedBy: 'Ninsho Instance A',
        message: 'Session revoked across the shared Redis store.',
        guarantee: 'Tokens will immediately fail on both Instance A and Instance B.',
      });
    } catch (err) {
      if (isNinshoError(err)) {
        const { status, body } = toErrorResponse(err);
        return res.status(status).json(body);
      }
      res.status(500).json({ error: { message: 'Failed to revoke session' } });
    }
  });

  // ── Comparison C: Ninsho DPoP Browser Client ───────────────────────────────

  app.post('/api/dpop/login', async (req: Request, res: Response) => {
    const { email, password } = req.body || {};
    const user = verifyUserPassword(email, password);
    if (!user) {
      return res.status(401).json({
        error: { code: 'INVALID_CREDENTIALS', message: 'Invalid credentials' },
      });
    }

    try {
      const ninshoReq = toNinshoRequest(req);
      const jkt = await dpop.auth.confirmProofOfPossession(ninshoReq);
      const pair = await dpop.auth.createSession(
        { userId: user.id, roles: [user.role], scopes: [] },
        { confirmationKey: jkt },
      );

      // HttpOnly cookie for refresh rotation
      res.cookie('ninsho_dpop_rt', pair.refreshToken, {
        httpOnly: true,
        sameSite: 'lax',
        path: '/api/dpop',
        maxAge: 7 * 86400 * 1000,
      });

      res.json({
        accessToken: pair.accessToken,
        sessionId: pair.sessionId,
        user,
        confirmationKey: jkt,
        comparison: 'ninsho-dpop-client',
        message: 'Bound session created. Access token held in memory only.',
      });
    } catch (err) {
      if (isNinshoError(err)) {
        const { status, body } = toErrorResponse(err);
        return res.status(status).json(body);
      }
      res.status(400).json({
        error: {
          code: 'DPOP_PROOF_FAILED',
          message: err instanceof Error ? err.message : 'DPoP proof verification failed',
        },
      });
    }
  });

  app.post('/api/dpop/refresh', async (req: Request, res: Response) => {
    const rawRefresh = (req.cookies?.ninsho_dpop_rt as string) || '';
    if (!rawRefresh) {
      return res.status(401).json({
        error: { code: 'NO_REFRESH_TOKEN', message: 'No refresh cookie present' },
      });
    }

    try {
      const ninshoReq = toNinshoRequest(req);
      const jkt = await dpop.auth.confirmProofOfPossession(ninshoReq);
      const pair = await dpop.auth.refresh(rawRefresh, { confirmationKey: jkt });

      res.cookie('ninsho_dpop_rt', pair.refreshToken, {
        httpOnly: true,
        sameSite: 'lax',
        path: '/api/dpop',
        maxAge: 7 * 86400 * 1000,
      });

      res.json({ accessToken: pair.accessToken });
    } catch (err) {
      res.clearCookie('ninsho_dpop_rt', { path: '/api/dpop' });
      if (isNinshoError(err)) {
        const { status, body } = toErrorResponse(err);
        return res.status(status).json(body);
      }
      res.status(401).json({ error: { message: 'Refresh rejected' } });
    }
  });

  app.get('/api/dpop/orders', dpop.auth.verify(), (req: Request, res: Response) => {
    const auth = getAuth(req);
    const orders = getOrdersForUser(auth.userId);
    res.json({
      verifiedBy: 'Ninsho DPoP Engine (RFC 9449 Proof of Possession Verified)',
      user: auth,
      orders,
      securityGuarantee: 'Token bound to non-extractable client key. Token-only replay is impossible.',
    });
  });

  // Logout is authenticated: the session to revoke is the one the verified
  // access token belongs to. This previously passed the raw refresh cookie to
  // revokeSession(), which takes a session id, so nothing was revoked while the
  // response claimed otherwise. See server.test.ts › *revokes the server session
  // on logout*. The cookie is cleared first so even a refused logout (expired
  // token) leaves no refresh credential in this browser.
  app.post(
    '/api/dpop/logout',
    (_req: Request, res: Response, next: NextFunction) => {
      res.clearCookie('ninsho_dpop_rt', { path: '/api/dpop' });
      next();
    },
    dpop.auth.verify(),
    async (req: Request, res: Response) => {
      const { sessionId } = getAuth(req);
      try {
        await dpop.auth.revokeSession(sessionId, 'logout');
      } catch (err) {
        // Report the failure rather than claim a revocation that did not happen.
        if (isNinshoError(err)) {
          const { status, body } = toErrorResponse(err);
          return res.status(status).json(body);
        }
        return res.status(503).json({
          error: { code: 'REVOCATION_FAILED', message: 'Session could not be revoked; try again' },
        });
      }
      res.json({
        ok: true,
        sessionId,
        message: 'Logged out. Cookie removed and server session revoked.',
      });
    },
  );

  // Global Error Handler
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (isNinshoError(err)) {
      const { status, body } = toErrorResponse(err);
      return res.status(status).json(body);
    }
    const message = err instanceof Error ? err.message : 'Internal Server Error';
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message } });
  });

  return {
    app,
    opaque,
    dpop,
    async close() {
      await Promise.all([opaque.close(), dpop.close()]);
    },
  };
}

// Direct execution entrypoint
if (process.env.NODE_ENV !== 'test' && (!process.env.VITEST || process.env.VITEST !== 'true')) {
  const PORT = Number(process.env.PORT) || 3000;
  const REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
  const showcase = createShowcaseApp(REDIS_URL);
  const server = showcase.app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🛡️  SecureShop Viva Showcase running at http://localhost:${PORT}`);
    console.log(`   Connected to Redis: ${REDIS_URL}\n`);
  });

  const shutdown = async () => {
    console.log('\nShutting down SecureShop showcase...');
    server.close();
    await showcase.close();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
