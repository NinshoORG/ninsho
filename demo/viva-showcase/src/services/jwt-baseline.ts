import { SignJWT, jwtVerify, type JWTPayload } from 'jose';
import type { DemoUser } from './mock-data.js';

/**
 * COMPARISON A: STATELESS JWT BASELINE (DELIBERATELY LIMITED)
 *
 * This implementation illustrates a very common industry pattern:
 * - The server signs a JSON Web Token (JWT) using HMAC-SHA256 (HS256).
 * - Claims (sub, email, role, etc.) and expiration (5m) are in the payload.
 * - The client typically saves this token in browser `localStorage`.
 * - The server verifies only the cryptographic signature and expiration time.
 * - The server maintains ZERO server-side session state, database records,
 *   or revocation denylists.
 *
 * ⚠️ DEMONSTRATED LIMITATION:
 * When a user "logs out", the client clears its `localStorage`. But the
 * token itself remains cryptographically valid. An attacker or copied token
 * replayed over HTTP will CONTINUE to be accepted by the server until `exp`
 * has elapsed.
 *
 * NOTE FOR EXAMINERS:
 * This limitation is an inherent consequence of pure *statelessness*, not an
 * unavoidable flaw of the JWT standard itself. A JWT system *can* support
 * revocation if the server adds a stateful denylist, token versioning in a
 * database, or sender-constrained keys (DPoP / mTLS). That server-side state,
 * however, removes the claimed "stateless" advantage.
 */

// A local development secret (minimum 256 bits for HS256).
// Scoped strictly to this demonstration; never used in production.
const JWT_DEV_SECRET = new TextEncoder().encode(
  'secureshop-stateless-jwt-secret-key-32bytes-min-for-viva-demo!',
);

export const JWT_ISSUER = 'https://secureshop.example.com';
export const JWT_AUDIENCE = 'secureshop-api';

export interface StatelessJwtPayload extends JWTPayload {
  readonly sub: string;
  readonly email: string;
  readonly name: string;
  readonly role: string;
}

/** Issues a signed stateless JWT valid for 5 minutes. */
export async function issueStatelessJwt(user: DemoUser): Promise<{
  token: string;
  expiresInSeconds: number;
}> {
  const token = await new SignJWT({
    email: user.email,
    name: user.name,
    role: user.role,
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setSubject(user.id)
    .setIssuer(JWT_ISSUER)
    .setAudience(JWT_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(JWT_DEV_SECRET);

  return { token, expiresInSeconds: 300 };
}

/** Verifies the JWT signature and expiration only — NO database lookup. */
export async function verifyStatelessJwt(token: string): Promise<StatelessJwtPayload> {
  const { payload } = await jwtVerify(token, JWT_DEV_SECRET, {
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
  });

  return payload as StatelessJwtPayload;
}
