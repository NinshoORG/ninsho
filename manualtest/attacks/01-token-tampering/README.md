# Attack 01: Token Tampering

## Objective
Demonstrate that modifying or bit-flipping characters in an access token prevents authentication on protected routes (`/me`), returning `401 Unauthorized` without crashing or leaking store keys.

## Target
- Service: `express-api` (`http://localhost:3000`)
- Endpoint: `GET /me`
- Guard: `auth.verify()`

## Manual Procedure (curl)

1. Register or login to obtain an access token:
   ```bash
   curl -s -X POST http://localhost:3000/auth/register \
     -H "Content-Type: application/json" \
     -d '{"email":"tamper-test@example.com","password":"Password12345!"}'
   ```
2. Call `/me` with the valid token:
   ```bash
   curl -i -s -H "Authorization: Bearer <TOKEN>" http://localhost:3000/me
   ```
3. Alter the token (flip characters or change prefix):
   ```bash
   curl -i -s -H "Authorization: Bearer <TAMPERED_TOKEN>" http://localhost:3000/me
   ```

## Automated Script Execution
```bash
node --experimental-strip-types manualtest/attacks/01-token-tampering/attack.ts
```
