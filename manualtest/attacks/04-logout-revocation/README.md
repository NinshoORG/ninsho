# Attack 04: Logout & Revocation Cascade

## Objective
Demonstrate that calling `POST /auth/logout-all` invalidates all active sessions for the user across multiple clients/devices simultaneously.

## Target
- Service: `express-api` (`http://localhost:3000`)
- Endpoints:
  - `POST /auth/login`
  - `POST /auth/logout-all`
  - `GET /me`

## Manual Procedure (curl)

1. Register user:
   ```bash
   curl -s -X POST http://localhost:3000/auth/register \
     -H "Content-Type: application/json" \
     -d '{"email":"multi-device@example.com","password":"Password123456!"}'
   ```
2. Login twice to simulate two devices (Device A and Device B):
   ```bash
   curl -s -X POST http://localhost:3000/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"multi-device@example.com","password":"Password123456!"}'
   ```
3. From Device A, call global logout:
   ```bash
   curl -i -s -X POST http://localhost:3000/auth/logout-all \
     -H "Authorization: Bearer <TOKEN_A>"
   ```
4. Verify Device B token is also invalidated on `/me`:
   ```bash
   curl -i -s -H "Authorization: Bearer <TOKEN_B>" http://localhost:3000/me
   ```

## Automated Script Execution
```bash
node --experimental-strip-types manualtest/attacks/04-logout-revocation/attack.ts
```
