# Attack 05: Refresh Token Replay & Reuse Detection

## Objective
Demonstrate that presenting an already-spent refresh token is detected by Ninsho as token theft, returning `401 Unauthorized` and automatically revoking the entire session family.

## Target
- Service: `express-api` (`http://localhost:3000`)
- Endpoint: `POST /auth/refresh`

## Manual Procedure (curl)

1. Login and save the refresh cookie:
   ```bash
   curl -s -c cookies.txt -X POST http://localhost:3000/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"reuse-test@example.com","password":"Password12345!"}'
   ```
2. Copy the refresh cookie value (`RT1`).
3. Perform a legitimate refresh using `RT1`:
   ```bash
   curl -i -s -b cookies.txt -c cookies2.txt -X POST http://localhost:3000/auth/refresh
   ```
4. Replay `RT1`:
   ```bash
   curl -i -s -b cookies.txt -X POST http://localhost:3000/auth/refresh
   ```
5. Attempt refresh with `RT2` (from cookies2.txt):
   ```bash
   curl -i -s -b cookies2.txt -X POST http://localhost:3000/auth/refresh
   ```

## Automated Script Execution
```bash
node --experimental-strip-types manualtest/attacks/05-refresh-replay/attack.ts
```
