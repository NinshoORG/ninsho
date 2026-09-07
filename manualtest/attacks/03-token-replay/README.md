# Attack 03: Token Replay

## Objective
Demonstrate that an access token cannot be replayed after its corresponding session has been revoked via `POST /auth/logout`.

## Target
- Service: `express-api` (`http://localhost:3000`)
- Endpoints:
  - `POST /auth/logout`
  - `GET /me`

## Manual Procedure (curl)

1. Obtain a valid session:
   ```bash
   curl -s -X POST http://localhost:3000/auth/register \
     -H "Content-Type: application/json" \
     -d '{"email":"replay-test@example.com","password":"ValidPassword123!"}'
   ```
2. Verify `/me` responds with 200 OK:
   ```bash
   curl -i -s -H "Authorization: Bearer <TOKEN>" http://localhost:3000/me
   ```
3. Log out:
   ```bash
   curl -i -s -X POST http://localhost:3000/auth/logout \
     -H "Authorization: Bearer <TOKEN>"
   ```
4. Replay the same token against `/me`:
   ```bash
   curl -i -s -H "Authorization: Bearer <TOKEN>" http://localhost:3000/me
   ```

## Automated Script Execution
```bash
node --experimental-strip-types manualtest/attacks/03-token-replay/attack.ts
```
