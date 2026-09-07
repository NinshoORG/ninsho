# Attack 06: Cross-User Access (BOLA / IDOR)

## Objective
Demonstrate that changing the `:id` parameter in a URL route (`/users/:id/orders`) to target another user's resources is refused with `403 Forbidden`, enforcing object-level authorization via `requireOwner`.

## Target
- Service: `express-api` (`http://localhost:3000`)
- Endpoint: `GET /users/:id/orders`
- Guard: `auth.requireOwner((req) => req.params?.['id'])`

## Manual Procedure (curl)

1. Register User Alice:
   ```bash
   curl -s -X POST http://localhost:3000/auth/register \
     -H "Content-Type: application/json" \
     -d '{"email":"alice@example.com","password":"AlicePassword123!"}'
   # Save Alice's id (e.g. usr_1) and accessToken
   ```
2. Register User Bob:
   ```bash
   curl -s -X POST http://localhost:3000/auth/register \
     -H "Content-Type: application/json" \
     -d '{"email":"bob@example.com","password":"BobPassword123!"}'
   # Save Bob's id (e.g. usr_2)
   ```
3. Alice attempts to fetch Bob's orders:
   ```bash
   curl -i -s -H "Authorization: Bearer <ALICE_TOKEN>" http://localhost:3000/users/<BOB_ID>/orders
   ```
4. Observe HTTP 403 Forbidden.

## Automated Script Execution
```bash
node --experimental-strip-types manualtest/attacks/06-cross-user-access/attack.ts
```
