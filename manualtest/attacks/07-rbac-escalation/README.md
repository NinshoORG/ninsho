# Attack 07: RBAC Privilege Escalation

## Objective
Demonstrate that a standard authenticated user cannot access administrative routes protected by `auth.requireRole('admin')`, returning `403 Forbidden` and distinguishing clearly from anonymous calls (`401 Unauthorized`).

## Target
- Service: `express-api` (`http://localhost:3000`)
- Endpoint: `GET /admin/reports`
- Guards: `auth.verify()`, `auth.requireRole('admin')`

## Manual Procedure (curl)

1. Register or login as standard user:
   ```bash
   curl -s -X POST http://localhost:3000/auth/register \
     -H "Content-Type: application/json" \
     -d '{"email":"standard-user@example.com","password":"Password12345!"}'
   ```
2. Attempt to call admin reports with standard token:
   ```bash
   curl -i -s -H "Authorization: Bearer <STANDARD_TOKEN>" http://localhost:3000/admin/reports
   ```
3. Attempt to call admin reports without any token (anonymous):
   ```bash
   curl -i -s http://localhost:3000/admin/reports
   ```

## Automated Script Execution
```bash
node --experimental-strip-types manualtest/attacks/07-rbac-escalation/attack.ts
```
