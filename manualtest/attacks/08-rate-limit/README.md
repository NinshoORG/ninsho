# Attack 08: Rate Limiting & Proxy Spoofing

## Objective
Demonstrate that brute-force password guessing against an account triggers HTTP `429 Too Many Requests` after the configured threshold (5 attempts per 15 minutes) and cannot be bypassed by spoofing `X-Forwarded-For`.

## Target
- Service: `express-api` (`http://localhost:3000`)
- Endpoint: `POST /auth/login`
- Limits: `perAccount: { limit: 5, windowMs: 15 * 60 * 1000 }`, `perIp: { limit: 20 }`

## Manual Procedure (curl)

1. Pick a target email: `victim-ratelimit@example.com`.
2. Send 6 failed login attempts:
   ```bash
   for i in {1..6}; do
     curl -i -s -X POST http://localhost:3000/auth/login \
       -H "Content-Type: application/json" \
       -d '{"email":"victim-ratelimit@example.com","password":"BadPassword123!"}'
   done
   ```
3. Observe attempts 1 to 5 return 401, and attempt 6 returns 429.

## Automated Script Execution
```bash
node --experimental-strip-types manualtest/attacks/08-rate-limit/attack.ts
```
