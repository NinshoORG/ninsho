# Attack 11: Malformed Input & Denial of Service

## Objective
Demonstrate that oversized request payloads (>16 KB) are rejected early before expensive parsing, and malformed URI escapes in headers (e.g. `Cookie: ninsho_rt=%`) do not trigger unhandled process exceptions (HTTP 500 / crash).

## Target
- Service: `express-api` (`http://localhost:3000`)
- Endpoints:
  - `POST /auth/login`
  - `POST /auth/refresh`

## Manual Procedure (curl)

1. Send an oversized JSON body (>16 KB) to `/auth/login`:
   ```bash
   node -e "process.stdout.write(JSON.stringify({email:'a@example.com',password:'a'.repeat(32768)}))" | \
     curl -i -s -X POST http://localhost:3000/auth/login \
       -H "Content-Type: application/json" \
       --data-binary @-
   ```
2. Send a malformed URI escape in the refresh cookie:
   ```bash
   curl -i -s -X POST http://localhost:3000/auth/refresh \
     -H "Cookie: ninsho_rt=%"
   ```
3. Verify the server process remains healthy and running:
   ```bash
   curl -i -s http://localhost:3000/health
   ```

## Automated Script Execution
```bash
node --experimental-strip-types manualtest/attacks/11-malformed-input/attack.ts
```
