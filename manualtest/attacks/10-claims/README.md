# Attack 10: Claims & Step-Up Authentication

## Objective
Demonstrate that sensitive operations requiring fresh authentication (`requireFreshAuth`) refuse stale sessions even if the session has been actively refreshed, defending against session hijacking and unattended workstation attacks.

## Target
- Service: `playground` (`http://localhost:4000`)
- Endpoint: `POST /api/authz/step-up`
- Guards: `auth.verify()`, `auth.requireFreshAuth(seconds)`

## Manual Procedure (curl)

1. Execute the step-up verification suite:
   ```bash
   curl -i -s -X POST http://localhost:4000/api/authz/step-up
   ```
2. Verify in the response that:
   - Initial call within window is allowed (HTTP 200).
   - Subsequent call after the freshness window is refused (HTTP 403).
   - Refreshing the session does NOT grant fresh authentication.

## Automated Script Execution
```bash
node --experimental-strip-types manualtest/attacks/10-claims/attack.ts
```
