# Attack 09: DPoP Proof-of-Possession Attacks

## Objective
Demonstrate that a DPoP-bound access token cannot be used without a valid DPoP proof of possession, and that captured DPoP proofs cannot be replayed (`jti` replay guard).

## Target
- Service: `playground` (`http://localhost:4000`)
- Endpoints:
  - `POST /api/dpop/bind`
  - `POST /api/dpop/call`

## Manual Procedure (curl)

1. Bind a session to a mock thumbprint:
   ```bash
   curl -i -s -X POST http://localhost:4000/api/dpop/bind \
     -H "Content-Type: application/json" \
     -d '{"thumbprint":"test-thumbprint-123456"}'
   ```
2. Attempt calling the protected route omitting the proof (`omitProof: true`):
   ```bash
   curl -i -s -X POST http://localhost:4000/api/dpop/call \
     -H "Content-Type: application/json" \
     -d '{"thumbprint":"test-thumbprint-123456","omitProof":true}'
   ```
3. Observe rejection (`accepted: false`).

## Automated Script Execution
```bash
node --experimental-strip-types manualtest/attacks/09-dpop/attack.ts
```
