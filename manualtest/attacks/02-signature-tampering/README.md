# Attack 02: Algorithm Confusion & Signature Tampering

## Objective
Demonstrate that presenting an asymmetric PASETO token format (`v4.public...`) or a tampered signature to an opaque-configured endpoint (`/api/session/verify` on playground, or `/me` on express-api) does not trigger parser confusion or algorithm downgrade, and is strictly rejected as `TOKEN_INVALID`.

## Target
- Service: `playground` (`http://localhost:4000`)
- Endpoint: `POST /api/session/verify`

## Background
Ninsho fixes token strategies at construction (`strategy: 'opaque'` or `strategy: 'paseto'`). A deployment configured for opaque tokens cannot be tricked into accepting a signed token minted with an attacker's key, because there is no header sniffing or runtime algorithm negotiation.

## Manual Procedure (curl)

1. Send a synthetic token with a fake Ed25519 signature:
   ```bash
   curl -i -s -X POST http://localhost:4000/api/session/verify \
     -H "Content-Type: application/json" \
     -d '{"token":"v4.public.eyJzdWIiOiIxMjM0In0_bad_signature_here"}'
   ```
2. Send a truncated token:
   ```bash
   curl -i -s -X POST http://localhost:4000/api/session/verify \
     -H "Content-Type: application/json" \
     -d '{"token":"v4.public.dGVzdA"}'
   ```
3. Observe `ok: false` and `code: "TOKEN_INVALID"`.

## Automated Script Execution
```bash
node --experimental-strip-types manualtest/attacks/02-signature-tampering/attack.ts
```
