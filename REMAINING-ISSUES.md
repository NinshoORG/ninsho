# Ninsho — remaining issues and review status

The October 9 report described `c7e6539`. A subsequent review reproduced five
additional defects despite its passing tests. The implementation, regressions,
and verification commands are recorded in [review remediation](docs/review-remediation.md).
This document replaces the earlier blanket “all invariants verified” conclusion.

## Addressed in the follow-up change

1. Initial access-token issuance racing completed session revocation.
2. Wrong/missing DPoP-key replay revoking a consumed token's legitimate family.
3. Late refresh/sign-in completion restoring a logged-out client identity.
4. Transient refresh errors clearing client recovery state and the example cookie.
5. Concurrent key creation across independent IndexedDB connections.
6. Redis persistence, outage recovery, and data loss guarantees verified across opaque and PASETO strategies (`packages/server/src/__tests__/redis-persistence.test.ts`).

Each fix names its regression in the remediation document or operations guide. Local runs on Node 20, 22, and 24
with real Redis each passed 2,116 tests with no skips (plus 7 Docker persistence tests). Test counts are
configuration-specific; inspect CI for the exact commit and Node version.

## Corrections to the earlier report

- `revokeAllForUser` reads one session-index snapshot, not a loop that drains
  the index. It removes only successfully revoked entries. The existing test
  `does not wipe concurrently created sessions when logout-all races a new login`
  intentionally preserves sessions added after the snapshot.
- The Redis command-error tests are named `propagates Redis command errors from
  increment on conflicting key types rather than returning 0`, `fails closed
  when RateLimiter encounters a Redis command error during increment`, and
  `propagates Redis command errors from sAdd on conflicting key types rather
  than silently resolving`. The old report incorrectly listed an sRemove test.
- Test counts from earlier commits must not be presented as current measurements.
- Repository HEAD and the published npm package can differ. Pushing these fixes
  does not publish a package release.
- GitHub private vulnerability reporting requires an actual administrator setting;
  documenting setup steps does not verify that the setting is enabled.

## Remaining work and limitations

| Area | Remaining work |
|---|---|
| Independent assurance | External security review; no certification is claimed |
| Browser coverage | Chromium/Firefox/WebKit share key-store and cross-tab regression scenarios in a dedicated CI matrix; see [measured results and limits](docs/browser-regressions.md). Deployment-specific cookie ordering, suspended tabs and physical-device coverage remain open |
| Device coverage | Real TPM, Android, and hardware-authenticator interoperability matrix |
| Parser assurance | Continue and expand automated fuzzing of attacker-controlled structures |
| Operations | Redis persistence, graceful restart, and recovery verified across opaque and PASETO strategies with Docker-backed tests; see [measured results and limits](docs/redis-operations.md). AOF write-ahead durability, abrupt process crash (kill -9/power loss), and cluster/Sentinel failover remain deployment-specific |
| Account lifecycle | Applications coordinate password changes with concurrent new logins |
| Integration UX | Pilot with unfamiliar developers; measure completion time and configuration errors |
| Disclosure | Administrator verifies private reporting availability and response process |

Immediate-login registration still reveals account existence through its
outcome; applications requiring enumeration resistance should use an
email-verification flow. Hono's normalized headers do not preserve all raw
header ambiguity. Neither is newly introduced by this change; see SECURITY.md.

## Viva guidance

Demonstrate concrete controls and their regression tests, including a fixed
race that the earlier suite missed. State the threat model and limitations.
Do not describe passing tests as proof that all attacks are prevented or that
the project is production-certified.
