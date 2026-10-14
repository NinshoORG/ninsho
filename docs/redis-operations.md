# Redis operations: persistence, recovery, and strategy guarantees

Ninsho relies on a centralized store for sessions, single-use counters,
rate-limiting buckets, DPoP replay guards, and token state. In production, this
is `RedisStore` backed by Redis 6.2+.

This document records the verified operational behavior of Redis persistence,
restart recovery, outage handling, and data loss across Ninsho's two token
strategies (`opaque` and `paseto`). All guarantees and failure modes described
here are demonstrated by reproducible tests in
`packages/server/src/__tests__/redis-persistence.test.ts`.

---

## Executive summary of strategy guarantees

| Scenario | `strategy: 'opaque'` (Default) | `strategy: 'paseto'` |
|---|---|---|
| **Graceful restart (RDB / AOF)** | All sessions and revocation state preserved. | All sessions and revocation denylist preserved. |
| **Temporary Redis outage (`onStoreError: 'closed'`)** | **Fails closed (HTTP 503).** All verifications reject with `StoreUnavailableError`. Recovers cleanly when Redis returns. | **Fails closed (HTTP 503).** Signature checks locally, but denylist lookup fails closed with `StoreUnavailableError`. Recovers when Redis returns. |
| **Temporary Redis outage (`onStoreError: 'open'`)** | **Disallowed.** Refuses configuration at startup (`ConfigurationError`) because the store *is* the token. | **Fails open on revocation (HTTP 200).** Valid signatures accepted without denylist check; **revoked tokens work during outage**. Emits `config.insecure` audit event. |
| **Complete data loss (Empty restart / unpersisted)** | **Fails closed (HTTP 401).** All tokens become unknown (`TokenInvalidError`); all refresh tokens fail. Users must re-authenticate. | **Fails open on revocation.** Active unrevoked tokens continue working; **previously revoked tokens become usable again** until `exp`. |
| **Snapshot rollback (Older RDB restore)** | Active sessions restored to snapshot state. Tokens created after snapshot fail closed. | Tokens revoked after the snapshot are **resurrected** because their denylist entries do not exist in the snapshot. |

---

## Test suite and demonstrated scenarios

The test suite in `packages/server/src/__tests__/redis-persistence.test.ts`
manages isolated `redis:7-alpine` Docker containers on ephemeral ports with
temporary volume directories to verify exact persistence lifecycle transitions.

### Scenario 1: Graceful restart with RDB persistence
- **Mechanism:** Redis container started with `--save 1 1 --dir /data --dbfilename dump.rdb`.
  Sessions and tokens are minted and verified. One token is revoked. Redis is
  stopped via `redis-cli SHUTDOWN SAVE` (ensuring point-in-time snapshot flush)
  and restarted using the same data directory.
- **Result:**
  - Opaque: Active session access token verifies cleanly; revoked session remains
    rejected (`TokenInvalidError`). Refresh rotation operates normally.
  - PASETO: Active access token verifies; revoked token remains rejected by the
    restored denylist (`TokenRevokedError`).
- **Evidence:** `redis-persistence.test.ts` › *preserves active opaque sessions and their revocation state across a graceful restart*, *preserves PASETO sessions and revocation denylist entries across a graceful restart*.

### Scenario 2: Temporary Redis outage and recovery
- **Mechanism:** Redis instance stopped during active token verification;
  requests attempted while unreachable; Redis instance brought back online.
- **Result:**
  - Under `onStoreError: 'closed'` (default), all verification attempts during the
    outage reject (`StoreUnavailableError` / 503).
  - `enableOfflineQueue: false` in `RedisStore` ensures requests do not stall or
    queue unboundedly during the outage.
  - Upon Redis container restart, fresh or reconnected clients resume normal
    verification and session retrieval without manual intervention.
- **Evidence:** `redis-persistence.test.ts` › *opaque engine fails closed during outage and recovers when Redis returns*, *PASETO engine fails closed during outage when onStoreError is closed*.

### Scenario 3: Complete data loss (restarting without persistence data)
- **Mechanism:** Active and revoked tokens established. Redis is abruptly stopped
  (`docker kill`) and restarted with a fresh, empty data directory.
- **Result:**
  - **Opaque:** Fails closed. The token is an opaque lookup key whose record lived
    in Redis. With Redis empty, every token lookup fails (`TokenInvalidError`).
    Refresh attempts fail. No unauthorized or revoked session is admitted.
  - **PASETO:** Fails open on revocation. Tokens carry an Ed25519 signature
    verifiable with in-memory keys. Active tokens continue to verify. However,
    the revocation denylist was stored in Redis and is now completely lost.
    **Previously revoked tokens verify again as valid** until their natural expiry
    (`exp`). The test asserts this dangerous outcome explicitly.
- **Evidence:** `redis-persistence.test.ts` › *opaque: all sessions fail closed — the store IS the token, and without it nothing verifies*, *PASETO: previously revoked tokens become usable again — a documented, unresolved limitation*.

### Scenario 4: Snapshot rollback
- **Mechanism:** Two sessions created (A and B). An RDB snapshot is forced via
  `BGSAVE` and copied. Session B is revoked. Redis is stopped and restarted
  pointing to the earlier snapshot directory.
- **Result:**
  - Session A continues to verify.
  - Session B, which was revoked *after* the snapshot, is resurrected: the
    restored database has no record of its revocation, so `PasetoEngine` admits
    it.
- **Evidence:** `redis-persistence.test.ts` › *restoring an older RDB snapshot discards revocations that occurred after it, resurrecting PASETO tokens*.

---

## Operational guidance and trade-offs

### 1. Choosing between `opaque` and `paseto`
- Use **`strategy: 'opaque'`** whenever a single logical database or cluster can
  be accessed by API services. It is strictly safer under data loss or operational
  mishaps: when in doubt, it fails closed (all users are logged out, but no
  revoked token is admitted).
- Use **`strategy: 'paseto'`** only when multi-service verification without
  database round-trips is a mandatory architectural requirement. When using
  PASETO, operators **must** configure continuous persistence (AOF) if
  revocations must survive process restarts and crashes.

### 2. Redis persistence configuration
- **RDB (Snapshotting):** Point-in-time dumps (e.g. `save 60 1000`). RDB
  guarantees graceful shutdown persistence (`SHUTDOWN SAVE`), but any crash
  between snapshots loses all writes (including revocations) since the last dump.
- **AOF (Append Only File):** Recommended for PASETO deployments.
  - `appendonly yes`
  - `appendfsync everysec`: Maximum 1 second of revocations lost on unexpected
    power loss or kernel crash.
  - `appendfsync always`: Maximum durability at the expense of write throughput.

### 3. Fail-open (`onStoreError: 'open'`)
- Allowed **only** under `paseto`.
- Emits a `config.insecure` audit event on process startup.
- During an outage, token signatures are verified, but the revocation denylist
  is skipped. Every revoked token remains accepted until its `exp` elapses.
- Must only be chosen when API availability during store degradation strictly
  outweighs revocation security.

---

## Residual limits

The tests prove behavior under Docker-managed lifecycle events. The following
remain operational considerations outside the automated test scope:
1. **Abrupt host power loss / unbuffered writes:** If Redis is terminated with
   un-synced dirty pages (`kill -9`, power loss) and AOF `appendfsync always` is
   not active, writes since the last sync will be lost.
2. **Replication lag and failover:** In a Redis Sentinel or Redis Cluster
   topology, asynchronous replication to replicas means a failover after primary
   death may lose recent revocations (split-brain or replication lag window).
3. **Clock synchronization:** Expiry of access and refresh tokens depends on
   NTP synchronization between application servers and Redis. Ninsho provides
   `clockToleranceSeconds` (default 5s) to absorb minor skew.
