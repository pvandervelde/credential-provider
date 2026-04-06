# ADR-003: Stale Fallback on Credential Refresh Failure

Status: Accepted
Date: 2026-04-01
Owners: credential-provider team

## Context

`CachingCredentialProvider` holds a cached credential and refreshes it before expiry. The question is what happens when a refresh attempt fails (backend timeout, HTTP 500, transient network issue) while the cached credential is still technically valid (not yet past its `expires_at`).

Services running against external secrets backends will experience transient outages — backend restarts for upgrades, network blips, brief unavailability during failovers. During these windows (typically 5–30 seconds), credential fetches fail. Services should not hard-fail if they already hold valid credentials.

## Decision

When a credential refresh fails and the cache holds a credential where `is_valid()` returns `true`, **return the stale cached credential** instead of propagating the error.

Specifically:

- If the cache is **empty** and the fetch fails → propagate the error (`CredentialError`)
- If the cached credential has **expired** (`is_valid() = false`) and the fetch fails → propagate the error
- If the cached credential is **still valid** and the fetch fails → return the cached credential

Do **not** propagate refresh errors when a valid cached credential exists.

## Consequences

**Enables:**

- Resilience against transient backend outages (secrets manager restarts, network blips, failovers)
- Services continue operating with valid credentials during short outage windows
- No cascading failures from a momentary backend unavailability

**Forbids:**

- Guaranteeing that returned credentials are always "freshly fetched"
- Detecting refresh failures at the consumer level when a cached value is available (the consumer sees success)

**Trade-offs:**

- During the stale window, credentials are closer to expiry, increasing the risk that they expire during a long-running operation
- If the backend has revoked a credential (not expired, but actively revoked), the stale cache will return it until it naturally expires — the revocation won't be detected until the credential is rejected by the target service
- Operational visibility requires observability at the caching layer (stale fallback counter) since consumers don't see the failure

## Alternatives considered

### Option A: Strict freshness — always propagate refresh errors

**Why not:** A 5-second backend restart would cause all services to fail simultaneously, even though they hold credentials with minutes or hours of remaining validity. This converts a minor operational event into a platform-wide outage.

### Option B: Background refresh with independent timer

**Why not:** Adds complexity (background task management, cancellation, lifecycle ownership). The lazy refresh-on-access approach is simpler and achieves the same resilience. A background approach may be considered in a future version if access patterns warrant it.

### Option C: Configurable fallback behavior (let consumer choose)

**Why not:** Adds API complexity for a rare need. Consumers who truly need strict freshness can set `refresh_before_expiry` equal to the credential's full lifetime, which disables meaningful caching but ensures every call fetches fresh.

## Implementation notes

- The stale fallback check must evaluate `is_valid()` on the cached credential **at the time of the fallback decision**, not at the time it was cached. A credential that was valid when cached may have expired by the time the refresh fails.
- The fallback should be logged at `warn` level so operators can detect prolonged backend outages.
- A metric `credential_cache_stale_fallbacks_total` should be incremented each time a stale fallback occurs.
- The fallback window is bounded: it can never exceed the credential's natural `expires_at`. Once the credential expires, the error propagates.

## Examples

**Normal refresh (no fallback):**

```
t=0s    cache populated, credential expires at t=3600s
t=3540s refresh window entered (60s before expiry)
t=3540s get() → refresh succeeds → new credential cached (expires t=7200s)
```

**Stale fallback in action:**

```
t=0s    cache populated, credential expires at t=3600s
t=3540s refresh window entered
t=3540s get() → refresh fails (backend restarting)
t=3540s fallback: cached credential is_valid()=true → return cached credential
t=3545s get() → refresh fails again → fallback again (still valid)
t=3550s get() → refresh succeeds (backend back) → new credential cached
```

**Fallback exhausted:**

```
t=3540s refresh window entered
t=3540s get() → refresh fails → fallback (cached credential still valid)
...backend stays down...
t=3600s get() → refresh fails → cached credential is_valid()=false → propagate error
```

## References

- [Tradeoffs: T-3](../spec/tradeoffs.md#t-3-stale-fallback-vs-strict-freshness)
- [Assertions: A-CACHE-4, A-CACHE-5](../spec/assertions.md#a-cache-4-credential-within-refresh-window-triggers-refresh--failure-with-stale-fallback)
- [Edge Cases: E-CACHE-1](../spec/edge-cases.md#e-cache-1-first-call-fails-empty-cache-backend-unreachable)
- [Security: S-5](../spec/security.md#s-5-stale-credential-after-backend-revocation)
