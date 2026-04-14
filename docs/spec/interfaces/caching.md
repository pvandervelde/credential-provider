# CachingCredentialProvider

**Architectural layer:** Business logic (`credential-provider-core`)
**Source file:** `credential-provider-core/src/caching.rs`
**ADRs:** [ADR-003](../../adr/ADR-003-stale-fallback-on-refresh-failure.md)

`CachingCredentialProvider<C, P>` wraps any `CredentialProvider<C>` and adds
transparent credential caching with automatic refresh. This is the component
consumers interact with — they call `get()` on it exactly as they would on a
raw provider.

---

## Struct Definition

```rust
pub struct CachingCredentialProvider<C, P>
where
    C: Credential,
    P: CredentialProvider<C>,
{
    inner: P,
    cached: RwLock<Option<C>>,
    refresh_before_expiry: Duration,
    refresh_lock: Mutex<()>,
}
```

### Fields

| Field | Type | Purpose |
|---|---|---|
| `inner` | `P` | The wrapped provider; called on cache miss or refresh |
| `cached` | `RwLock<Option<C>>` | The cached credential; `None` until first fetch |
| `refresh_before_expiry` | `Duration` | How early to begin proactive renewal |
| `refresh_lock` | `Mutex<()>` | Serializes concurrent refresh operations |

---

## Constructor: `new()`

```rust
pub fn new(inner: P, refresh_before_expiry: Duration) -> Self
```

### Parameters

- `inner` — the raw provider that performs live credential fetches
- `refresh_before_expiry` — how long before expiry to trigger proactive renewal.
  A value of `Duration::from_secs(60)` means renewal starts when the cached
  credential has less than 60 seconds of remaining validity.

The cache starts empty. The first call to `get()` always performs a live fetch.

### Example

```rust
use std::time::Duration;
use credential_provider_core::CachingCredentialProvider;

let caching = CachingCredentialProvider::new(raw_provider, Duration::from_secs(60));
```

---

## Method: `get()`

```rust
pub async fn get(&self) -> Result<C, CredentialError>
```

### Caching State Machine

`get()` evaluates the cache state and applies exactly one of the following rules,
in order:

#### Rule 1 — Empty cache (no cached credential)

- **Condition:** `cached` is `None`
- **Action:** Acquire `refresh_lock`, fetch from `inner.get()`, release lock
  - On success: store result in `cached`, return it
  - On failure: return `CredentialError::Unavailable`

#### Rule 2 — Valid, outside refresh window

- **Condition:** `cached` is `Some(c)` AND `c.is_valid() == true` AND
  `c.expires_at()` is either `None` or more than `refresh_before_expiry` in the future
- **Action:** Return the cached value without any fetch
- **Inner provider:** NOT called

This is the hot path. No locking beyond the `RwLock` read guard.

#### Rule 3 — Valid, inside refresh window → refresh succeeds

- **Condition:** `cached` is `Some(c)` AND `c.is_valid() == true` AND
  `c.expires_at()` is within `refresh_before_expiry` of now
- **Action:** Acquire `refresh_lock`, fetch from `inner.get()`, release lock
  - On success: update `cached` with the new credential, return it

#### Rule 4 — Valid, inside refresh window → refresh fails (stale fallback)

- **Condition:** Same as Rule 3, but `inner.get()` returns `Err`
- **Action:** Return the still-valid stale cached credential
- The error from the inner provider is **discarded** (but should be logged at `warn`)
- **Applies only when** `c.is_valid() == true` at the time the fallback decision is made

See [ADR-003] for the rationale.

#### Rule 5 — Expired cache → refresh fails

- **Condition:** `cached` is `Some(c)` AND `c.is_valid() == false`
- **Action:** Acquire `refresh_lock`, fetch from `inner.get()`, release lock
  - On success: update `cached`, return new credential
  - On failure: propagate the `CredentialError` (no stale fallback for expired credentials)

#### Rule 6 — No-expiry credential (HmacSecret)

- **Condition:** `cached` is `Some(c)` AND `c.expires_at() == None`
- **Action:** Rule 2 applies — return cached value, never refresh
- `inner.get()` is called only once (on the first fetch); all subsequent calls
  return the cached value without fetching

#### Important: stale check uses current time

The `is_valid()` check in Rule 4 must be evaluated **at the moment the fallback
decision is made** (after the failed fetch), not at the moment the cached
credential was stored. A credential that was valid when cached may have expired
while a fetch was in progress.

---

## Concurrency: Refresh Serialization

When multiple tasks call `get()` simultaneously and a refresh is needed:

1. The first task to observe a needs-refresh state acquires `refresh_lock`
2. It performs the fetch from `inner.get()`
3. On completion it updates `cached` (under the `RwLock` write guard) and releases `refresh_lock`
4. All other tasks waiting on `refresh_lock` acquire it in sequence
5. Each subsequent task reads the updated `cached` value via the `RwLock` read guard
   and returns it — without triggering another fetch

This prevents a thundering herd against the backend when many tasks observe a
stale or empty cache simultaneously. Only **one** fetch is dispatched per
refresh cycle.

### Re-check after acquiring refresh_lock

After acquiring `refresh_lock`, an implementation must re-check whether the
cache still needs refreshing (another task may have refreshed it while this task
was waiting). This avoids duplicate fetches.

---

## Observability Requirements

Implementations must emit:

- `warn!` log when returning a stale fallback credential
- A counter `credential_cache_stale_fallbacks_total` incremented on each stale fallback
- Optionally: `debug!` log on cache hit, `info!` log on successful refresh

---

## Usage Example

```rust
use std::{sync::Arc, time::Duration};
use credential_provider_core::{CachingCredentialProvider, CredentialProvider, UsernamePassword};

// raw_provider: impl CredentialProvider<UsernamePassword>
let provider = Arc::new(CachingCredentialProvider::new(
    raw_provider,
    Duration::from_secs(60),
));

// Consumer calls get() — caching is transparent
let creds: UsernamePassword = provider.get().await?;
```
