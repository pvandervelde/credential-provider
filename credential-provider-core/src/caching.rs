// SPEC: docs/spec/interfaces/caching.md

use std::time::{Duration, Instant};

use tokio::sync::{Mutex, RwLock};
use tracing::warn;

use crate::{BoxFuture, Credential, CredentialError, CredentialProvider};

/// Returns `true` when the credential will expire within `refresh_before_expiry`.
///
/// A credential with no expiry (`None`) is never inside the refresh window.
/// The comparison uses `<=` so that the at-boundary case is treated as inside
/// the window (see E-CACHE-2).
fn is_inside_refresh_window(expires_at: Option<Instant>, refresh_before_expiry: Duration) -> bool {
    match expires_at {
        None => false,
        Some(exp) => {
            let remaining = exp.saturating_duration_since(Instant::now());
            remaining <= refresh_before_expiry
        }
    }
}

/// A caching wrapper around any [`CredentialProvider<C>`].
///
/// `CachingCredentialProvider` sits between consumers and a raw provider,
/// holding a cached credential and transparently refreshing it before expiry.
/// Consumers interact with this wrapper exclusively — they call `get()` on it
/// exactly as they would on the raw provider, and the caching lifecycle is
/// entirely internal.
///
/// # Caching Policy
///
/// Each call to `get()` applies the following rules in order:
///
/// 1. **Empty cache** — fetch immediately from the inner provider, cache the
///    result, and return it.
/// 2. **Valid cache, outside refresh window** — the cached credential has
///    `is_valid() == true` and its expiry is more than `refresh_before_expiry`
///    in the future. Return the cached value directly without fetching.
/// 3. **Valid cache, inside refresh window** — the cached credential has
///    `is_valid() == true` but will expire within `refresh_before_expiry`.
///    Fetch fresh credentials.
///    - On success: cache the new credential and return it.
///    - On failure: return the still-valid stale cached credential (stale
///      fallback). See ADR-003 (`docs/adr/ADR-003-stale-fallback-on-refresh-failure.md`).
/// 4. **Expired cache** — the cached credential has `is_valid() == false`.
///    Fetch fresh credentials.
///    - On success: cache the new credential and return it.
///    - On failure: propagate the [`CredentialError`] (no stale fallback for
///      expired credentials).
/// 5. **No-expiry credential** — a cached credential where `expires_at()`
///    returns `None` is always considered valid and outside the refresh window.
///    The inner provider is called only once (the initial fetch).
///
/// # Concurrent Refresh Serialization
///
/// When multiple tasks call `get()` concurrently and a refresh is needed, only
/// one fetch is dispatched to the inner provider. All other callers wait on the
/// refresh lock and then read the updated cache. This prevents a thundering
/// herd against the backend.
///
/// # Construction
///
/// ```rust,ignore
/// use std::time::Duration;
/// use credential_provider_core::{CachingCredentialProvider, UsernamePassword};
///
/// // raw_provider implements CredentialProvider<UsernamePassword>
/// let caching = CachingCredentialProvider::new(raw_provider, Duration::from_secs(60));
/// let creds = caching.get().await?;
/// ```
///
/// See: docs/spec/interfaces/caching.md
pub struct CachingCredentialProvider<C, P>
where
    C: Credential,
    P: CredentialProvider<C>,
{
    /// The wrapped raw provider. Called when a cache miss or refresh is needed.
    inner: P,

    /// The currently cached credential, if any.
    ///
    /// Uses `RwLock` to allow concurrent reads without blocking when the cache
    /// is valid. Writes (cache updates) are serialized via `refresh_lock`.
    cached: RwLock<Option<C>>,

    /// How early to begin proactive renewal before the credential expires.
    ///
    /// A value of `Duration::from_secs(60)` means renewal is triggered when
    /// the cached credential has less than 60 seconds of remaining validity.
    refresh_before_expiry: Duration,

    /// Guards the refresh operation so that only one fetch is in flight at a
    /// time. When multiple tasks observe a stale or empty cache concurrently,
    /// the first acquires this mutex and performs the fetch; all others block
    /// until the mutex is released, then read the updated cache.
    refresh_lock: Mutex<()>,
}

impl<C, P> CachingCredentialProvider<C, P>
where
    C: Credential,
    P: CredentialProvider<C>,
{
    /// Create a new `CachingCredentialProvider`.
    ///
    /// # Parameters
    ///
    /// - `inner` — the raw provider that performs live credential fetches.
    /// - `refresh_before_expiry` — how long before credential expiry to begin
    ///   proactive renewal. Must be a positive duration. A value of
    ///   `Duration::from_secs(60)` is recommended as a sensible default.
    ///
    /// The cache starts empty. The first call to `get()` will always perform
    /// a live fetch.
    pub fn new(inner: P, refresh_before_expiry: Duration) -> Self {
        Self {
            inner,
            cached: RwLock::new(None),
            refresh_before_expiry,
            refresh_lock: Mutex::new(()),
        }
    }

}

impl<C, P> CredentialProvider<C> for CachingCredentialProvider<C, P>
where
    C: Credential,
    P: CredentialProvider<C>,
{
    /// Returns cached credentials if still valid and outside the refresh
    /// window; otherwise fetches fresh credentials from the inner provider
    /// and updates the cache.
    ///
    /// See the struct-level documentation for the full caching policy.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::Unavailable`] when the cache is empty and
    /// the inner provider fetch fails, or propagates the inner provider error
    /// when the cached credential has expired and the fetch fails.
    fn get(&self) -> BoxFuture<'_, Result<C, CredentialError>> {
        Box::pin(async move {
            // Step 1: snapshot the cache without holding the guard across an await.
            let cached_snapshot = {
                let read_guard = self.cached.read().await;
                read_guard.clone()
            };

            // Rule 2 / Rule 6 — hot path: valid credential outside refresh window.
            // No locking needed; just return the cached value immediately.
            if let Some(ref c) = cached_snapshot {
                if c.is_valid()
                    && !is_inside_refresh_window(c.expires_at(), self.refresh_before_expiry)
                {
                    return Ok(c.clone());
                }
            }

            // Rules 1, 3, 4, 5 all require a fetch.  Serialize concurrent fetches
            // so only one task calls the inner provider at a time.
            let _refresh_guard = self.refresh_lock.lock().await;

            // Re-read the cache: another task may have refreshed while we waited.
            let recheck = {
                let read_guard = self.cached.read().await;
                read_guard.clone()
            };

            // If the re-check is now valid and outside the refresh window, return it
            // (covers the thundering-herd case for all rules).
            if let Some(ref c) = recheck {
                if c.is_valid()
                    && !is_inside_refresh_window(c.expires_at(), self.refresh_before_expiry)
                {
                    return Ok(c.clone());
                }
            }

            // Classify the original snapshot to choose the right error-handling path
            // after a failed fetch.
            let cache_was_empty = cached_snapshot.is_none();
            let cached_was_valid = cached_snapshot.as_ref().map_or(false, |c| c.is_valid());

            // Fetch fresh credentials from the inner provider.
            match self.inner.get().await {
                Ok(new_cred) => {
                    {
                        let mut write_guard = self.cached.write().await;
                        *write_guard = Some(new_cred.clone());
                    }
                    Ok(new_cred)
                }
                Err(e) => {
                    if cache_was_empty {
                        // Rule 1: empty cache + failed fetch → always Unavailable.
                        Err(CredentialError::Unavailable)
                    } else if cached_was_valid {
                        // Rule 3/4: was valid (inside window) + failed fetch.
                        // Re-check validity RIGHT NOW — time passed during the fetch.
                        let stale = cached_snapshot.unwrap();
                        if stale.is_valid() {
                            warn!(
                                error = %e,
                                "stale credential fallback: refresh failed while cache is still valid"
                            );
                            Ok(stale)
                        } else {
                            // Expired during the fetch; fall through to Rule 5 behaviour.
                            Err(e)
                        }
                    } else {
                        // Rule 5: expired + failed fetch → propagate the actual error.
                        Err(e)
                    }
                }
            }
        })
    }
}

#[cfg(test)]
#[path = "caching_tests.rs"]
mod tests;
