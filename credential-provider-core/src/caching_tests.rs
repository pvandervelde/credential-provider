//! Adversarial test suite for `CachingCredentialProvider::get()`.
//!
//! Coverage: A-CACHE-1 through A-CACHE-8, E-CACHE-1, E-CACHE-2.
//! All tests FAIL against the current `unimplemented!()` stub and PASS
//! once the correct implementation is in place.
//!
//! Time control: `std::time::Instant` is used directly for expiry because
//! `tokio::time::pause()` does not affect `std::time::Instant::now()`.
//! Expired credentials are constructed with `expires_at` set to a past
//! instant; near-expiry credentials use a short future duration that is
//! shorter than `REFRESH_WINDOW`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use secrecy::{ExposeSecret, SecretString, SecretVec};

use crate::mock::MockCredentialProvider;
use crate::{
    CachingCredentialProvider, CredentialError, CredentialProvider, HmacSecret, UsernamePassword,
};

// ── Helpers ──────────────────────────────────────────────────────────────

/// Build a `UsernamePassword` with a fixed password and the given expiry.
fn up(username: &str, expires_at: Option<Instant>) -> UsernamePassword {
    UsernamePassword::new(username, SecretString::new("pass".to_string()), expires_at)
}

/// A `UsernamePassword` that expires far in the future — outside any
/// reasonable refresh window.
fn valid_up(username: &str) -> UsernamePassword {
    up(username, Some(Instant::now() + Duration::from_secs(3600)))
}

/// A `UsernamePassword` expiring in 30 s: inside the 60-second
/// `REFRESH_WINDOW`.
fn refreshing_up(username: &str) -> UsernamePassword {
    up(username, Some(Instant::now() + Duration::from_secs(30)))
}

/// A `UsernamePassword` whose expiry is already in the past.
fn expired_up(username: &str) -> UsernamePassword {
    up(username, Some(Instant::now() - Duration::from_secs(5)))
}

/// Standard `refresh_before_expiry` used by all tests.
const REFRESH_WINDOW: Duration = Duration::from_secs(60);

// ── A-CACHE-1: Empty cache triggers fetch ─────────────────────────────────
// Assertions:
//   • inner.get() is called exactly once
//   • the result is returned to the caller
//   • the result is cached (second call does NOT call inner again)

#[tokio::test]
async fn empty_cache_calls_inner_and_returns_result() {
    let mock = MockCredentialProvider::returning_ok(valid_up("alice"));
    let caching = CachingCredentialProvider::new(mock, REFRESH_WINDOW);

    let result = caching.get().await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().username, "alice");
}

/// Stub-killer: if the result is not cached, the second call would hit the
/// `Err` response and fail.
#[tokio::test]
async fn empty_cache_result_is_cached_second_call_does_not_refetch() {
    let mock = MockCredentialProvider::from_sequence(vec![
        Ok(valid_up("alice")),
        Err(CredentialError::Backend(
            "inner must not be called a second time".into(),
        )),
    ]);
    let caching = CachingCredentialProvider::new(mock, REFRESH_WINDOW);

    let _ = caching.get().await.expect("first get should succeed");
    let second = caching.get().await;

    assert!(
        second.is_ok(),
        "second call must return cached credential, not an error"
    );
    assert_eq!(second.unwrap().username, "alice");
}

/// Rule 1 failure path: spec requires `Unavailable`, not propagation of the
/// inner error variant. This kills stubs that unconditionally propagate.
///
/// Covers E-CACHE-1 as well.
#[tokio::test]
async fn empty_cache_inner_failure_returns_unavailable() {
    let mock = MockCredentialProvider::<UsernamePassword>::returning_err(CredentialError::Backend(
        "vault unreachable".into(),
    ));
    let caching = CachingCredentialProvider::new(mock, REFRESH_WINDOW);

    let result = caching.get().await;

    assert!(
        matches!(result, Err(CredentialError::Unavailable)),
        "empty-cache fetch failure must return Unavailable; got: {:?}",
        result,
    );
}

// ── A-CACHE-2: Valid credential outside refresh window ────────────────────
// Assertions:
//   • inner.get() is NOT called
//   • the cached credential is returned

/// If inner is called a second time it returns `Err` — proves it must not be.
#[tokio::test]
async fn valid_credential_outside_refresh_window_not_fetched_again() {
    let mock = MockCredentialProvider::from_sequence(vec![
        Ok(valid_up("alice")),
        Err(CredentialError::Backend(
            "inner must not be called on cache hit".into(),
        )),
    ]);
    let caching = CachingCredentialProvider::new(mock, REFRESH_WINDOW);

    let _ = caching.get().await.expect("first call populates cache");
    let second = caching.get().await;

    assert!(
        second.is_ok(),
        "valid cached credential outside refresh window must not trigger another fetch",
    );
}

#[tokio::test]
async fn valid_credential_outside_refresh_window_returns_cached_value() {
    let mock = MockCredentialProvider::returning_ok(valid_up("cached-user"));
    let caching = CachingCredentialProvider::new(mock, REFRESH_WINDOW);

    let _ = caching.get().await.unwrap();
    let second = caching.get().await.unwrap();

    assert_eq!(second.username, "cached-user");
}

// ── A-CACHE-3: Valid credential inside refresh window — refresh succeeds ──
// Assertions:
//   • inner.get() is called again
//   • the NEW credential is returned (not the old one)

#[tokio::test]
async fn credential_inside_refresh_window_triggers_refresh_and_returns_new() {
    // 30 s remaining < 60 s window → inside window → refresh triggered
    let mock = MockCredentialProvider::from_sequence(vec![
        Ok(refreshing_up("old-user")),
        Ok(valid_up("new-user")),
    ]);
    let caching = CachingCredentialProvider::new(mock, REFRESH_WINDOW);

    let first = caching.get().await.unwrap();
    assert_eq!(first.username, "old-user");

    let second = caching.get().await.unwrap();
    assert_eq!(
        second.username, "new-user",
        "credential inside refresh window must be refreshed",
    );
}

/// Stub-killer: verifies that the old cached value is NOT returned when
/// inner succeeds during a refresh.
#[tokio::test]
async fn credential_inside_refresh_window_does_not_return_old_value_on_success() {
    let mock = MockCredentialProvider::from_sequence(vec![
        Ok(refreshing_up("old-user")),
        Ok(valid_up("new-user")),
    ]);
    let caching = CachingCredentialProvider::new(mock, REFRESH_WINDOW);

    let _ = caching.get().await.unwrap();
    let refreshed = caching.get().await.unwrap();

    assert_ne!(
        refreshed.username, "old-user",
        "refresh must NOT return old cached value when inner succeeds",
    );
}

// ── A-CACHE-4: Valid credential inside refresh window — stale fallback ────
// Assertions:
//   • stale cached credential is returned (not the error)

#[tokio::test]
async fn credential_inside_refresh_window_refresh_failure_returns_stale_not_error() {
    let mock = MockCredentialProvider::from_sequence(vec![
        Ok(refreshing_up("stale-user")),
        Err(CredentialError::Unreachable("backend down".into())),
    ]);
    let caching = CachingCredentialProvider::new(mock, REFRESH_WINDOW);

    let _ = caching.get().await.expect("cache must be populated");
    let fallback = caching.get().await;

    assert!(
        fallback.is_ok(),
        "refresh failure while cached credential is still valid must return stale, not error; got: {:?}",
        fallback,
    );
}

#[tokio::test]
async fn stale_fallback_returns_specifically_the_still_valid_cached_username() {
    let mock = MockCredentialProvider::from_sequence(vec![
        Ok(refreshing_up("stale-user")),
        Err(CredentialError::Backend("refresh failed".into())),
    ]);
    let caching = CachingCredentialProvider::new(mock, REFRESH_WINDOW);

    let _ = caching.get().await.unwrap();
    let fallback = caching.get().await.unwrap();

    assert_eq!(
        fallback.username, "stale-user",
        "stale fallback must return the still-valid cached credential",
    );
}

// ── A-CACHE-5: Expired cache + refresh failure → propagate error ──────────
// Assertions:
//   • the CredentialError is propagated (not the expired stale credential)
//   • the specific inner error variant is preserved (not wrapped in Unavailable)

/// The cache is populated with a pre-expired credential. The second call
/// hits Rule 5 (expired cache) and must propagate the error, not fall back.
#[tokio::test]
async fn expired_credential_refresh_failure_propagates_error_not_stale() {
    let mock = MockCredentialProvider::from_sequence(vec![
        Ok(expired_up("expired-user")),
        Err(CredentialError::Backend("refresh failed".into())),
    ]);
    let caching = CachingCredentialProvider::new(mock, REFRESH_WINDOW);

    let _ = caching.get().await; // populates cache with expired credential
    let result = caching.get().await;

    assert!(
        result.is_err(),
        "expired cached credential with failed refresh must propagate error, not return stale",
    );
}

/// Stub-killer pair with `empty_cache_inner_failure_returns_unavailable`:
/// Rule 5 must propagate the inner error, NOT wrap it in `Unavailable`.
#[tokio::test]
async fn expired_credential_refresh_failure_propagates_original_error_variant_not_unavailable() {
    let mock = MockCredentialProvider::from_sequence(vec![
        Ok(expired_up("expired-user")),
        Err(CredentialError::Backend("specific backend error".into())),
    ]);
    let caching = CachingCredentialProvider::new(mock, REFRESH_WINDOW);

    let _ = caching.get().await;
    let result = caching.get().await;

    assert!(
        matches!(result, Err(CredentialError::Backend(_))),
        "expired-cache refresh failure must propagate Backend error, not wrap in Unavailable; got: {:?}",
        result,
    );
}

// ── A-CACHE-6: Concurrent calls serialize to one fetch ────────────────────
// Approach: mock returns "fetched-once" on the first call, "fetched-again"
// on all subsequent calls. Correct serialization → all 8 tasks see
// "fetched-once". Any duplicate fetch → at least one task sees "fetched-again".

#[tokio::test]
async fn concurrent_calls_on_empty_cache_serialize_to_one_fetch() {
    const N: usize = 8;

    let mock = MockCredentialProvider::from_sequence(vec![
        Ok(valid_up("fetched-once")),
        Ok(valid_up("fetched-again")), // repeated for any extra fetches
    ]);

    let caching = Arc::new(CachingCredentialProvider::new(mock, REFRESH_WINDOW));
    let barrier = Arc::new(tokio::sync::Barrier::new(N));

    let mut join_set = tokio::task::JoinSet::new();
    for _ in 0..N {
        let c = Arc::clone(&caching);
        let b = Arc::clone(&barrier);
        join_set.spawn(async move {
            b.wait().await;
            c.get().await
        });
    }

    let mut results: Vec<Result<UsernamePassword, CredentialError>> = Vec::with_capacity(N);
    while let Some(join_result) = join_set.join_next().await {
        results.push(join_result.expect("spawned task panicked"));
    }

    assert_eq!(results.len(), N, "all {} tasks must complete", N);

    for (i, result) in results.iter().enumerate() {
        assert!(result.is_ok(), "task {} must succeed; got: {:?}", i, result);
    }

    for (i, result) in results.iter().enumerate() {
        assert_eq!(
            result.as_ref().unwrap().username,
            "fetched-once",
            "task {} must receive the once-fetched credential, not a subsequent fetch",
            i,
        );
    }
}

// ── A-CACHE-7: No-expiry credential — inner called only once ──────────────
// HmacSecret has expires_at() == None, so Rule 2 / Rule 6 always applies
// after the first fetch.

/// If inner is called more than once it returns `Err` on the second call,
/// causing any of the 6 loop iterations to fail.
#[tokio::test]
async fn no_expiry_credential_inner_called_only_once_across_many_calls() {
    let mock = MockCredentialProvider::from_sequence(vec![
        Ok(HmacSecret::new(SecretVec::new(vec![1u8, 2, 3, 4]))),
        Err(CredentialError::Backend(
            "inner must not be called again".into(),
        )),
    ]);
    let caching = CachingCredentialProvider::new(mock, REFRESH_WINDOW);

    for i in 1..=6 {
        let result = caching.get().await;
        assert!(
            result.is_ok(),
            "call {} on a no-expiry credential must succeed; got: {:?}",
            i,
            result,
        );
    }
}

#[tokio::test]
async fn no_expiry_credential_returns_same_bytes_on_every_call() {
    let key_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let mock =
        MockCredentialProvider::returning_ok(HmacSecret::new(SecretVec::new(key_bytes.clone())));
    let caching = CachingCredentialProvider::new(mock, REFRESH_WINDOW);

    let first = caching.get().await.unwrap();
    let second = caching.get().await.unwrap();
    let third = caching.get().await.unwrap();

    assert_eq!(first.key.expose_secret(), &key_bytes);
    assert_eq!(second.key.expose_secret(), &key_bytes);
    assert_eq!(third.key.expose_secret(), &key_bytes);
}

// ── A-CACHE-8: Successful refresh replaces cached value ───────────────────
// Assertions:
//   • the newly refreshed credential is returned (not old)
//   • a SUBSEQUENT call within the new credential's validity window also
//     returns the new credential

#[tokio::test]
async fn successful_refresh_returns_new_credential_not_old() {
    let mock = MockCredentialProvider::from_sequence(vec![
        Ok(refreshing_up("old-user")),
        Ok(valid_up("new-user")),
    ]);
    let caching = CachingCredentialProvider::new(mock, REFRESH_WINDOW);

    let _ = caching.get().await.unwrap(); // populate with old-user (inside window)
    let refreshed = caching.get().await.unwrap();

    assert_eq!(refreshed.username, "new-user");
}

/// After a successful refresh the new credential must be stored in the
/// cache. The third call must return the new credential from cache without
/// hitting inner again (inner would return `Err` on the third call).
#[tokio::test]
async fn after_successful_refresh_subsequent_call_returns_new_credential() {
    let mock = MockCredentialProvider::from_sequence(vec![
        Ok(refreshing_up("old-user")),
        Ok(valid_up("new-user")), // new-user has 3600 s validity → outside window on 3rd call
        Err(CredentialError::Backend("inner called a third time".into())),
    ]);
    let caching = CachingCredentialProvider::new(mock, REFRESH_WINDOW);

    let _ = caching.get().await.unwrap(); // 1st: populate with old-user (inside window)
    let _ = caching.get().await.unwrap(); // 2nd: refresh → new-user cached
    let third = caching.get().await; // 3rd: new-user is outside window → cached

    assert!(
        third.is_ok(),
        "third call must return cached new credential; got: {:?}",
        third,
    );
    assert_eq!(
        third.unwrap().username,
        "new-user",
        "third call must return newly cached credential, not old value",
    );
}

// ── E-CACHE-2: Refresh window boundary (inclusive ≤) ─────────────────────
// A credential set to expire in exactly `REFRESH_WINDOW` seconds is at the
// boundary. By the time get() evaluates it, a few microseconds have elapsed,
// making remaining_time < REFRESH_WINDOW. The implementation must use ≤ (not
// <) so that the at-boundary case is always treated as inside the window.

#[tokio::test]
async fn credential_at_boundary_of_refresh_window_triggers_refresh() {
    // expires_at ≈ now + 60 s; by the time get() checks it, remaining ≤ 60 s
    let boundary_cred = up("boundary-user", Some(Instant::now() + REFRESH_WINDOW));
    let mock = MockCredentialProvider::from_sequence(vec![
        Ok(boundary_cred),
        Ok(valid_up("refreshed-boundary-user")),
    ]);
    let caching = CachingCredentialProvider::new(mock, REFRESH_WINDOW);

    let _ = caching.get().await.unwrap();
    let second = caching.get().await.unwrap();

    assert_eq!(
        second.username, "refreshed-boundary-user",
        "credential at the refresh window boundary must trigger refresh (inclusive ≤ comparison)",
    );
}
