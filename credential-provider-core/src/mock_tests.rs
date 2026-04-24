//! Tests for MockCredentialProvider.
//!
//! Verifies call_count() tracking and sequenced response delivery.

use std::time::{Duration, Instant};

use secrecy::SecretString;

use super::MockCredentialProvider;
use crate::{CredentialError, CredentialProvider, UsernamePassword};

fn up() -> UsernamePassword {
    UsernamePassword::new(
        "testuser",
        SecretString::new("pass".into()),
        Some(Instant::now() + Duration::from_secs(3600)),
    )
}

// ── call_count ────────────────────────────────────────────────────────────────

/// call_count() returns 0 before any get() calls.
///
/// Stub-killer: kills `call_count → 1` mutation.
#[tokio::test]
async fn test_call_count_is_zero_before_any_calls() {
    let mock = MockCredentialProvider::returning_ok(up());
    assert_eq!(
        mock.call_count(),
        0,
        "call_count must be zero before any calls"
    );
}

/// call_count() returns 1 after a single get() call.
///
/// Stub-killer: kills `call_count → 0` mutation.
#[tokio::test]
async fn test_call_count_is_one_after_one_call() {
    let mock = MockCredentialProvider::returning_ok(up());
    let _ = mock.get().await;
    assert_eq!(
        mock.call_count(),
        1,
        "call_count must be 1 after one get() call"
    );
}

/// call_count() increments correctly across multiple calls.
///
/// Stub-killer: kills both `→ 0` and `→ 1` constant-replacement mutations
/// because 3 ≠ 0 and 3 ≠ 1.
#[tokio::test]
async fn test_call_count_increments_over_multiple_calls() {
    let mock = MockCredentialProvider::returning_ok(up());
    let _ = mock.get().await;
    let _ = mock.get().await;
    let _ = mock.get().await;
    assert_eq!(
        mock.call_count(),
        3,
        "call_count must equal the number of get() calls"
    );
}

// ── Response sequencing ───────────────────────────────────────────────────────

/// returning_ok repeats the single credential on every call.
#[tokio::test]
async fn test_returning_ok_repeats_credential() {
    let mock = MockCredentialProvider::returning_ok(up());
    let r1 = mock.get().await.unwrap();
    let r2 = mock.get().await.unwrap();
    assert_eq!(r1.username, "testuser");
    assert_eq!(r2.username, "testuser");
}

/// returning_err repeats the error on every call and tracks call_count.
#[tokio::test]
async fn test_returning_err_repeats_error() {
    let mock = MockCredentialProvider::<UsernamePassword>::returning_err(CredentialError::Backend(
        "boom".into(),
    ));
    let r1 = mock.get().await;
    let r2 = mock.get().await;
    assert!(matches!(r1, Err(CredentialError::Backend(_))));
    assert!(matches!(r2, Err(CredentialError::Backend(_))));
    assert_eq!(
        mock.call_count(),
        2,
        "call_count must reflect error calls too"
    );
}

/// from_sequence delivers values in order and repeats the last entry.
#[tokio::test]
async fn test_from_sequence_delivers_in_order_and_repeats_last() {
    let mock = MockCredentialProvider::from_sequence(vec![
        Ok(UsernamePassword::new(
            "first",
            SecretString::new("p".into()),
            None,
        )),
        Ok(UsernamePassword::new(
            "second",
            SecretString::new("p".into()),
            None,
        )),
    ]);
    assert_eq!(mock.get().await.unwrap().username, "first");
    assert_eq!(mock.get().await.unwrap().username, "second");
    // third call: last element ("second") repeated
    assert_eq!(mock.get().await.unwrap().username, "second");
}
