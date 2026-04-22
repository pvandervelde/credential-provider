// SPEC: docs/spec/interfaces/test-support.md
//
// MockCredentialProvider is available only in test code or when the
// `test-support` feature is explicitly enabled. It must never be compiled
// into production builds.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Mutex;

use crate::{BoxFuture, Credential, CredentialError, CredentialProvider};

/// A test double for [`CredentialProvider<C>`] that returns pre-configured
/// values.
///
/// Use `MockCredentialProvider` in tests that need to control credential
/// validity, expiry, or error conditions precisely without connecting to an
/// external backend.
///
/// # Availability
///
/// Only available under `#[cfg(any(test, feature = "test-support"))]`.
/// The `test-support` feature must never be enabled in production Cargo
/// profiles.
///
/// # Examples
///
/// ```rust,ignore
/// use std::time::{Duration, Instant};
/// use secrecy::SecretString;
/// use credential_provider_core::{UsernamePassword, CachingCredentialProvider};
/// use credential_provider_core::mock::MockCredentialProvider;
///
/// let provider = MockCredentialProvider::returning_ok(UsernamePassword::new(
///     "testuser",
///     SecretString::new("pass".to_string()),
///     Some(Instant::now() + Duration::from_secs(300)),
/// ));
///
/// let caching = CachingCredentialProvider::new(provider, Duration::from_secs(60));
/// let creds = caching.get().await.unwrap();
/// assert_eq!(creds.username, "testuser");
/// assert_eq!(provider.call_count(), 1);
/// ```
///
/// See: docs/spec/interfaces/test-support.md
#[cfg(any(test, feature = "test-support"))]
pub struct MockCredentialProvider<C: Credential> {
    /// The values returned in sequence on each call to `get()`. When the
    /// sequence is exhausted, subsequent calls return a clone of the last
    /// value.
    responses: Mutex<Vec<Result<C, CredentialError>>>,

    /// Total number of times `get()` has been called. Useful for asserting
    /// that the caching layer called the inner provider the expected number
    /// of times.
    call_count: Arc<AtomicUsize>,
}

#[cfg(any(test, feature = "test-support"))]
impl<C: Credential> MockCredentialProvider<C> {
    /// Creates a mock that always returns the given credential.
    pub fn returning_ok(credential: C) -> Self {
        Self {
            responses: Mutex::new(vec![Ok(credential)]),
            call_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Creates a mock that always returns the given error.
    pub fn returning_err(error: CredentialError) -> Self {
        Self {
            responses: Mutex::new(vec![Err(error)]),
            call_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Creates a mock that returns each value in `responses` sequentially on
    /// successive calls. Once the sequence is exhausted the last value is
    /// repeated on all subsequent calls.
    ///
    /// # Panics
    ///
    /// Panics if `responses` is empty.
    pub fn from_sequence(responses: Vec<Result<C, CredentialError>>) -> Self {
        assert!(
            !responses.is_empty(),
            "MockCredentialProvider::from_sequence requires at least one response"
        );
        Self {
            responses: Mutex::new(responses),
            call_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Returns the total number of times `get()` has been called on this mock.
    pub fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl<C: Credential> CredentialProvider<C> for MockCredentialProvider<C> {
    fn get(&self) -> BoxFuture<'_, Result<C, CredentialError>> {
        Box::pin(async move {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            let mut guard = self.responses.lock().await;
            if guard.len() > 1 {
                guard.remove(0)
            } else {
                // Clone the last element so we can repeat it indefinitely.
                guard[0].clone()
            }
        })
    }
}
