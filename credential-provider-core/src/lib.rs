// credential-provider-core
//
// Port definitions for provider-agnostic credential management.
// This crate defines what credentials *are* and how they behave.
// It has no knowledge of any secrets backend.
//
// SPEC: docs/spec/credential-provider-core.md

mod caching;
mod credentials;
mod error;
mod provider;

#[cfg(any(test, feature = "test-support"))]
pub mod mock;

// --- Public API ---

pub use caching::CachingCredentialProvider;
pub use credentials::{BearerToken, HmacSecret, TlsClientCertificate, UsernamePassword};
pub use error::CredentialError;
pub use provider::{BoxFuture, CredentialProvider};

// Re-export secrecy primitives so consumers of this crate do not need a
// direct dependency on `secrecy`.
pub use secrecy::{ExposeSecret, SecretString, SecretVec};

use std::time::Instant;

/// Contract that all credential types must satisfy.
///
/// Implementors represent a set of data that proves identity or grants access
/// to a resource. The trait provides validity inspection so the caching layer
/// can determine whether a cached credential is still usable without knowing
/// the credential's internal structure.
///
/// # Trait Bounds
///
/// Implementors must be `Send + Sync + Clone + 'static` because:
/// - `Clone` — `CachingCredentialProvider` returns copies from the cache
/// - `Send + Sync` — credentials are passed across async task boundaries
/// - `'static` — providers are stored in `Arc` and passed to spawned tasks
///
/// # Implementing
///
/// ```rust,ignore
/// use std::time::Instant;
/// use credential_provider_core::Credential;
///
/// #[derive(Clone)]
/// pub struct MyCredential {
///     pub value: String,
///     pub expires_at: Option<Instant>,
/// }
///
/// impl Credential for MyCredential {
///     fn is_valid(&self) -> bool {
///         self.expires_at.map_or(true, |e| Instant::now() < e)
///     }
///
///     fn expires_at(&self) -> Option<Instant> {
///         self.expires_at
///     }
/// }
/// ```
///
/// See: docs/spec/interfaces/shared-types.md
pub trait Credential: Send + Sync + Clone + 'static {
    /// Returns `true` if these credentials are currently usable.
    ///
    /// A credential with no known expiry (`expires_at()` returns `None`) is
    /// always considered valid.
    fn is_valid(&self) -> bool;

    /// Returns the instant at which these credentials will no longer be valid,
    /// if known.
    ///
    /// `None` means the credential does not expire or the expiry is not
    /// communicated by the backing store.
    fn expires_at(&self) -> Option<Instant>;
}
