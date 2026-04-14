// SPEC: docs/spec/interfaces/shared-types.md — CredentialProvider

use std::pin::Pin;

use crate::{Credential, CredentialError};

/// Type alias for a boxed, pinned async future used in trait method signatures.
///
/// Using `BoxFuture` instead of `impl Future` in the [`CredentialProvider`] trait
/// makes the trait object-safe, allowing `Arc<dyn CredentialProvider<C>>` to
/// be used at runtime without size-at-compile-time constraints.
pub type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// The central abstraction for credential management.
///
/// Implementations fetch credentials from a specific backing store on every
/// call to `get()`. Implementations must **not** cache results internally —
/// caching is the sole responsibility of [`CachingCredentialProvider`].
///
/// # Contract
///
/// - `get()` returns a freshly fetched credential on every call
/// - Implementations must translate all backend-specific errors into
///   [`CredentialError`] variants before returning
/// - Implementations must be safe to call concurrently from multiple tasks
/// - Implementations must be `Send + Sync + 'static` so they can be held
///   behind `Arc` and passed to spawned tasks
///
/// # Wiring
///
/// Applications construct concrete providers from the `credential-provider`
/// adapter crate and wrap them in [`CachingCredentialProvider`] before
/// passing them to consumer libraries. Consumer libraries accept
/// `Arc<dyn CredentialProvider<C>>` and never construct providers directly.
///
/// # Examples
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use credential_provider_core::{CredentialProvider, UsernamePassword};
///
/// pub struct QueueConnector {
///     credentials: Arc<dyn CredentialProvider<UsernamePassword>>,
/// }
///
/// impl QueueConnector {
///     pub async fn connect(&self) -> Result<(), Box<dyn std::error::Error>> {
///         let creds = self.credentials.get().await?;
///         // use creds.username and creds.password
///         Ok(())
///     }
/// }
/// ```
///
/// See: docs/spec/interfaces/shared-types.md
///
/// [`CachingCredentialProvider`]: crate::CachingCredentialProvider
pub trait CredentialProvider<C: Credential>: Send + Sync + 'static {
    /// Fetch a fresh set of credentials from the backing store.
    ///
    /// This method may be called concurrently from multiple tasks.
    /// Implementations must not hold long-lived locks across `.await` points.
    ///
    /// # Errors
    ///
    /// Returns a [`CredentialError`] variant appropriate to the failure:
    /// - [`CredentialError::Backend`] — store responded with an error
    /// - [`CredentialError::Unreachable`] — store could not be contacted
    /// - [`CredentialError::Configuration`] — provider is misconfigured
    /// - [`CredentialError::Revoked`] — credential was explicitly revoked
    fn get(&self) -> BoxFuture<'_, Result<C, CredentialError>>;
}
