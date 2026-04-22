// SPEC: docs/spec/interfaces/env-adapters.md
#![allow(dead_code)]

use credential_provider_core::{
    BearerToken, BoxFuture, CredentialError, CredentialProvider, HmacSecret, UsernamePassword,
};

// ---------------------------------------------------------------------------
// EnvUsernamePasswordProvider
// ---------------------------------------------------------------------------

/// Reads a username and password from a pair of environment variables.
///
/// Both variables are read on every call to `get()`. This means that if the
/// variables change between calls (e.g., via a secrets management sidecar),
/// the change is picked up on the next refresh cycle of
/// `CachingCredentialProvider`.
///
/// The returned [`UsernamePassword`] always has `is_valid() == true` and
/// `expires_at() == None`.
///
/// # Errors
///
/// Returns [`CredentialError::Configuration`] if either variable is not set
/// or is empty.
///
/// # Examples
///
/// ```rust,ignore
/// use credential_provider::env::EnvUsernamePasswordProvider;
///
/// let provider = EnvUsernamePasswordProvider::new("RABBITMQ_USERNAME", "RABBITMQ_PASSWORD");
/// ```
///
/// See: docs/spec/interfaces/env-adapters.md
pub struct EnvUsernamePasswordProvider {
    username_var: String,
    password_var: String,
}

impl EnvUsernamePasswordProvider {
    /// Creates a new provider that reads the username from `username_var` and
    /// the password from `password_var`.
    pub fn new(username_var: impl Into<String>, password_var: impl Into<String>) -> Self {
        Self {
            username_var: username_var.into(),
            password_var: password_var.into(),
        }
    }
}

impl CredentialProvider<UsernamePassword> for EnvUsernamePasswordProvider {
    fn get(&self) -> BoxFuture<'_, Result<UsernamePassword, CredentialError>> {
        Box::pin(async move { unimplemented!("See docs/spec/interfaces/env-adapters.md") })
    }
}

// ---------------------------------------------------------------------------
// EnvHmacSecretProvider
// ---------------------------------------------------------------------------

/// Reads a hex- or base64-encoded HMAC key from an environment variable.
///
/// The variable is read on every call to `get()`. The encoding format (hex or
/// base64) is detected automatically.
///
/// The returned [`HmacSecret`] has `is_valid() == true` and
/// `expires_at() == None` (HMAC keys do not expire).
///
/// # Errors
///
/// Returns [`CredentialError::Configuration`] if the variable is not set,
/// is empty, or contains a value that cannot be decoded as hex or base64.
///
/// # Examples
///
/// ```rust,ignore
/// use credential_provider::env::EnvHmacSecretProvider;
///
/// let provider = EnvHmacSecretProvider::new("GITHUB_WEBHOOK_SECRET");
/// ```
///
/// See: docs/spec/interfaces/env-adapters.md
pub struct EnvHmacSecretProvider {
    secret_var: String,
}

impl EnvHmacSecretProvider {
    /// Creates a new provider that reads the HMAC key from `secret_var`.
    pub fn new(secret_var: impl Into<String>) -> Self {
        Self {
            secret_var: secret_var.into(),
        }
    }
}

impl CredentialProvider<HmacSecret> for EnvHmacSecretProvider {
    fn get(&self) -> BoxFuture<'_, Result<HmacSecret, CredentialError>> {
        Box::pin(async move { unimplemented!("See docs/spec/interfaces/env-adapters.md") })
    }
}

// ---------------------------------------------------------------------------
// EnvBearerTokenProvider
// ---------------------------------------------------------------------------

/// Reads a bearer token from an environment variable.
///
/// The variable is read on every call to `get()`.
///
/// The returned [`BearerToken`] always has `is_valid() == true` and
/// `expires_at() == None`.
///
/// # Errors
///
/// Returns [`CredentialError::Configuration`] if the variable is not set or
/// is empty.
///
/// # Examples
///
/// ```rust,ignore
/// use credential_provider::env::EnvBearerTokenProvider;
///
/// let provider = EnvBearerTokenProvider::new("API_TOKEN");
/// ```
///
/// See: docs/spec/interfaces/env-adapters.md
pub struct EnvBearerTokenProvider {
    token_var: String,
}

impl EnvBearerTokenProvider {
    /// Creates a new provider that reads the bearer token from `token_var`.
    pub fn new(token_var: impl Into<String>) -> Self {
        Self {
            token_var: token_var.into(),
        }
    }
}

impl CredentialProvider<BearerToken> for EnvBearerTokenProvider {
    fn get(&self) -> BoxFuture<'_, Result<BearerToken, CredentialError>> {
        Box::pin(async move { unimplemented!("See docs/spec/interfaces/env-adapters.md") })
    }
}
