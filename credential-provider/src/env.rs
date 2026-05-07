// SPEC: docs/spec/interfaces/env-adapters.md

use base64::Engine as _;
use credential_provider_core::{
    BearerToken, BoxFuture, CredentialError, CredentialProvider, HmacSecret, SecretString,
    SecretVec, UsernamePassword,
};

// ---------------------------------------------------------------------------
// Internal helper
// ---------------------------------------------------------------------------

/// Reads an environment variable by name.
///
/// Returns:
/// - `Ok(value)` — variable is set and non-empty
/// - `Err(CredentialError::Configuration)` — variable is absent or empty
/// - `Err(CredentialError::Configuration)` — variable contains non-UTF-8 bytes
fn read_env_var(name: &str) -> Result<String, CredentialError> {
    match std::env::var(name) {
        Ok(value) if value.is_empty() => Err(CredentialError::Configuration(format!(
            "missing env var: {name}"
        ))),
        Ok(value) => Ok(value),
        Err(std::env::VarError::NotPresent) => Err(CredentialError::Configuration(format!(
            "missing env var: {name}"
        ))),
        Err(std::env::VarError::NotUnicode(_)) => Err(CredentialError::Configuration(format!(
            "variable contains invalid UTF-8: {name}"
        ))),
    }
}

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
        Box::pin(async {
            let username = read_env_var(&self.username_var)?;
            let password = read_env_var(&self.password_var)?;
            Ok(UsernamePassword::new(
                username,
                SecretString::new(password),
                None,
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// EnvHmacSecretProvider
// ---------------------------------------------------------------------------

/// Reads a hex- or base64-encoded HMAC key from an environment variable.
///
/// The variable is read on every call to `get()`. The encoding format (hex or
/// base64) is detected automatically: hex is tried first, then base64 (standard
/// alphabet with padding). A value that is valid hex will never be interpreted
/// as base64.
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
        Box::pin(async {
            let raw = read_env_var(&self.secret_var)?;

            // Attempt hex decode first; on failure fall back to base64 standard.
            let bytes = if let Ok(decoded) = hex::decode(&raw) {
                decoded
            } else {
                base64::engine::general_purpose::STANDARD
                    .decode(&raw)
                    .map_err(|_| {
                        CredentialError::Configuration(format!(
                            "invalid encoding for env var: {}",
                            self.secret_var
                        ))
                    })?
            };

            Ok(HmacSecret::new(SecretVec::new(bytes)))
        })
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
        Box::pin(async {
            let token = read_env_var(&self.token_var)?;
            Ok(BearerToken::new(SecretString::new(token), None))
        })
    }
}

#[cfg(test)]
#[path = "env_tests.rs"]
mod tests;
