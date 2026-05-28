// SPEC: docs/spec/interfaces/vault-adapter.md
//
// This module is gated behind the `vault` feature flag.
// It requires the `vaultrs` crate with the `rustls` feature.

use std::sync::Arc;
use std::time::{Duration, Instant};

use credential_provider_core::{
    BearerToken, BoxFuture, Credential, CredentialError, CredentialProvider, HmacSecret,
    SecretString, TlsClientCertificate, UsernamePassword,
};
use vaultrs::client::VaultClient;

// ---------------------------------------------------------------------------
// VaultExtractor — response translation strategy
// ---------------------------------------------------------------------------

/// Strategy for translating a Vault secrets engine response into a credential.
///
/// Each Vault secrets engine has its own response structure. `VaultExtractor`
/// decouples response parsing from the fetch logic, allowing `VaultProvider<C>`
/// to support any engine without modification.
///
/// Implementors receive the raw JSON response from the Vault API and the
/// lease duration (in seconds, if any) and must construct a `C` or return a
/// [`CredentialError`].
///
/// # Implementing
///
/// ```rust,ignore
/// use serde_json::Value;
/// use credential_provider_core::{UsernamePassword, CredentialError};
/// use credential_provider::vault::VaultExtractor;
///
/// struct MyExtractor;
///
/// impl VaultExtractor<UsernamePassword> for MyExtractor {
///     fn extract(
///         &self,
///         data: &Value,
///         lease_duration_secs: Option<u64>,
///     ) -> Result<UsernamePassword, CredentialError> {
///         // parse data, construct UsernamePassword
///         unimplemented!()
///     }
/// }
/// ```
///
/// See: docs/spec/interfaces/vault-adapter.md
pub trait VaultExtractor<C: Credential>: Send + Sync + 'static {
    /// Translate a Vault response body and lease metadata into a credential.
    ///
    /// # Parameters
    ///
    /// - `data` — the `data` field from the Vault API response (deserialized JSON)
    /// - `lease_duration_secs` — the `lease_duration` from the Vault response,
    ///   if present. Dynamic engines return a non-zero lease duration; static
    ///   engines (KV v2 without TTL) return `None` or zero.
    ///
    /// # Errors
    ///
    /// Return [`CredentialError::Backend`] if a required field is missing or
    /// has an unexpected type in `data`.
    fn extract(
        &self,
        data: &serde_json::Value,
        lease_duration_secs: Option<u64>,
    ) -> Result<C, CredentialError>;
}

// ---------------------------------------------------------------------------
// VaultProvider — generic provider for any secrets engine
// ---------------------------------------------------------------------------

/// A generic [`CredentialProvider<C>`] that reads from any Vault secrets engine.
///
/// `VaultProvider<C>` is parameterized on the credential type it produces and
/// is configured with a [`VaultExtractor<C>`] that knows how to map a
/// specific engine's JSON response to `C`.
///
/// # Authentication
///
/// The provider does **not** manage Vault authentication. A [`VaultClient`]
/// that is already authenticated must be supplied at construction time. The
/// application is responsible for authenticating (AppRole, JWT/OIDC,
/// Kubernetes, etc.) and for renewing the Vault token before it expires.
/// See [ADR-004].
///
/// # Error Mapping
///
/// Vault errors are translated to [`CredentialError`] uniformly:
///
/// | Vault / vaultrs condition          | `CredentialError` variant              |
/// |------------------------------------|----------------------------------------|
/// | HTTP 403 Forbidden                 | `Backend("permission denied")`         |
/// | HTTP 404 Not Found (path missing)  | `Configuration("role or path not found: …")` |
/// | Connection refused / timeout       | `Unreachable("…")`                     |
/// | Lease expired on re-read           | `Revoked`                              |
/// | Malformed response                 | `Backend("unexpected response: …")`    |
///
/// # Convenience Constructors
///
/// Prefer the convenience constructors for common engine patterns:
/// - [`VaultProvider::dynamic_credentials`] — RabbitMQ, database, AWS, SSH, etc.
/// - [`VaultProvider::kv2_secret`] — KV v2 static secrets
/// - [`VaultProvider::pki_certificate`] — PKI engine certificates
/// - [`VaultProvider::with_extractor`] — custom engine with a bespoke extractor
///
/// # Examples
///
/// ```rust,ignore
/// use credential_provider::vault::VaultProvider;
///
/// let provider = VaultProvider::dynamic_credentials(
///     vault_client.clone(),
///     "rabbitmq",
///     "creds/queue-keeper",
/// );
/// ```
///
/// See: docs/spec/interfaces/vault-adapter.md
///
/// # Security Note
///
/// [`vaultrs::client::VaultClientSettings`] derives `Debug` with a plaintext
/// `token` field. Do **not** format `VaultClient.settings` with `{:?}` in
/// production log statements. Store `Arc<VaultClient>` as an opaque handle
/// and do not access `.settings` inside tracing spans or log macros.
///
/// [ADR-004]: docs/adr/ADR-004-external-vault-authentication.md
pub struct VaultProvider<C: Credential> {
    client: Arc<VaultClient>,
    mount: String,
    path: String,
    extractor: Arc<dyn VaultExtractor<C>>,
    // fetch_strategy is intentionally absent from this task-3.0 implementation.
    // The current get() uses vaultrs::kv1::get_raw() which covers dynamic secrets
    // engines (RabbitMQ, database, SSH, Consul, AWS). KV v2 and PKI require
    // different vaultrs calls. Task 5.0 (KV v2) will extend VaultProvider<C> with a
    //   fetch_strategy: FetchStrategy   (private enum: Kv1, Kv2, Pki)
    // field and dispatch on it in get(). Adding the field now without implementing
    // the branches would be dead code. See docs/spec/interfaces/vault-adapter.md
    // for the complete constructor design.
}

impl<C: Credential> VaultProvider<C> {
    /// Creates a `VaultProvider` with a custom [`VaultExtractor`].
    ///
    /// Use this when a convenience constructor does not cover your engine.
    pub fn with_extractor(
        client: Arc<VaultClient>,
        mount: impl Into<String>,
        path: impl Into<String>,
        extractor: impl VaultExtractor<C> + 'static,
    ) -> Self {
        Self {
            client,
            mount: mount.into(),
            path: path.into(),
            extractor: Arc::new(extractor),
        }
    }
}

// Convenience constructors for common engine patterns.

/// Extracts a `UsernamePassword` credential from a dynamic Vault secrets engine response.
///
/// Reads `username` and `password` string fields from the `data` object and derives
/// `expires_at` from `lease_duration_secs`. Used by `VaultProvider::dynamic_credentials`.
struct DynamicCredentialsExtractor;

impl VaultExtractor<UsernamePassword> for DynamicCredentialsExtractor {
    fn extract(
        &self,
        data: &serde_json::Value,
        lease_duration_secs: Option<u64>,
    ) -> Result<UsernamePassword, CredentialError> {
        let username = extract_str_field(data, "username")?;
        let password = extract_str_field(data, "password")?;
        let expires_at = lease_duration_secs
            .filter(|&d| d > 0)
            .map(|d| Instant::now() + Duration::from_secs(d));
        Ok(UsernamePassword::new(
            username.to_string(),
            SecretString::from(password.to_owned()),
            expires_at,
        ))
    }
}

impl VaultProvider<UsernamePassword> {
    /// Creates a provider for dynamic secrets engines (RabbitMQ, database, etc.)
    /// that issue `UsernamePassword` credentials with a lease duration.
    ///
    /// # Parameters
    ///
    /// - `client` — an authenticated `VaultClient`
    /// - `mount` — the mount path of the secrets engine (e.g. `"rabbitmq"`)
    /// - `path` — the role path within the mount (e.g. `"creds/queue-keeper"`)
    ///
    /// The returned credential carries `expires_at` derived from Vault's
    /// `lease_duration` field.
    pub fn dynamic_credentials(
        client: Arc<VaultClient>,
        mount: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self::with_extractor(client, mount, path, DynamicCredentialsExtractor)
    }

    /// Creates a provider that reads a `UsernamePassword` from a KV v2 secret.
    ///
    /// # Parameters
    ///
    /// - `client` — an authenticated `VaultClient`
    /// - `mount` — the KV v2 mount path (e.g. `"secret"`)
    /// - `key_path` — path within the mount (e.g. `"services/db"`)
    /// - `username_field` — the field in the secret containing the username
    /// - `password_field` — the field in the secret containing the password
    ///
    /// The returned credential always has `expires_at() == None`.
    pub fn kv2_username_password(
        _client: Arc<VaultClient>,
        _mount: impl Into<String>,
        _key_path: impl Into<String>,
        _username_field: impl Into<String>,
        _password_field: impl Into<String>,
    ) -> Self {
        unimplemented!(
            "See docs/spec/interfaces/vault-adapter.md — kv2_username_password constructor"
        )
    }
}

impl VaultProvider<HmacSecret> {
    /// Creates a provider that reads an HMAC key from a KV v2 secret field.
    ///
    /// # Parameters
    ///
    /// - `client` — an authenticated `VaultClient`
    /// - `mount` — the KV v2 mount path (e.g. `"secret"`)
    /// - `key_path` — path within the mount (e.g. `"github/webhook-secret"`)
    /// - `field` — the field name within the secret (e.g. `"value"`)
    ///
    /// The returned credential always has `expires_at() == None`.
    pub fn kv2_secret(
        _client: Arc<VaultClient>,
        _mount: impl Into<String>,
        _key_path: impl Into<String>,
        _field: impl Into<String>,
    ) -> Self {
        unimplemented!("See docs/spec/interfaces/vault-adapter.md — kv2_secret constructor")
    }
}

impl VaultProvider<BearerToken> {
    /// Creates a provider that reads a bearer token from a KV v2 secret field.
    ///
    /// # Parameters
    ///
    /// - `client` — an authenticated `VaultClient`
    /// - `mount` — the KV v2 mount path (e.g. `"secret"`)
    /// - `key_path` — path within the mount (e.g. `"services/some-api-token"`)
    /// - `field` — the field name within the secret (e.g. `"token"`)
    ///
    /// The returned credential always has `expires_at() == None`.
    pub fn kv2_bearer_token(
        _client: Arc<VaultClient>,
        _mount: impl Into<String>,
        _key_path: impl Into<String>,
        _field: impl Into<String>,
    ) -> Self {
        unimplemented!("See docs/spec/interfaces/vault-adapter.md — kv2_bearer_token constructor")
    }
}

impl VaultProvider<TlsClientCertificate> {
    /// Creates a provider that requests a TLS client certificate from Vault's
    /// PKI secrets engine.
    ///
    /// # Parameters
    ///
    /// - `client` — an authenticated `VaultClient`
    /// - `mount` — the PKI mount path (e.g. `"pki"`)
    /// - `path` — the role path (e.g. `"issue/service-cert"`)
    ///
    /// The returned credential carries `expires_at` derived from the
    /// certificate's validity period as reported by Vault.
    pub fn pki_certificate(
        _client: Arc<VaultClient>,
        _mount: impl Into<String>,
        _path: impl Into<String>,
    ) -> Self {
        unimplemented!("See docs/spec/interfaces/vault-adapter.md — pki_certificate constructor")
    }
}

impl<C: Credential> CredentialProvider<C> for VaultProvider<C> {
    fn get(&self) -> BoxFuture<'_, Result<C, CredentialError>> {
        Box::pin(async move {
            // NOTE: This uses the KV v1 read API, which is correct for dynamic secrets
            // engines (RabbitMQ, database, SSH, AWS, Consul) and for KV v1 mounts.
            // KV v2 and PKI use different vaultrs APIs. Task 5.0 will add a
            // `fetch_strategy: FetchStrategy` field to VaultProvider<C> and dispatch
            // on it here, replacing this unconditional kv1 call.
            let response = vaultrs::kv1::get_raw(&*self.client, &self.mount, &self.path)
                .await
                .map_err(|err| map_vaultrs_error(err, &self.mount, &self.path))?;

            let lease_duration = lease_secs_from_raw(response.lease_duration);

            self.extractor.extract(&response.data, lease_duration)
        })
    }
}

// ---------------------------------------------------------------------------
// Error mapping — translates vaultrs errors to CredentialError
// ---------------------------------------------------------------------------

/// Converts a raw Vault `lease_duration` (i32 seconds) to `Option<u64>`.
///
/// Returns `None` when the duration is zero or negative — Vault uses zero to
/// indicate a static credential with no lease. Dynamic secrets engines return
/// a positive value for the lease duration in seconds.
pub(crate) fn lease_secs_from_raw(duration: i32) -> Option<u64> {
    if duration > 0 {
        Some(duration as u64)
    } else {
        None
    }
}

/// Reads a string field from a Vault response `data` object.
///
/// Returns `CredentialError::Backend("missing field: {field}")` if the field is
/// absent or not a JSON string.
fn extract_str_field<'a>(data: &'a serde_json::Value, field: &str) -> Result<&'a str, CredentialError> {
    data[field]
        .as_str()
        .ok_or_else(|| CredentialError::Backend(format!("missing field: {field}")))
}

/// Returns `true` if any error in the `std::error::Error` source chain contains
/// TLS-related keywords (case-insensitive).
fn tls_in_error_chain(err: &dyn std::error::Error) -> bool {
    let mut current: Option<&dyn std::error::Error> = Some(err);
    while let Some(e) = current {
        let msg = e.to_string().to_lowercase();
        // "tls" and "handshake" are transport-layer specific. "certificate" is
        // broader but in practice only appears in TLS-stack messages within the
        // reqwest/rustls error chain; no vaultrs 0.8.x RestClientError variant
        // produces a non-TLS message containing "certificate".
        if msg.contains("tls") || msg.contains("handshake") || msg.contains("certificate") {
            return true;
        }
        current = e.source();
    }
    false
}

/// Maps a [`vaultrs::error::ClientError`] to a [`CredentialError`] using the
/// vault error classification table from the spec.
///
/// `mount` and `path` are included in the [`CredentialError::Configuration`]
/// message produced for 404 responses so that operators can identify the
/// misconfigured path.
///
/// See: docs/spec/interfaces/vault-adapter.md — Error Mapping
pub(crate) fn map_vaultrs_error(
    error: vaultrs::error::ClientError,
    mount: &str,
    path: &str,
) -> CredentialError {
    use vaultrs::error::ClientError as VaultrsError;

    match error {
        VaultrsError::APIError { code, errors } => match code {
            403 => CredentialError::Backend("permission denied".to_string()),
            404 => {
                CredentialError::Configuration(format!("role or path not found: {mount}/{path}"))
            }
            400 if errors.iter().any(|e| e.to_lowercase().contains("lease")) => {
                CredentialError::Revoked
            }
            c if c >= 500 => {
                CredentialError::Backend(format!("vault server error: {c} {}", errors.join(", ")))
            }
            c => CredentialError::Backend(format!("vault error: {c} {}", errors.join(", "))),
        },
        VaultrsError::RestClientError { source } => {
            if tls_in_error_chain(&source) {
                CredentialError::Unreachable(format!("TLS error: {source}"))
            } else {
                CredentialError::Unreachable(source.to_string())
            }
        }
        VaultrsError::ResponseDataEmptyError => {
            CredentialError::Backend("unexpected response: missing data field".to_string())
        }
        VaultrsError::JsonParseError { source } => {
            CredentialError::Backend(format!("unexpected response: {source}"))
        }
        // File-path variants arise from VaultClient::new() (CA cert loading), not from
        // get_raw(). They cannot be produced by VaultProvider::get() under normal use, but
        // are handled explicitly to avoid leaking filesystem paths via the catch-all arm.
        VaultrsError::FileNotFoundError { .. }
        | VaultrsError::FileReadError { .. }
        | VaultrsError::ParseCertificateError { .. } => CredentialError::Configuration(
            "vault client configuration error: invalid CA certificate".to_string(),
        ),
        // All known vaultrs 0.8 ClientError variants are matched explicitly above.
        // This arm catches any variants added in future vaultrs versions. The Display
        // output of future variants is not under our control; if vaultrs 0.9+ adds a
        // variant whose Display leaks internal details, this arm will surface them in
        // CredentialError::Backend messages. Review this arm whenever vaultrs is bumped.
        other => CredentialError::Backend(format!("vault error: {other}")),
    }
}

#[cfg(test)]
#[path = "vault_tests.rs"]
mod tests;
