// SPEC: docs/spec/interfaces/vault-adapter.md
//
// This module is gated behind the `vault` feature flag.
// It requires the `vaultrs` crate with the `rustls` feature.
#![allow(dead_code, unused_variables)]

use std::sync::Arc;

use credential_provider_core::{
    BearerToken, BoxFuture, Credential, CredentialError, CredentialProvider, HmacSecret,
    TlsClientCertificate, UsernamePassword,
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
/// [ADR-004]: docs/adr/ADR-004-external-vault-authentication.md
pub struct VaultProvider<C: Credential> {
    client: Arc<VaultClient>,
    mount: String,
    path: String,
    extractor: Arc<dyn VaultExtractor<C>>,
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
        unimplemented!(
            "See docs/spec/interfaces/vault-adapter.md — dynamic_credentials constructor"
        )
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
        client: Arc<VaultClient>,
        mount: impl Into<String>,
        key_path: impl Into<String>,
        username_field: impl Into<String>,
        password_field: impl Into<String>,
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
        client: Arc<VaultClient>,
        mount: impl Into<String>,
        key_path: impl Into<String>,
        field: impl Into<String>,
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
        client: Arc<VaultClient>,
        mount: impl Into<String>,
        key_path: impl Into<String>,
        field: impl Into<String>,
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
        client: Arc<VaultClient>,
        mount: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        unimplemented!("See docs/spec/interfaces/vault-adapter.md — pki_certificate constructor")
    }
}

impl<C: Credential> CredentialProvider<C> for VaultProvider<C> {
    fn get(&self) -> BoxFuture<'_, Result<C, CredentialError>> {
        Box::pin(async move { unimplemented!("See docs/spec/interfaces/vault-adapter.md") })
    }
}
