# Specification: `credential-provider-core`

## Overview

`credential-provider-core` defines the shared abstraction for credential management. It provides the `CredentialProvider` trait, common credential types, and a caching wrapper — and nothing else. The crate has no dependency on any secrets backend and is deliberately kept minimal so that any library crate in the stack can depend on it without inheriting heavyweight transitive dependencies.

This crate is the *port definition* in hexagonal architecture terms. It describes what credential management looks like from the consumer's perspective, without prescribing how credentials are sourced.

## Scope

This crate is responsible for:

- Defining the `CredentialProvider<C>` trait
- Defining the `Credential` trait and the common concrete credential types
- Providing the `CachingCredentialProvider<C, P>` wrapper that handles transparent refresh
- Providing the `CredentialError` error type
- Re-exporting `secrecy` primitives so consumers do not need a direct dependency

This crate is **not** responsible for:

- Connecting to any secrets backend (Vault, Azure, AWS, etc.)
- Storing or persisting credentials
- Authentication flows
- Rotation policy decisions

## Dependencies

```toml
[dependencies]
secrecy     = { version = "0.8", features = ["serde"] }
thiserror   = "1"
tokio       = { version = "1", features = ["sync", "time"] }
```

No other dependencies are permitted. Any proposal to add a dependency to this crate requires an ADR and explicit justification that the crate cannot instead live in `credential-provider`.

## Core Traits

### `Credential`

`Credential` is implemented by every type that represents a set of credentials. It provides validity inspection so that the caching layer can determine whether a cached value needs refreshing without needing to know the structure of the credential itself.

```rust
pub trait Credential: Send + Sync + Clone + 'static {
    /// Returns true if these credentials are currently usable.
    /// A credential that has no known expiry is always considered valid.
    fn is_valid(&self) -> bool;

    /// Returns the instant at which these credentials will no longer be valid,
    /// if known. None means the credential does not expire or the expiry is
    /// not communicated by the backend.
    fn expires_at(&self) -> Option<std::time::Instant>;
}
```

### `CredentialProvider`

`CredentialProvider<C>` is the central trait. Implementations fetch credentials from a specific backend. They are not responsible for caching — that concern is handled by `CachingCredentialProvider`.

```rust
pub trait CredentialProvider<C: Credential>: Send + Sync + 'static {
    /// Fetch a fresh set of credentials from the backing store.
    ///
    /// Implementations must not cache results internally. Caching is
    /// the responsibility of `CachingCredentialProvider`.
    ///
    /// This method may be called concurrently. Implementations must be
    /// safe to call from multiple tasks simultaneously.
    async fn get(&self) -> Result<C, CredentialError>;
}
```

Callers that want transparent caching should wrap their provider in `CachingCredentialProvider` rather than calling `get()` directly on a raw provider.

## Credential Types

The following concrete types are defined in this crate because they are used across multiple contexts (queue brokers, databases, webhooks) and do not belong to any single domain.

### `UsernamePassword`

Used wherever a service authenticates with a username and password — RabbitMQ, NATS accounts, database connections, and similar.

```rust
#[derive(Clone)]
pub struct UsernamePassword {
    pub username: String,
    pub password: SecretString,
    pub expires_at: Option<std::time::Instant>,
}
```

### `BearerToken`

Used for HTTP API authentication where a short-lived opaque token is presented in an `Authorization` header.

```rust
#[derive(Clone)]
pub struct BearerToken {
    pub token: SecretString,
    pub expires_at: Option<std::time::Instant>,
}
```

### `HmacSecret`

Used for symmetric HMAC validation — GitHub webhook signature verification being the primary use case in this stack.

```rust
#[derive(Clone)]
pub struct HmacSecret {
    pub key: SecretVec<u8>,
}
```

`HmacSecret` implements `Credential` with `is_valid()` always returning `true` and `expires_at()` always returning `None`, since HMAC keys are rotated externally on a policy schedule rather than expiring automatically.

### `TlsClientCertificate`

Used when mutual TLS is required — for example, connecting to a service over a Vault-issued PKI certificate.

```rust
#[derive(Clone)]
pub struct TlsClientCertificate {
    pub certificate_pem: SecretVec<u8>,
    pub private_key_pem: SecretVec<u8>,
    pub expires_at: Option<std::time::Instant>,
}
```

## Caching

### `CachingCredentialProvider`

`CachingCredentialProvider<C, P>` wraps any `CredentialProvider<C>` and adds transparent credential caching with automatic refresh. Consumers use this wrapper rather than calling a raw provider, and they call `get()` on the wrapper exactly as they would on the raw provider. The caching lifecycle is entirely internal.

```rust
pub struct CachingCredentialProvider<C, P>
where
    C: Credential,
    P: CredentialProvider<C>,
{
    inner: P,
    cached: RwLock<Option<C>>,
    refresh_before_expiry: Duration,
}

impl<C, P> CachingCredentialProvider<C, P>
where
    C: Credential,
    P: CredentialProvider<C>,
{
    /// Create a new caching provider.
    ///
    /// `refresh_before_expiry` controls how early a renewal is triggered
    /// before the cached credential expires. A value of 30 seconds means
    /// the cache will fetch new credentials when the remaining validity
    /// window drops below 30 seconds. Defaults to 60 seconds if not
    /// specified.
    pub fn new(inner: P, refresh_before_expiry: Duration) -> Self { ... }

    /// Returns cached credentials if still valid, otherwise fetches fresh
    /// credentials from the inner provider and updates the cache.
    ///
    /// Concurrent calls during a refresh are serialised: only one fetch
    /// is in flight at a time, and all waiters receive the result of that
    /// single fetch.
    pub async fn get(&self) -> Result<C, CredentialError> { ... }
}
```

The caching logic applies the following rules in order:

1. If the cache is empty, fetch immediately and populate.
2. If the cache holds a credential that `is_valid()` and will not expire within `refresh_before_expiry`, return it directly.
3. If the cached credential is within the refresh window or has already expired, fetch fresh credentials. On success, update the cache and return the new value. On failure, return the last known valid credential if one exists, or propagate the error if the cache is empty.

Rule 3's fallback behaviour (returning a stale-but-still-valid credential on fetch failure) is intentional. A transient Vault outage should not immediately cause application failures if credentials are still technically valid.

## Error Type

```rust
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// The backing store returned an error response.
    #[error("credential backend error: {0}")]
    Backend(String),

    /// The backing store was unreachable.
    #[error("credential backend unreachable: {0}")]
    Unreachable(String),

    /// The provided configuration is invalid.
    #[error("invalid credential configuration: {0}")]
    Configuration(String),

    /// No credential is available and no cached value exists.
    #[error("no credential available")]
    Unavailable,

    /// The credential was explicitly revoked before expiry.
    #[error("credential revoked")]
    Revoked,
}
```

## Usage Pattern

### In a library crate

A library crate that needs credentials accepts a `CredentialProvider<C>` as a configuration value:

```rust
use credential_provider_core::{CredentialProvider, UsernamePassword};
use std::sync::Arc;

pub struct RabbitMqConfig {
    pub uri: String,
    // Static credentials for simple deployments
    pub credentials: Option<UsernamePassword>,
    // Dynamic provider takes precedence when present
    pub credential_provider: Option<Arc<dyn CredentialProvider<UsernamePassword>>>,
}
```

The library calls `provider.get().await?` when it needs credentials — on initial connection, on reconnection, and never otherwise. It does not track leases, schedule renewals, or manage any Vault-specific state.

### In an application

An application constructs a concrete provider from `credential-provider`, wraps it in `CachingCredentialProvider`, and passes it into the library:

```rust
use credential_provider::vault::VaultUsernamePasswordProvider;
use credential_provider_core::CachingCredentialProvider;
use std::sync::Arc;

let raw_provider = VaultUsernamePasswordProvider::new(vault_client, "rabbitmq/creds/queue-keeper");
let provider = Arc::new(CachingCredentialProvider::new(raw_provider, Duration::from_secs(60)));

let config = RabbitMqConfig {
    uri: "amqp://rabbitmq.example.com:5672".to_string(),
    credentials: None,
    credential_provider: Some(provider),
};
```

## Compatibility and Stability

`credential-provider-core` follows semantic versioning. The `CredentialProvider<C>` and `Credential` traits are considered stable public API from v0.1.0. Breaking changes to either trait require a major version bump.

The concrete credential types (`UsernamePassword`, `BearerToken`, `HmacSecret`, `TlsClientCertificate`) are also stable. New fields must be added in a backwards-compatible way (using `Option<T>` with sensible defaults, or via the builder pattern).

`CredentialError` variants may be added in minor releases. Match arms against `CredentialError` should include a wildcard arm to remain forward-compatible.
