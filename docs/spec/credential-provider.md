# Specification: `credential-provider`

## Overview

`credential-provider` provides concrete implementations of the `CredentialProvider<C>` trait defined in `credential-provider-core`. Each implementation targets a specific secrets backend and is gated behind a Cargo feature flag, so applications compile in only the backends they need.

This crate is the *adapter layer* in hexagonal architecture terms. It knows how to talk to Vault, Azure, AWS, and environment variables, and translates their responses into the common credential types that the rest of the stack understands.

## Scope

This crate is responsible for:

- Implementing `CredentialProvider<C>` for each supported backend
- Managing the connection and authentication lifecycle for each backend
- Translating backend-specific error responses into `CredentialError`
- Providing the `env` backend for development and testing without an external service

This crate is **not** responsible for:

- Caching or renewal scheduling (that is `CachingCredentialProvider` in core)
- Deciding which credential type a consumer needs
- Revoking or rotating credentials on the backend side
- Any business logic beyond fetching what was asked for

## Feature Flags

```toml
[features]
default = ["env"]

# Environment variable provider — no external deps, always safe to include.
# This is also the recommended provider for local development and tests.
env = []

# HashiCorp Vault provider. Generic VaultProvider<C> supporting any secrets engine.
vault = ["dep:vaultrs", "dep:tokio"]

# Azure credential provider. Wraps azure-identity for managed identity,
# service principal, and workload identity flows.
azure = ["dep:azure-identity", "dep:azure-core"]

# AWS credential provider. Wraps aws-config for IAM role and environment
# credential chain resolution.
aws = ["dep:aws-config", "dep:aws-credential-types"]
```

The `env` feature requires no additional dependencies and is always compiled by default. Disabling it is permitted but unusual — it exists primarily as a convenience for embedded environments where even the standard environment API is not available.

## Dependencies

```toml
[dependencies]
credential-provider-core = { path = "../credential-provider-core" }
thiserror     = "1"
tokio         = { version = "1", features = ["sync", "time"], optional = true }

# vault feature
vaultrs       = { version = "0.7", optional = true, default-features = false,
                  features = ["rustls"] }

# azure feature
azure-identity = { version = "0.19", optional = true }
azure-core     = { version = "0.19", optional = true }

# aws feature
aws-config          = { version = "1", optional = true }
aws-credential-types = { version = "1", optional = true }
```

## Backends

### `env` — Environment Variable Provider

The environment provider reads credentials from environment variables at the time `get()` is called. It is the simplest possible implementation and serves two purposes: providing a development-time default that requires no external service, and acting as a test double in unit and integration tests.

#### Supported credential types

`EnvUsernamePasswordProvider` reads a username and password from a named pair of environment variables:

```rust
use credential_provider::env::EnvUsernamePasswordProvider;

let provider = EnvUsernamePasswordProvider::new(
    "RABBITMQ_USERNAME",
    "RABBITMQ_PASSWORD",
);
```

`EnvHmacSecretProvider` reads a hex- or base64-encoded secret from a single environment variable:

```rust
use credential_provider::env::EnvHmacSecretProvider;

let provider = EnvHmacSecretProvider::new("GITHUB_WEBHOOK_SECRET");
```

`EnvBearerTokenProvider` reads a token from an environment variable:

```rust
use credential_provider::env::EnvBearerTokenProvider;

let provider = EnvBearerTokenProvider::new("API_TOKEN");
```

#### Behaviour

The `env` provider re-reads the environment variable on every call to `get()`. This means that if the variable changes between calls (for example, via a secrets management sidecar that rewrites environment variables), the change is picked up on the next refresh cycle of `CachingCredentialProvider`. The returned credential always reports `is_valid() = true` and `expires_at() = None`.

If the required variable is not set or is empty, `get()` returns `CredentialError::Configuration`.

---

### `vault` — HashiCorp Vault Provider

The Vault provider uses `vaultrs` to fetch credentials from a running Vault instance. It is designed as a single generic `VaultProvider<C>` that works with **any** Vault secrets engine — KV v2, RabbitMQ, database, PKI, SSH, Consul, AWS, and any other engine that returns credential data. The provider is parameterized on the credential type `C` and configured with a response extraction strategy that knows how to map engine-specific JSON responses to the desired credential type.

The Vault provider does not manage Vault authentication itself. A `VaultClient` (from `vaultrs`) must be constructed and authenticated by the application before being passed to the provider. This separation means the application controls which auth method is used (AppRole, JWT/OIDC, Kubernetes, certificate, etc.) independently of which secrets engine is being accessed.

#### Generic design

`VaultProvider<C>` accepts:

- An authenticated `VaultClient`
- A mount path (e.g., `"secret"`, `"rabbitmq"`, `"database"`, `"pki"`)
- A request path within the mount (e.g., `"creds/queue-keeper"`, `"data/github/webhook"`, `"issue/service-cert"`)
- A response extractor that maps the Vault response JSON and lease metadata to `C`

Convenience constructors are provided for commonly used engine patterns. Adding support for a new engine does not require changes to the provider itself — only a new extractor.

#### Dynamic credentials engines (RabbitMQ, database, etc.)

Engines that generate credentials on demand with a lease duration. The `dynamic_credentials` convenience constructor returns a `VaultProvider<UsernamePassword>` — the default credential type for engines that issue username/password pairs (RabbitMQ, database, etc.). The returned credential carries `expires_at` derived from Vault's `lease_duration`.

```rust
use credential_provider::vault::VaultProvider;

// RabbitMQ dynamic credentials — returns VaultProvider<UsernamePassword>
let provider = VaultProvider::dynamic_credentials(
    vault_client.clone(),
    "rabbitmq",             // mount path
    "creds/queue-keeper",   // role path
);

// Database dynamic credentials (same pattern, different engine)
let db_provider = VaultProvider::dynamic_credentials(
    vault_client.clone(),
    "database",
    "creds/readonly",
);
```

The role at the given path must already exist in Vault and must have been granted appropriate permissions. The provider does not create or manage Vault roles — that is an operator responsibility handled via infrastructure-as-code or the Vault CLI during provisioning.

#### KV v2 engine

Reads a field from a KV v2 secret path. Useful for static secrets (HMAC keys, API tokens, webhook secrets) that are stored in Vault but not issued dynamically.

```rust
use credential_provider::vault::VaultProvider;

// Read an HMAC secret from KV v2
let hmac_provider = VaultProvider::kv2_secret(
    vault_client.clone(),
    "secret",                 // KV v2 mount path
    "github/webhook-secret",  // key path within the mount
    "value",                  // field name within the secret
);

// Read a bearer token from KV v2
let token_provider = VaultProvider::kv2_secret(
    vault_client.clone(),
    "secret",
    "services/some-api-token",
    "token",
);
```

Credentials from KV v2 always report `is_valid() = true` and `expires_at() = None`. Rotation is handled externally (Vault KV v2 versioning and policy) and picked up on the next `CachingCredentialProvider` refresh cycle.

#### PKI engine

Requests a certificate from Vault's PKI secrets engine. Returns a `TlsClientCertificate` with expiry derived from the certificate's validity period.

```rust
use credential_provider::vault::VaultProvider;

let cert_provider = VaultProvider::pki_certificate(
    vault_client.clone(),
    "pki",                    // PKI mount path
    "issue/service-cert",     // role path
);
```

#### Custom engines

For engines not covered by convenience constructors, supply a custom response extractor:

```rust
use credential_provider::vault::VaultProvider;

let provider = VaultProvider::with_extractor(
    vault_client.clone(),
    "custom-engine",
    "creds/my-role",
    my_custom_extractor,  // maps Vault response to credential type
);
```

#### Error mapping

Vault errors are mapped to `CredentialError` uniformly across all engines:

| Vault / vaultrs condition | `CredentialError` variant |
|---|---|
| HTTP 403 Forbidden | `Backend("permission denied")` |
| HTTP 404 Not Found (path missing) | `Configuration("role or path not found: ...")` |
| Connection refused / timeout | `Unreachable("...")` |
| Lease expired on re-read | `Revoked` |
| Malformed response | `Backend("unexpected response: ...")` |

---

### `azure` — Azure Identity Provider

The Azure provider wraps `azure-identity` to supply `BearerToken` credentials for Azure service authentication. It is the recommended provider when the service is running in an Azure environment and needs to authenticate to Azure-managed resources.

The provider delegates entirely to the `azure-identity` credential chain, which resolves credentials in the following order: managed identity (when running on Azure infrastructure), workload identity (Kubernetes), environment variables (`AZURE_CLIENT_ID`, etc.), and Azure CLI (for local development). This means no configuration change is required when moving between local development and Azure deployment.

```rust
use credential_provider::azure::AzureCredentialProvider;

let provider = AzureCredentialProvider::new(
    "https://servicebus.azure.net/.default",  // OAuth2 scope
);
```

The returned `BearerToken` carries the expiry from the Azure token response. `CachingCredentialProvider` will schedule renewal before expiry using its configured `refresh_before_expiry` window.

This provider is used by `queue-runtime`'s Azure Service Bus adapter when `AzureAuthMethod::ManagedIdentity` or `AzureAuthMethod::WorkloadIdentity` is selected, and is not typically constructed directly by application code.

---

### `aws` — AWS Credential Provider

The AWS provider wraps `aws-config` to supply credentials for AWS-managed resources. Like the Azure provider, it delegates to the standard AWS credential chain: IAM role (EC2/ECS/EKS), environment variables (`AWS_ACCESS_KEY_ID`, etc.), `~/.aws/credentials`, and the instance metadata service.

```rust
use credential_provider::aws::AwsCredentialProvider;

let provider = AwsCredentialProvider::new().await?;
```

The returned credential type is `AwsCredentials`, which is defined in this crate and implements `Credential`. It wraps the `aws-credential-types::Credentials` value and carries the token expiry when provided by the credential source.

This provider is used by `queue-runtime`'s AWS SQS adapter and is not typically constructed directly by application code.

## Testing

### Using the `env` backend as a test double

The recommended approach for unit and integration tests that exercise code depending on `credential-provider-core` is to use `EnvUsernamePasswordProvider` (or the appropriate `Env*` variant) with `temp_env` or direct environment variable manipulation:

```rust
#[tokio::test]
async fn test_queue_connection_uses_credentials() {
    // SAFETY: test is single-threaded; no concurrent env access.
    unsafe {
        std::env::set_var("TEST_QUEUE_USER", "testuser");
        std::env::set_var("TEST_QUEUE_PASS", "testpass");
    }

    let provider = EnvUsernamePasswordProvider::new("TEST_QUEUE_USER", "TEST_QUEUE_PASS");
    let caching = CachingCredentialProvider::new(provider, Duration::from_secs(60));

    let creds = caching.get().await.expect("should return credentials");
    assert_eq!(creds.username, "testuser");
}
```

### Using a `MockCredentialProvider`

For tests that need to control credential validity and expiry precisely, `MockCredentialProvider` is defined in `credential-provider-core` (available under `#[cfg(test)]` for that crate's own tests) and re-exported by this crate behind the `test-support` feature for use by downstream consumers:

```rust
use credential_provider::test_support::MockCredentialProvider;

let provider = MockCredentialProvider::<UsernamePassword>::new()
    .returning(Ok(UsernamePassword {
        username: "mock".to_string(),
        password: SecretString::new("secret".to_string()),
        expires_at: Some(Instant::now() + Duration::from_secs(300)),
    }));
```

The `test-support` feature must never be enabled in production builds. It is gated on `cfg(any(test, feature = "test-support"))` and will emit a compile warning if enabled outside a test profile.

## Recommended Configuration Patterns

### Self-hosted deployment (Vault)

Services running on self-hosted infrastructure authenticate to Vault using an appropriate auth method (AppRole for service accounts, JWT/OIDC for CI pipelines, Kubernetes auth for K8s workloads, etc.). The `VaultClient` is constructed at startup using provisioned credentials, then passed to the relevant providers:

```rust
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::auth::approle;
use credential_provider::vault::VaultProvider;
use credential_provider_core::CachingCredentialProvider;

// Authenticate to Vault via AppRole
let vault = VaultClient::new(
    VaultClientSettingsBuilder::default()
        .address(std::env::var("VAULT_ADDR")?)
        .build()?
)?;
approle::login(&vault, "auth/approle/login", &role_id, &secret_id).await?;

// Construct providers
let queue_creds = Arc::new(CachingCredentialProvider::new(
    VaultProvider::dynamic_credentials(vault.clone(), "rabbitmq", "creds/queue-keeper"),
    Duration::from_secs(60),
));

let webhook_secret = Arc::new(CachingCredentialProvider::new(
    VaultProvider::kv2_secret(vault.clone(), "secret", "github/webhook", "value"),
    Duration::from_secs(300),
));
```

### Local development

```toml
# .env (never committed)
RABBITMQ_USERNAME=dev
RABBITMQ_PASSWORD=dev
GITHUB_WEBHOOK_SECRET=localsecret
```

```rust
use credential_provider::env::{EnvUsernamePasswordProvider, EnvHmacSecretProvider};

let queue_creds = Arc::new(CachingCredentialProvider::new(
    EnvUsernamePasswordProvider::new("RABBITMQ_USERNAME", "RABBITMQ_PASSWORD"),
    Duration::from_secs(300),
));

let webhook_secret = Arc::new(CachingCredentialProvider::new(
    EnvHmacSecretProvider::new("GITHUB_WEBHOOK_SECRET"),
    Duration::from_secs(300),
));
```

The application code that wires up `queue-runtime` is identical in both cases — only the provider construction changes. This is the intended property.
