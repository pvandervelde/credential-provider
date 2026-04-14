# Shared Types Registry

A catalogue of every reusable type, trait, and pattern in the workspace.
Updated as implementation proceeds. Coders should consult this before creating
new types to avoid duplication.

---

## Core Abstractions

### `Credential` (trait)

- **Crate:** `credential-provider-core`
- **Location:** `credential-provider-core/src/lib.rs`
- **Spec:** [shared-types.md](interfaces/shared-types.md#credential-trait)
- **Bounds:** `Send + Sync + Clone + 'static`
- **Methods:** `is_valid() -> bool`, `expires_at() -> Option<Instant>`
- **Usage:** Implement for any new credential type

### `CredentialProvider<C>` (trait)

- **Crate:** `credential-provider-core`
- **Location:** `credential-provider-core/src/provider.rs`
- **Spec:** [shared-types.md](interfaces/shared-types.md#credentialproviderc-trait)
- **Bounds:** `Send + Sync + 'static`
- **Method:** `get(&self) -> impl Future<Output = Result<C, CredentialError>> + Send`
- **Usage:** Implement for each new backend adapter

### `CredentialError` (enum)

- **Crate:** `credential-provider-core`
- **Location:** `credential-provider-core/src/error.rs`
- **Spec:** [shared-types.md](interfaces/shared-types.md#credentialerror-enum)
- **Derives:** `Debug`, `Clone`, `thiserror::Error`
- **Variants:** `Backend(String)`, `Unreachable(String)`, `Configuration(String)`, `Unavailable`, `Revoked`
- **Usage:** The only error type that crosses the provider boundary

---

## Credential Types

### `UsernamePassword`

- **Crate:** `credential-provider-core`
- **Location:** `credential-provider-core/src/credentials.rs`
- **Spec:** [credential-types.md](interfaces/credential-types.md#usernamepassword)
- **Fields:** `username: String`, `password: SecretString`, `expires_at: Option<Instant>`
- **Validity:** Time-based expiry
- **Usage:** Queue brokers (RabbitMQ, NATS), databases, generic username/password auth

### `BearerToken`

- **Crate:** `credential-provider-core`
- **Location:** `credential-provider-core/src/credentials.rs`
- **Spec:** [credential-types.md](interfaces/credential-types.md#bearertoken)
- **Fields:** `token: SecretString`, `expires_at: Option<Instant>`
- **Validity:** Time-based expiry
- **Usage:** HTTP API authentication, Azure AD tokens

### `HmacSecret`

- **Crate:** `credential-provider-core`
- **Location:** `credential-provider-core/src/credentials.rs`
- **Spec:** [credential-types.md](interfaces/credential-types.md#hmacsecret)
- **Fields:** `key: SecretVec<u8>`
- **Validity:** Always valid (`is_valid() = true`, `expires_at() = None`)
- **Usage:** Webhook signature verification (GitHub `X-Hub-Signature-256`)

### `TlsClientCertificate`

- **Crate:** `credential-provider-core`
- **Location:** `credential-provider-core/src/credentials.rs`
- **Spec:** [credential-types.md](interfaces/credential-types.md#tlsclientcertificate)
- **Fields:** `certificate_pem: SecretVec<u8>`, `private_key_pem: SecretVec<u8>`, `expires_at: Option<Instant>`
- **Validity:** Time-based expiry (from certificate validity period)
- **Usage:** Mutual TLS client authentication (Vault PKI engine)

### `AwsCredentials`

- **Crate:** `credential-provider`
- **Location:** `credential-provider/src/aws.rs`
- **Spec:** [aws-adapter.md](interfaces/aws-adapter.md#awscredentials)
- **Fields:** `inner: aws_credential_types::Credentials`, `expires_at: Option<Instant>`
- **Validity:** Time-based expiry (from STS token), or always valid (long-lived access keys)
- **Usage:** AWS SDK client construction

---

## Caching Infrastructure

### `CachingCredentialProvider<C, P>`

- **Crate:** `credential-provider-core`
- **Location:** `credential-provider-core/src/caching.rs`
- **Spec:** [caching.md](interfaces/caching.md)
- **Type params:** `C: Credential`, `P: CredentialProvider<C>`
- **Purpose:** Wraps any provider with transparent caching, refresh, and stale fallback
- **Usage:** Always wrap raw providers in this before injecting into consumer libraries

---

## Adapter Types

### `VaultExtractor<C>` (trait)

- **Crate:** `credential-provider`
- **Location:** `credential-provider/src/vault.rs`
- **Spec:** [vault-adapter.md](interfaces/vault-adapter.md#vaultextractorc-trait)
- **Feature:** `vault`
- **Purpose:** Strategy for translating Vault response JSON into a `C: Credential`

### `VaultProvider<C>`

- **Crate:** `credential-provider`
- **Location:** `credential-provider/src/vault.rs`
- **Spec:** [vault-adapter.md](interfaces/vault-adapter.md#vaultproviderc-struct)
- **Feature:** `vault`
- **Purpose:** Generic Vault secrets engine adapter

### `EnvUsernamePasswordProvider`

- **Crate:** `credential-provider`
- **Location:** `credential-provider/src/env.rs`
- **Spec:** [env-adapters.md](interfaces/env-adapters.md#envusernamepasswordprovider)
- **Feature:** `env` (default)

### `EnvHmacSecretProvider`

- **Crate:** `credential-provider`
- **Location:** `credential-provider/src/env.rs`
- **Spec:** [env-adapters.md](interfaces/env-adapters.md#envhmacsecretprovider)
- **Feature:** `env` (default)

### `EnvBearerTokenProvider`

- **Crate:** `credential-provider`
- **Location:** `credential-provider/src/env.rs`
- **Spec:** [env-adapters.md](interfaces/env-adapters.md#envbearertokenprovider)
- **Feature:** `env` (default)

### `AzureCredentialProvider`

- **Crate:** `credential-provider`
- **Location:** `credential-provider/src/azure.rs`
- **Spec:** [azure-adapter.md](interfaces/azure-adapter.md)
- **Feature:** `azure`

### `AwsCredentialProvider`

- **Crate:** `credential-provider`
- **Location:** `credential-provider/src/aws.rs`
- **Spec:** [aws-adapter.md](interfaces/aws-adapter.md#awscredentialprovider)
- **Feature:** `aws`

---

## Test Support

### `MockCredentialProvider<C>`

- **Crate:** `credential-provider-core`
- **Location:** `credential-provider-core/src/mock.rs`
- **Re-exported:** `credential-provider::test_support::MockCredentialProvider`
- **Spec:** [test-support.md](interfaces/test-support.md)
- **Gate:** `cfg(any(test, feature = "test-support"))`
- **Purpose:** Configurable test double; tracks call count for assertions

---

## Secrecy Re-exports

These are re-exported from `credential-provider-core` so consumers do not need
a direct dependency on `secrecy`:

| Re-export | Original |
|---|---|
| `credential_provider_core::SecretString` | `secrecy::SecretString` |
| `credential_provider_core::SecretVec` | `secrecy::SecretVec` |
| `credential_provider_core::ExposeSecret` | `secrecy::ExposeSecret` |

---

## Patterns

### Secret field access

Use `ExposeSecret::expose_secret()` to access raw value only when strictly
necessary (e.g., passing to a backend SDK). Never store the exposed value in a
`String` or log it.

### Error propagation

Use `?` to propagate `CredentialError`. Map backend-specific errors at the
adapter boundary — never let SDK error types escape into callers.

### Provider injection

Consumer libraries accept `Arc<dyn CredentialProvider<C>>`. Applications
construct concrete providers, wrap in `CachingCredentialProvider`, then wrap in
`Arc` before injecting.

### Dependency resolution order

1. Application constructs `SomeConcreteProvider`
2. Wraps: `let caching = CachingCredentialProvider::new(provider, refresh_window)`
3. Wraps: `let shared = Arc::new(caching)`
4. Injects `shared` into consumer library configuration
