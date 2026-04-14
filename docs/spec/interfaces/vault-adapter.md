# Vault Adapter

**Architectural layer:** Adapters (`credential-provider`)
**Source file:** `credential-provider/src/vault.rs`
**Feature flag:** `vault`
**External dependencies:** `vaultrs 0.7` (rustls feature), `serde_json 1`, `tokio 1`
**ADRs:** [ADR-004](../../adr/ADR-004-external-vault-authentication.md)

The Vault adapter provides a single generic `VaultProvider<C>` that reads from
any HashiCorp Vault secrets engine and translates responses into the appropriate
credential type. A `VaultExtractor<C>` strategy handles the engine-specific
response mapping.

---

## Authentication Contract (ADR-004)

`VaultProvider<C>` does **not** manage Vault authentication. The application must:

1. Construct a `VaultClient` with the correct Vault address
2. Authenticate via the appropriate auth method (AppRole, JWT/OIDC, Kubernetes, etc.)
3. Pass the authenticated `Arc<VaultClient>` to the provider constructor

If the Vault token expires between refreshes, `get()` calls will fail and map
to the appropriate `CredentialError` variant. The `CachingCredentialProvider`
stale fallback provides a grace period (see [ADR-003]).

---

## `VaultExtractor<C>` (trait)

### Location

`credential-provider/src/vault.rs`

### Purpose

Strategy for translating a Vault secrets engine response into a credential.
Decouples response parsing from fetch logic, allowing `VaultProvider<C>` to
support any engine without modification.

### Signature

```rust
pub trait VaultExtractor<C: Credential>: Send + Sync + 'static {
    fn extract(
        &self,
        data: &serde_json::Value,
        lease_duration_secs: Option<u64>,
    ) -> Result<C, CredentialError>;
}
```

### Parameters

- `data` — the `data` field from the Vault API JSON response (deserialized)
- `lease_duration_secs` — the `lease_duration` from the response, if present.
  Dynamic engines (RabbitMQ, database, etc.) return a non-zero duration; static
  engines (KV v2 without TTL) return `None` or zero.

### Contract

- Must return `CredentialError::Backend` if a required field is missing or has
  an unexpected type in `data`
- Must never return backend-specific error types
- Must be a pure function — no I/O or side effects
- `expires_at` on the returned credential should be derived from
  `lease_duration_secs` if present: `Instant::now() + Duration::from_secs(lease_duration_secs)`

### Implementing a custom extractor

```rust
use serde_json::Value;
use credential_provider_core::{UsernamePassword, CredentialError};
use credential_provider::vault::VaultExtractor;
use secrecy::SecretString;
use std::time::{Duration, Instant};

struct MyEngineExtractor;

impl VaultExtractor<UsernamePassword> for MyEngineExtractor {
    fn extract(
        &self,
        data: &Value,
        lease_duration_secs: Option<u64>,
    ) -> Result<UsernamePassword, CredentialError> {
        let username = data["username"]
            .as_str()
            .ok_or_else(|| CredentialError::Backend("missing field: username".into()))?
            .to_string();
        let password = data["password"]
            .as_str()
            .ok_or_else(|| CredentialError::Backend("missing field: password".into()))?;
        let expires_at = lease_duration_secs
            .filter(|&d| d > 0)
            .map(|d| Instant::now() + Duration::from_secs(d));
        Ok(UsernamePassword::new(username, SecretString::new(password.to_string()), expires_at))
    }
}
```

---

## `VaultProvider<C>` (struct)

### Location

`credential-provider/src/vault.rs`

### Purpose

A generic `CredentialProvider<C>` that reads from any Vault secrets engine
path and uses a `VaultExtractor<C>` to translate the response.

### Fields (private)

| Field | Type | Description |
|---|---|---|
| `client` | `Arc<VaultClient>` | Authenticated Vault client |
| `mount` | `String` | Secrets engine mount path |
| `path` | `String` | Request path within the mount |
| `extractor` | `Arc<dyn VaultExtractor<C>>` | Response translation strategy |

### `get()` Implementation

1. Call `vaultrs` to read the secret at `{mount}/{path}`
2. Extract `data` and `lease_duration` from the response
3. Call `extractor.extract(data, lease_duration_secs)`
4. Return the result, mapping any `vaultrs` errors via the [Error Mapping](#error-mapping) table

### Error Mapping

| Vault / vaultrs condition | `CredentialError` variant |
|---|---|
| HTTP 403 Forbidden | `Backend("permission denied")` |
| HTTP 404 Not Found (path or role missing) | `Configuration("role or path not found: {mount}/{path}")` |
| Connection refused / TCP timeout | `Unreachable("{addr}: {detail}")` |
| TLS handshake failure | `Unreachable("TLS error: {detail}")` |
| Lease explicitly revoked on re-read | `Revoked` |
| Response missing `data` field | `Backend("unexpected response: missing data field")` |
| Response `data` malformed | `Backend("unexpected response: {detail}")` |
| HTTP 5xx from Vault | `Backend("vault server error: {status} {detail}")` |

---

## Convenience Constructors

### `VaultProvider::with_extractor()`

```rust
pub fn with_extractor(
    client: Arc<VaultClient>,
    mount: impl Into<String>,
    path: impl Into<String>,
    extractor: impl VaultExtractor<C> + 'static,
) -> Self
```

Generic constructor. Use when no convenience constructor covers the target engine.

---

### `VaultProvider::dynamic_credentials()` → `VaultProvider<UsernamePassword>`

```rust
pub fn dynamic_credentials(
    client: Arc<VaultClient>,
    mount: impl Into<String>,
    path: impl Into<String>,
) -> VaultProvider<UsernamePassword>
```

For dynamic credential engines (RabbitMQ, database, AWS, SSH, Consul) that
generate username/password pairs with a lease duration.

**Extractor behaviour:**

- Reads `username` and `password` fields from the response `data`
- Sets `expires_at` from `lease_duration` (if non-zero)

**Use for:** RabbitMQ (`rabbitmq`), database (`database`), generic dynamic engines.

```rust
let provider = VaultProvider::dynamic_credentials(
    vault_client.clone(),
    "rabbitmq",
    "creds/queue-keeper",
);
```

---

### `VaultProvider::kv2_username_password()` → `VaultProvider<UsernamePassword>`

```rust
pub fn kv2_username_password(
    client: Arc<VaultClient>,
    mount: impl Into<String>,
    key_path: impl Into<String>,
    username_field: impl Into<String>,
    password_field: impl Into<String>,
) -> VaultProvider<UsernamePassword>
```

Reads a username and password from named fields in a KV v2 secret. The returned
credential always has `expires_at() == None`.

---

### `VaultProvider::kv2_secret()` → `VaultProvider<HmacSecret>`

```rust
pub fn kv2_secret(
    client: Arc<VaultClient>,
    mount: impl Into<String>,
    key_path: impl Into<String>,
    field: impl Into<String>,
) -> VaultProvider<HmacSecret>
```

Reads an HMAC key from a named field in a KV v2 secret. The field value is
treated as raw bytes (UTF-8 encoded string in the secret). `expires_at() == None`.

```rust
let provider = VaultProvider::kv2_secret(
    vault_client.clone(),
    "secret",
    "github/webhook-secret",
    "value",
);
```

---

### `VaultProvider::kv2_bearer_token()` → `VaultProvider<BearerToken>`

```rust
pub fn kv2_bearer_token(
    client: Arc<VaultClient>,
    mount: impl Into<String>,
    key_path: impl Into<String>,
    field: impl Into<String>,
) -> VaultProvider<BearerToken>
```

Reads a bearer token from a named field in a KV v2 secret. `expires_at() == None`.

---

### `VaultProvider::pki_certificate()` → `VaultProvider<TlsClientCertificate>`

```rust
pub fn pki_certificate(
    client: Arc<VaultClient>,
    mount: impl Into<String>,
    path: impl Into<String>,
) -> VaultProvider<TlsClientCertificate>
```

Issues a TLS client certificate from Vault's PKI secrets engine.

**Extractor behaviour:**

- Reads `certificate` (PEM) and `private_key` (PEM) from the response
- Sets `expires_at` from the certificate's `expiration` field in the response
  (a Unix timestamp) — **not** from `lease_duration`

```rust
let provider = VaultProvider::pki_certificate(
    vault_client.clone(),
    "pki",
    "issue/service-cert",
);
```

---

## TLS Requirement

The `vaultrs` dependency must always be compiled with the `rustls` feature.
Vault communication in production must use HTTPS. Never configure `vaultrs` with
`native-tls` or disable TLS. See [security.md S-4].

[security.md S-4]: ../../security.md#s-4-network-interception-of-vault-communications
