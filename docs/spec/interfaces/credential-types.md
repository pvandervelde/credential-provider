# Credential Types

**Architectural layer:** Business logic (`credential-provider-core`)
**Source file:** `credential-provider-core/src/credentials.rs`

The four concrete credential value types defined in the core crate. Each is a
value object (immutable data carrier) that implements the `Credential` trait.

---

## Common Rules

- All types implement `Send + Sync + Clone + 'static` (required by `Credential`)
- Fields containing sensitive data use `secrecy::SecretString` or `secrecy::SecretVec<u8>`
  — these are zeroed from memory on drop
- `Debug` implementations redact all secret fields (outputs `"[REDACTED]"`)
- No `Display` implementation should render secret material
- Validity is purely time-based: compare `expires_at` against `Instant::now()`

---

## `UsernamePassword`

### Location

`credential-provider-core/src/credentials.rs`

### Purpose

Username and password credentials. Used for queue brokers (RabbitMQ, NATS),
databases, and any service that authenticates with a username/password pair.

### Fields

| Field | Type | Secret | Description |
|---|---|---|---|
| `username` | `String` | No | Plaintext username |
| `password` | `SecretString` | Yes | Password, zeroed on drop |
| `expires_at` | `Option<Instant>` | No | Expiry, if known |

### Constructor

```rust
pub fn new(
    username: impl Into<String>,
    password: SecretString,
    expires_at: Option<Instant>,
) -> Self
```

### `Credential` implementation

- `is_valid()`: `expires_at.map_or(true, |e| Instant::now() < e)`
- `expires_at()`: returns the stored `expires_at` field

### Clone behaviour

`Clone` is derived. Cloning a `UsernamePassword` produces a new value with an
independent copy of the `SecretString` password (the clone owns its own memory).

### Debug output

```
UsernamePassword { username: "alice", password: "[REDACTED]", expires_at: Some(...) }
```

---

## `BearerToken`

### Location

`credential-provider-core/src/credentials.rs`

### Purpose

An opaque token for HTTP `Authorization: Bearer` headers. Used for API
authentication where a short-lived token is issued by an identity provider.

### Fields

| Field | Type | Secret | Description |
|---|---|---|---|
| `token` | `SecretString` | Yes | Token value, zeroed on drop |
| `expires_at` | `Option<Instant>` | No | Expiry from token issuer, if known |

### Constructor

```rust
pub fn new(token: SecretString, expires_at: Option<Instant>) -> Self
```

### `Credential` implementation

- `is_valid()`: `expires_at.map_or(true, |e| Instant::now() < e)`
- `expires_at()`: returns the stored `expires_at` field

### Debug output

```
BearerToken { token: "[REDACTED]", expires_at: Some(...) }
```

---

## `HmacSecret`

### Location

`credential-provider-core/src/credentials.rs`

### Purpose

A symmetric HMAC key for webhook signature verification. The primary use case
is GitHub webhook payload validation (`X-Hub-Signature-256`).

### Fields

| Field | Type | Secret | Description |
|---|---|---|---|
| `key` | `SecretVec<u8>` | Yes | Raw key bytes, zeroed on drop |

### Constructor

```rust
pub fn new(key: SecretVec<u8>) -> Self
```

### `Credential` implementation

- `is_valid()`: **always returns `true`** — HMAC keys do not expire
- `expires_at()`: **always returns `None`**

HMAC key rotation is handled externally on a policy schedule. The caching layer
will fetch a fresh value only on the first call and then cache it indefinitely
(`is_valid()` never triggers a refresh).

### Clone behaviour

`Clone` is implemented manually. Cloning produces a new `SecretVec<u8>` by
reading the bytes via `ExposeSecret` and allocating a new zeroing vector.

### Debug output

```
HmacSecret { key: "[REDACTED]" }
```

### Consumer responsibility

The consumer (e.g., `webhook-handler`) must use **constant-time comparison**
when validating HMAC digests. The provider only stores and delivers the key —
it does not perform HMAC operations.

---

## `TlsClientCertificate`

### Location

`credential-provider-core/src/credentials.rs`

### Purpose

A certificate + private key pair for mutual TLS (mTLS) client authentication.
Used when connecting to services that require client certificate verification,
such as Vault-issued PKI certificates.

### Fields

| Field | Type | Secret | Description |
|---|---|---|---|
| `certificate_pem` | `SecretVec<u8>` | Yes | PEM-encoded certificate, zeroed on drop |
| `private_key_pem` | `SecretVec<u8>` | Yes | PEM-encoded private key, zeroed on drop |
| `expires_at` | `Option<Instant>` | No | Certificate validity end, if known |

### Constructor

```rust
pub fn new(
    certificate_pem: SecretVec<u8>,
    private_key_pem: SecretVec<u8>,
    expires_at: Option<Instant>,
) -> Self
```

### `Credential` implementation

- `is_valid()`: `expires_at.map_or(true, |e| Instant::now() < e)`
- `expires_at()`: returns the stored `expires_at` field

For Vault PKI-issued certificates, the expiry is derived from the certificate's
validity period as reported in the Vault response.

### Clone behaviour

`Clone` is implemented manually (same as `HmacSecret`). Both PEM fields are
cloned into new `SecretVec<u8>` allocations via `ExposeSecret`.

### Debug output

```
TlsClientCertificate { certificate_pem: "[REDACTED]", private_key_pem: "[REDACTED]", expires_at: Some(...) }
```
