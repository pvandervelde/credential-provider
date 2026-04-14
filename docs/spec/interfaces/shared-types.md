# Shared Types

**Architectural layer:** Business logic (`credential-provider-core`)
**Source file:** `credential-provider-core/src/lib.rs`, `error.rs`, `provider.rs`

This document specifies the three foundational abstractions that every other
component in the workspace depends on.

---

## `Credential` (trait)

### Location

`credential-provider-core/src/lib.rs`

### Purpose

Contract that every credential type must satisfy. Provides validity inspection
so the caching layer can determine whether a cached credential is still usable
without knowing the credential's internal structure.

### Signature

```rust
pub trait Credential: Send + Sync + Clone + 'static {
    fn is_valid(&self) -> bool;
    fn expires_at(&self) -> Option<std::time::Instant>;
}
```

### Trait Bounds

| Bound | Reason |
|---|---|
| `Send + Sync` | Credentials are passed across async task boundaries |
| `Clone` | `CachingCredentialProvider` returns value copies from the cache |
| `'static` | Providers are stored in `Arc` and passed to spawned tasks |

### Method: `is_valid()`

- Returns `true` if the credential is currently usable
- A credential with `expires_at() == None` **must** return `true`
- A credential where `expires_at() == Some(t)` and `t > Instant::now()` **must** return `true`
- A credential where `expires_at() == Some(t)` and `t <= Instant::now()` **must** return `false`
- No other logic may affect the return value — validity is purely time-based

### Method: `expires_at()`

- Returns `Some(instant)` when the credential has a known expiry
- Returns `None` when the credential does not expire or the expiry is not
  communicated by the backend

### Implementing

```rust
use std::time::Instant;
use credential_provider_core::Credential;

#[derive(Clone)]
pub struct MyCredential {
    pub value: String,
    pub expires_at: Option<Instant>,
}

impl Credential for MyCredential {
    fn is_valid(&self) -> bool {
        self.expires_at.map_or(true, |e| Instant::now() < e)
    }

    fn expires_at(&self) -> Option<Instant> {
        self.expires_at
    }
}
```

---

## `CredentialProvider<C>` (trait)

### Location

`credential-provider-core/src/provider.rs`

### Purpose

The single port abstraction. Implementations fetch credentials from a specific
backing store. This is the boundary that separates business logic (core) from
infrastructure (adapters).

### Signature

```rust
pub trait CredentialProvider<C: Credential>: Send + Sync + 'static {
    fn get(&self) -> impl Future<Output = Result<C, CredentialError>> + Send;
}
```

### Contract

- `get()` must perform a **live fetch** on every call — no internal caching
- `get()` must be safe to call concurrently from multiple tasks
- Implementations must not hold long-lived locks across `.await` points
- All backend-specific errors must be translated to `CredentialError` before returning
- Implementations must be `Send + Sync + 'static` to be held behind `Arc` or in `CachingCredentialProvider`

### Dependency injection pattern

Consumer libraries accept the provider as an injected `Arc<dyn CredentialProvider<C>>`:

```rust
use std::sync::Arc;
use credential_provider_core::{CredentialProvider, UsernamePassword};

pub struct QueueConnector {
    credentials: Arc<dyn CredentialProvider<UsernamePassword>>,
}

impl QueueConnector {
    pub async fn connect(&self) -> Result<(), Box<dyn std::error::Error>> {
        let creds = self.credentials.get().await?;
        // use creds
        Ok(())
    }
}
```

Applications should wrap providers in `CachingCredentialProvider` before injecting.

### `dyn` object safety

`CredentialProvider<C>` is object-safe for any fixed `C: Credential`. The
generic parameter on the trait (not an associated type) preserves this.
`dyn CredentialProvider<UsernamePassword>` is valid.

---

## `CredentialError` (enum)

### Location

`credential-provider-core/src/error.rs`

### Purpose

The shared error vocabulary across all providers. Classifies failures by cause
so consumers can decide how to react without inspecting backend-specific details.

### Derives

`Debug`, `Clone`, `thiserror::Error`

### Variants

```rust
pub enum CredentialError {
    Backend(String),
    Unreachable(String),
    Configuration(String),
    Unavailable,
    Revoked,
}
```

### Variant Catalogue

#### `Backend(String)`

**When to use:** The backing store was reachable and responded, but the response
indicates an error (HTTP 500, malformed body, unexpected structure, permission
denied at the application level).

**Context string:** Should include HTTP status, response summary, or store error
message. Must **never** include credential values.

**Typical consumer reaction:** Retry with backoff.

#### `Unreachable(String)`

**When to use:** The backing store could not be contacted at the network level
(connection refused, DNS failure, timeout, TLS handshake failure).

**Context string:** Should include the address, port, and error detail.

**Typical consumer reaction:** Retry, check network/DNS.

**Distinguished from `Backend`:** `Unreachable` means the transport failed
before receiving any response. `Backend` means a response was received but it
indicated an error.

#### `Configuration(String)`

**When to use:** The provider is misconfigured — a required environment variable
is missing or empty, a Vault path does not exist, or a required field is absent
from the backend response.

**Context string:** Should name the missing item (variable name, Vault path,
field name) without revealing its value.

**Typical consumer reaction:** Surface to operator, fail the operation. Retrying
without a configuration change will not help.

#### `Unavailable`

**When to use:** No credential is available and no cached value exists. This is
the terminal state returned by `CachingCredentialProvider` when both a live
fetch and the cache fallback have failed (or when the cache is empty and the
first fetch fails).

**No string payload:** The distinguishing information is already in the wrapping
`CredentialError` that caused the unavailability.

**Typical consumer reaction:** Fail the operation.

#### `Revoked`

**When to use:** The credential was explicitly revoked before its natural expiry.
This is distinct from expiry (time-based) — revocation is an active action by
an operator or policy.

Example: Vault indicates a lease has been explicitly revoked on re-read.

**Typical consumer reaction:** Re-authenticate or escalate to operator.

### Stability

New variants **may be added in minor releases**. All match arms against
`CredentialError` in consumer code must include a wildcard arm for forward
compatibility:

```rust
match err {
    CredentialError::Configuration(msg) => { /* fix config */ }
    CredentialError::Unreachable(msg)   => { /* retry */ }
    CredentialError::Backend(msg)       => { /* retry with backoff */ }
    CredentialError::Revoked            => { /* escalate */ }
    CredentialError::Unavailable        => { /* fail */ }
    _ => { /* forward-compatibility catch-all */ }
}
```

### Security constraint

`CredentialError` messages must contain paths, status codes, variable names, and
context — **never** credential values (passwords, tokens, keys). This is
enforced in code review.
