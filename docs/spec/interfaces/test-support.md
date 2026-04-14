# Test Support — MockCredentialProvider

**Architectural layer:** Business logic (`credential-provider-core`)
**Source file:** `credential-provider-core/src/mock.rs`
**Re-exported by:** `credential-provider/src/test_support.rs`
**Feature gate:** `cfg(any(test, feature = "test-support"))`
**ADR security reference:** [security.md S-7](../../security.md#s-7-mockcredentialprovider-in-production)

`MockCredentialProvider<C>` is a test double for `CredentialProvider<C>` that
returns pre-configured values. Use it in tests that need to control credential
validity, expiry, or error conditions precisely without connecting to an
external backend.

---

## Availability

`MockCredentialProvider` is **only** available under:

```rust
#[cfg(any(test, feature = "test-support"))]
```

It is defined in `credential-provider-core` for use in that crate's own unit
tests and re-exported by `credential-provider` behind the `test-support` feature
for downstream consumers.

**The `test-support` feature must never be enabled in production Cargo profiles.**
CI should verify this. A compile-time warning is emitted if `test-support` is
enabled outside a test profile.

---

## Struct

```rust
pub struct MockCredentialProvider<C: Credential + Clone> {
    responses: Mutex<Vec<Result<C, CredentialError>>>,
    call_count: Arc<AtomicUsize>,
}
```

### Fields

| Field | Type | Description |
|---|---|---|
| `responses` | `Mutex<Vec<Result<C, CredentialError>>>` | Pre-configured responses, consumed in order |
| `call_count` | `Arc<AtomicUsize>` | Total number of `get()` invocations |

---

## Constructors

### `returning_ok(credential)`

```rust
pub fn returning_ok(credential: C) -> Self
```

Creates a mock that returns the given credential on every call to `get()`.
The credential is cloned on each call so the same instance is returned
indefinitely.

```rust
let provider = MockCredentialProvider::returning_ok(UsernamePassword::new(
    "testuser",
    SecretString::new("testpass".to_string()),
    Some(Instant::now() + Duration::from_secs(300)),
));
```

### `returning_err(error)`

```rust
pub fn returning_err(error: CredentialError) -> Self
```

Creates a mock that returns the given error on every call to `get()`.
The error is cloned on each call.

```rust
let provider = MockCredentialProvider::<UsernamePassword>::returning_err(
    CredentialError::Unreachable("test backend down".into()),
);
```

### `from_sequence(responses)`

```rust
pub fn from_sequence(responses: Vec<Result<C, CredentialError>>) -> Self
```

Creates a mock that returns each value in `responses` sequentially on successive
calls. Once the sequence is exhausted, the last value is repeated on all
subsequent calls.

Useful for testing state transitions (e.g., first call fails, second call succeeds).

```rust
let provider = MockCredentialProvider::from_sequence(vec![
    Err(CredentialError::Unreachable("first attempt fails".into())),
    Ok(UsernamePassword::new("user", password.clone(), None)),
]);
```

**Panics** if `responses` is empty.

---

## Method: `call_count()`

```rust
pub fn call_count(&self) -> usize
```

Returns the total number of times `get()` has been called on this mock.
Useful for asserting that the caching layer called the inner provider the
expected number of times.

```rust
assert_eq!(mock.call_count(), 1, "cache should have prevented second fetch");
```

---

## `CredentialProvider<C>` Implementation

```rust
impl<C: Credential + Clone> CredentialProvider<C> for MockCredentialProvider<C> {
    async fn get(&self) -> Result<C, CredentialError> {
        // increments call_count, pops next response
    }
}
```

The implementation is `Send + Sync + 'static` (required by `CredentialProvider`).
The `Mutex` ensures thread-safe access to the response sequence.

---

## Usage with `CachingCredentialProvider`

```rust
use std::time::{Duration, Instant};
use secrecy::SecretString;
use credential_provider_core::{
    CachingCredentialProvider, UsernamePassword,
};
use credential_provider_core::mock::MockCredentialProvider;

#[tokio::test]
async fn test_cache_calls_inner_once() {
    let credential = UsernamePassword::new(
        "alice",
        SecretString::new("secret".to_string()),
        Some(Instant::now() + Duration::from_secs(300)),
    );
    let mock = MockCredentialProvider::returning_ok(credential);
    let caching = CachingCredentialProvider::new(mock, Duration::from_secs(60));

    // Two calls — cache should prevent second fetch
    let _ = caching.get().await.unwrap();
    let _ = caching.get().await.unwrap();

    // Need access to mock to check call_count — wrap in Arc for shared access
}
```

---

## Accessing from `credential-provider`

```rust
// In test code depending on the credential-provider crate:
use credential_provider::test_support::MockCredentialProvider;
```

Requires `features = ["test-support"]` in `Cargo.toml` dev-dependencies:

```toml
[dev-dependencies]
credential-provider = { path = "...", features = ["test-support"] }
```
