# Testing Strategy

---

## Testing Layers

### 1. Unit Tests — Credential Types (credential-provider-core)

Test the `Credential` trait implementations on each concrete type.

**What to test:**

- `is_valid()` returns `true` for non-expired credentials (A-CRED-1, A-CRED-2)
- `is_valid()` returns `false` for expired credentials (A-CRED-3)
- `HmacSecret` is always valid with no expiry (A-CRED-4)
- `Clone` produces an independent copy
- `Debug` does not leak secret material

**Approach:** Pure unit tests, no mocks or external dependencies needed.

---

### 2. Unit Tests — CachingCredentialProvider (credential-provider-core)

Test the caching logic in isolation using `MockCredentialProvider`.

**What to test:**

- Empty cache triggers fetch (A-CACHE-1)
- Cache hit returns without fetch (A-CACHE-2)
- Refresh window triggers fetch (A-CACHE-3)
- Stale fallback on refresh failure (A-CACHE-4)
- Error propagation when cache empty and fetch fails (A-CACHE-5)
- Concurrent serialization (A-CACHE-6)
- No-expiry credentials never refresh (A-CACHE-7)
- Successful refresh replaces cache (A-CACHE-8)

**Approach:** Use `MockCredentialProvider` to control what the inner provider returns. Use `tokio::time::pause()` to control time advancement for expiry testing. Use `tokio::spawn` for concurrency tests.

**Key technique for concurrency test (A-CACHE-6):**

- Create a `MockCredentialProvider` that includes an internal delay (e.g., a `tokio::sync::Barrier` or `Notify`)
- Spawn multiple tasks calling `get()` concurrently
- Verify the mock's `get()` was called exactly once
- Verify all tasks received the same result

---

### 3. Unit Tests — Env Providers (credential-provider)

Test environment variable reading logic.

**What to test:**

- All `A-ENV-*` assertions (happy path, missing, empty, invalid encoding, re-read)

**Approach:** Set/unset environment variables directly in tests. Use `std::env::set_var` / `std::env::remove_var`. Note: environment variable tests are inherently serial (shared global state). Use `#[serial]` from the `serial_test` crate or run via `cargo test -- --test-threads=1` for the env module.

**Caution:** `std::env::set_var` is unsafe in edition 2024. Use `unsafe { std::env::set_var(...) }` in tests, or use the `temp_env` crate for safer environment variable manipulation in test code.

---

### 4. Unit Tests — Vault Providers (credential-provider)

Test error mapping and response parsing without a real Vault server.

**What to test:**

- All `A-VAULT-*` assertions
- Correct mapping of vaultrs error types to `CredentialError` variants
- Correct parsing of Vault response structure into credential types
- Lease duration to `expires_at` conversion

**Approach:** This is the hardest set of unit tests because `vaultrs::Client` is not trivially mockable. Options:

1. **Extract a trait** over the Vault read operations used by each provider, then mock that trait in tests
2. **Use `wiremock`** or similar to mock HTTP responses at the transport level
3. **Test the mapping functions in isolation** — extract the response-to-credential and error-to-CredentialError mapping as pure functions, test those directly

Option 3 is recommended for unit tests. Options 1 and 2 are better suited for integration tests.

---

### 5. Integration Tests — Vault Providers (credential-provider)

Test against a real Vault instance.

**What to test:**

- Full round-trip: authenticate to Vault, create a provider, call `get()`, verify credential
- Error conditions with actual Vault responses (permission denied, path not found)

**Approach:** Use a Vault dev-mode container (`hashicorp/vault:latest` with `-dev` flag). Set up test fixtures (KV secrets, RabbitMQ roles) via the Vault CLI in test setup. Gate behind a feature flag or `#[ignore]` so they don't run in standard CI.

---

### 6. Integration Tests — Azure & AWS Providers

These providers delegate to their respective SDKs and are difficult to test without real infrastructure.

**Approach:**

- Unit tests can verify error mapping using mocked SDK responses (if SDKs support test utilities)
- Full integration tests require actual Azure/AWS credentials and should be gated behind `#[ignore]` or a CI-only flag
- The primary verification is that the credential type conversion is correct and expiry is propagated

---

### 7. Mock Provider for Consumers

`MockCredentialProvider<C>` enables downstream crates and applications to test code that depends on `CredentialProvider<C>` without any backend.

**Capabilities needed:**

- Return a pre-configured `Ok(credential)` or `Err(error)` value
- Support returning different values on successive calls (for testing refresh sequences)
- Track call count for assertions
- Available under `cfg(any(test, feature = "test-support"))`

---

## Test Organization

```
credential-provider-core/
└── src/
    ├── credentials.rs         # #[path = "credentials_tests.rs"] mod tests;
    ├── credentials_tests.rs   # adjacent test file for credential types
    ├── caching.rs             # #[path = "caching_tests.rs"] mod tests;
    ├── caching_tests.rs       # adjacent test file for caching logic
    ├── mock.rs                # #[path = "mock_tests.rs"] mod tests;
    └── mock_tests.rs          # adjacent test file for MockCredentialProvider

credential-provider/
├── src/
│   ├── env.rs                 # #[path = "env_tests.rs"] mod tests;
│   └── vault.rs               # #[path = "vault_tests.rs"] mod tests;
└── tests/
    └── vault_integration.rs   # #[ignore] integration tests requiring Vault
```

Test files are never inline — all tests live in an adjacent `_tests.rs` file
and are referenced from the source file with:

```rust
#[cfg(test)]
#[path = "<module>_tests.rs"]
mod tests;
```

---

## CI Test Matrix

| Stage | Scope | Features | External deps |
|---|---|---|---|
| Default | All unit tests | `--all-features` | None |
| Env only | Env provider tests | `--features env` | None |
| Vault unit | Vault mapping tests | `--features vault` | None |
| Vault integration | Full Vault round-trip | `--features vault` | Vault dev container |
| Azure/AWS | SDK integration | `--features azure,aws` | Cloud credentials |

The first three stages should run on every PR. Vault integration runs in CI with a containerized Vault. Azure/AWS integration runs on a schedule or manual trigger.
