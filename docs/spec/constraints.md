# Implementation Constraints

Hard rules that must be followed during implementation. Violations should be caught in code review and CI.

---

## Type System

### Secret Material

- All credential fields containing sensitive data (passwords, tokens, keys, private keys) **must** use `secrecy::SecretString` or `secrecy::SecretVec<u8>`
- Secret types are zeroed from memory on drop — this is a security invariant, not optional
- `Debug` implementations for credential types must NOT print secret material (secrecy handles this automatically)
- No `Display` implementation should reveal secret material

### Credential Trait Bounds

- All credential types must implement `Send + Sync + Clone + 'static`
- `Clone` is required because `CachingCredentialProvider` needs to return copies from the cache
- `Send + Sync` is required because credentials are passed across async task boundaries
- `'static` is required because providers are stored in `Arc` and passed to spawned tasks

### Error Handling

- All provider `get()` methods return `Result<C, CredentialError>` — no panics for expected failures
- `CredentialError` is the **only** error type that crosses the provider boundary
- Backend-specific errors must be translated into `CredentialError` variants within the adapter
- Match arms against `CredentialError` in consumer code should include a wildcard arm for forward compatibility

---

## Module Boundaries

### Core Crate (credential-provider-core)

- **Must not** depend on any secrets backend SDK (vaultrs, azure-identity, aws-config, etc.)
- **Must not** depend on anything beyond: `secrecy`, `thiserror`, `tokio`
- **Must not** contain any backend-specific code, types, or error details
- **Must** be a self-contained library that any Rust crate can depend on with minimal cost
- Adding a dependency to this crate requires explicit justification

### Adapter Crate (credential-provider)

- **Must** depend on `credential-provider-core`
- **Must** gate each backend behind a Cargo feature flag
- **Must not** let backend SDK types appear in public API signatures (only core types cross the boundary)
- **Must** re-export `credential-provider-core` so applications can use a single dependency
- The `env` feature is the default and requires no external dependencies

### Consumer Libraries

- **Must** depend only on `credential-provider-core`, never on `credential-provider` directly
- **Must** accept providers as injected dependencies (`Arc<dyn CredentialProvider<C>>` or similar)
- **Must not** construct concrete providers — that is the application's responsibility

---

## Concurrency

### CachingCredentialProvider

- Cache reads must allow concurrent access (multiple `get()` calls reading simultaneously)
- Cache writes (refresh) must be serialized — only one fetch in flight at a time
- The specified approach is `RwLock<Option<C>>` for the cache
- Concurrent refresh serialization must prevent thundering herd on cache expiry
- All waiters during a refresh receive the same result (no duplicate fetches)

### CredentialProvider Implementations

- All implementations must be `Send + Sync`
- All implementations must be safe for concurrent `get()` calls
- Implementations must not hold long-lived locks across await points

---

## Feature Flags

```toml
[features]
default = ["env"]
env   = []
vault = ["dep:vaultrs", "dep:tokio"]
azure = ["dep:azure-identity", "dep:azure-core"]
aws   = ["dep:aws-config", "dep:aws-credential-types"]
```

- Each feature must be independently toggleable
- The `env` feature adds no external dependencies
- Disabling all features (including `env`) is permitted but unusual
- The `test-support` feature (for `MockCredentialProvider`) must be gated on `cfg(any(test, feature = "test-support"))` and must never be enabled in production profiles

---

## API Stability

- `CredentialProvider<C>` and `Credential` traits are stable public API from v0.1.0
- Breaking changes to either trait require a major version bump
- Concrete credential types (`UsernamePassword`, `BearerToken`, `HmacSecret`, `TlsClientCertificate`) are stable
- New fields on credential types must be backwards-compatible (`Option<T>` with defaults, or builder pattern)
- New `CredentialError` variants may be added in minor releases (hence the wildcard arm requirement)

---

## Rust Toolchain

- **MSRV:** 1.90
- **Edition:** 2024
- **Resolver:** 2 (workspace-level)
- Native async traits are used (stabilized in Rust 1.75)

---

## Dependencies

### Workspace Dependencies (pinned in workspace Cargo.toml)

| Dependency | Version | Purpose |
|---|---|---|
| `secrecy` | 0.8 (with `serde` feature) | Secret memory management with zeroize-on-drop. The `serde` feature is enabled because `SecretString` and `SecretVec<u8>` require it for `Deserialize` support — this allows credential types to be constructed from deserialized configuration or backend responses without manual conversion. |
| `thiserror` | 1 | Derive macro for error types |
| `tokio` | 1 (features: `sync`, `time`) | RwLock, timing primitives |
| `vaultrs` | 0.7 (optional, `rustls` feature) | Vault client |
| `azure-identity` | 0.19 (optional) | Azure credential chain |
| `azure-core` | 0.19 (optional) | Azure core types |
| `aws-config` | 1 (optional) | AWS credential chain |
| `aws-credential-types` | 1 (optional) | AWS credential types |

### Forbidden Dependencies in Core

The following must never appear in `credential-provider-core`:

- Any secrets backend SDK
- Any HTTP client
- Any serialization library beyond what `secrecy` requires
- Any logging/tracing framework (consumers choose their own)
