# ADR-002: Single Generic CredentialProvider Trait

Status: Accepted
Date: 2026-04-01
Owners: credential-provider team

## Context

The credential management layer needs a trait abstraction that backend implementations conform to. There are multiple credential types in the system (`UsernamePassword`, `BearerToken`, `HmacSecret`, `TlsClientCertificate`), and each backend (secrets managers, cloud identity providers, environment variables) may produce one or more of these types.

Two design directions exist: a single trait generic over the credential type, or a family of per-credential-type traits.

The caching wrapper (`CachingCredentialProvider`) must work with any credential type. Its implementation — caching, refresh window, stale fallback, concurrent serialization — is identical regardless of the credential type being cached.

## Decision

Use a **single generic trait** `CredentialProvider<C: Credential>` with one method, `get() -> Result<C, CredentialError>`.

- All backend implementations implement `CredentialProvider<C>` for the specific `C` they produce.
- `CachingCredentialProvider<C, P>` is generic over both the credential type and the inner provider — one implementation covers all credential types.
- Consumers accept `Arc<dyn CredentialProvider<C>>` or `CachingCredentialProvider<C, P>` as injected dependencies and are generic over the provider, not the backend.

Do **not** create separate traits per credential type (e.g., `UsernamePasswordProvider`, `BearerTokenProvider`).

## Consequences

**Enables:**

- One `CachingCredentialProvider` implementation for all credential types — no duplication, no macro gymnastics
- Adding a new credential type (e.g., `DatabaseConnectionString`) requires only a new `Credential` impl, not a new trait
- Consumers can be generic over both credential type and provider
- Consistent API surface: every provider has exactly one method to learn

**Forbids:**

- A single provider instance returning different credential types from the same `get()` call (each impl is `CredentialProvider<SpecificType>`)
- Trait methods specific to one credential type (e.g., a `rotate_password()` on a username/password provider)

**Trade-offs:**

- Generic type signatures are more verbose than named traits (`Arc<dyn CredentialProvider<UsernamePassword>>` vs. `Arc<dyn UsernamePasswordProvider>`)
- The trait cannot express backend-specific capabilities beyond `get()` — this is intentional

## Alternatives considered

### Option A: Separate traits per credential type

```rust
trait UsernamePasswordProvider { async fn get(&self) -> Result<UsernamePassword, CredentialError>; }
trait BearerTokenProvider { async fn get(&self) -> Result<BearerToken, CredentialError>; }
trait HmacSecretProvider { async fn get(&self) -> Result<HmacSecret, CredentialError>; }
```

**Why not:** Caching logic would need to be duplicated for each trait (or require a complex macro). Adding a new credential type would require adding a new trait, a new caching wrapper implementation, and updating all generic consumer code. The proliferation does not carry enough benefit to justify the cost.

### Option B: Trait with associated type instead of generic parameter

```rust
trait CredentialProvider { type Cred: Credential; async fn get(&self) -> Result<Self::Cred, CredentialError>; }
```

**Why not:** Associated types prevent `dyn CredentialProvider` from being object-safe in a useful way — consumers would need to know the concrete credential type at the trait-object level. The generic parameter `CredentialProvider<C>` allows `dyn CredentialProvider<UsernamePassword>`, which is object-safe and useful for dependency injection.

## Implementation notes

- The `Credential` trait bound on `C` requires `Send + Sync + Clone + 'static`. `Clone` is needed because the caching layer returns copies. `Send + Sync` is needed for async task boundaries.
- Native async traits are used (MSRV 1.90, edition 2024).
- The `get()` method takes `&self`, not `&mut self`, so providers must handle interior mutability if needed. In practice, all current providers are stateless readers and need no mutation.

## Examples

**Defining a provider:**

```rust
pub struct MyBackendProvider { /* ... */ }

impl CredentialProvider<UsernamePassword> for MyBackendProvider {
    async fn get(&self) -> Result<UsernamePassword, CredentialError> {
        // fetch from backend, translate response
    }
}
```

**Using a provider with caching:**

```rust
let raw = MyBackendProvider::new(client, "path/to/credentials");
let cached = CachingCredentialProvider::new(raw, Duration::from_secs(60));
let creds = cached.get().await?;
```

**Consumer accepting any provider:**

```rust
pub struct QueueConnector {
    credentials: Arc<dyn CredentialProvider<UsernamePassword>>,
}
```

## References

- [Tradeoffs: T-1](../spec/tradeoffs.md#t-1-single-trait-vs-typed-provider-traits)
- [Architecture Spec](../spec/architecture.md)
- [Vocabulary: CredentialProvider](../spec/vocabulary.md#credentialprovider)
