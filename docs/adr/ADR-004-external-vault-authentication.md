# ADR-004: External Backend Authentication

Status: Accepted
Date: 2026-04-01
Owners: credential-provider team

## Context

Some credential backends require the application to establish an authenticated session before secrets can be fetched. For example, HashiCorp Vault requires an authenticated `VaultClient`, and each deployment environment may use a different auth method (AppRole, JWT/OIDC, Kubernetes auth, TLS certificate, userpass, etc.). Azure and AWS have analogous concepts through their identity credential chains.

The question is whether credential providers should manage backend authentication internally or receive pre-authenticated clients from the application.

## Decision

Credential providers **do not manage backend authentication**. They receive pre-authenticated clients from the application. The application is responsible for:

1. Constructing the backend client with the correct endpoint/configuration
2. Authenticating with the appropriate auth method
3. Renewing sessions or tokens before they expire
4. Passing the authenticated client to each provider

Providers accept backend-specific clients as constructor parameters and assume they are authenticated and usable. If the backend session has expired, provider calls will fail and the errors will map to the appropriate `CredentialError` variant.

Do **not** add authentication parameters, auth method selection, or session renewal logic to any provider.

## Consequences

**Enables:**

- Any backend auth method works without provider code changes
- Application controls the full authentication lifecycle (method selection, token/session renewal, re-authentication)
- Provider code is simple: read a path/scope, translate the response, map errors
- Multiple providers can share a single backend client instance
- Testing providers does not require testing authentication flows

**Forbids:**

- Providers auto-recovering from expired backend sessions (they return errors, application must re-authenticate)
- Providers accepting raw authentication credentials directly
- Auth method configuration in provider constructors

**Trade-offs:**

- Applications must implement backend session renewal independently — this is additional work that each consuming application must get right
- If a backend session expires between refreshes, credential fetches fail until the application re-authenticates. The stale fallback (ADR-003) mitigates this for cached credentials.
- Providers may not be able to distinguish "session expired" from "access denied" — both may arrive as the same error from the backend SDK

## Alternatives considered

### Option A: Provider manages authentication internally

```rust
let provider = MyBackendProvider::new(
    backend_addr,
    AuthMethod::ServiceAccount { id, secret },
    "path/to/credentials",
);
```

**Why not:** Every provider would need to support every auth method. With N providers × M auth methods, this creates a combinatorial explosion. Auth method configuration (periodic session renewal, retry logic, error handling) is complex and orthogonal to secret fetching. This conflates two distinct concerns.

### Option B: Abstract auth behind a trait per backend

```rust
trait BackendAuthProvider { async fn authenticate(&self, client: &BackendClient) -> Result<(), AuthError>; }
```

**Why not:** Adds indirection without clear benefit. The application already has the backend SDK as a dependency (transitively through `credential-provider`). Wrapping SDK-specific auth calls in another trait only adds a layer for the sake of abstraction. The application can call the auth functions directly.

### Option C: Provider lazily authenticates on first use

**Why not:** Defers authentication failure to the first `get()` call, making startup errors harder to detect. Contradicts the recommended startup pattern of fail-fast credential population.

## Implementation notes

- Backend clients that are `Clone` (e.g., `VaultClient` wraps an `Arc` internally) can be shared between providers cheaply.
- The application should authenticate before constructing any providers. A failed authentication at startup is clearer than a failed `get()` later.
- For backends with session TTLs, the application should set up a renewal loop or use the backend's renewable session feature.
- The `CachingCredentialProvider` stale fallback (ADR-003) provides a grace period if a backend session expires briefly, since cached credentials remain usable until their own expiry.

## Examples

**Vault example — application authenticates, then constructs providers:**

```rust
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::auth::approle;

// 1. Construct client
let vault = VaultClient::new(
    VaultClientSettingsBuilder::default()
        .address(std::env::var("VAULT_ADDR")?)
        .build()?
)?;

// 2. Authenticate (application's responsibility)
approle::login(&vault, "auth/approle/login", &role_id, &secret_id).await?;

// 3. Pass authenticated client to providers
let queue_creds = VaultProvider::dynamic_credentials(vault.clone(), "rabbitmq", "creds/queue-keeper");
let webhook_secret = VaultProvider::kv2_secret(vault.clone(), "secret", "github/webhook", "value");
```

**General pattern — provider constructor takes no auth parameters:**

```rust
pub struct MyBackendProvider {
    client: BackendClient,
    resource_path: String,
}

impl MyBackendProvider {
    pub fn new(client: BackendClient, resource_path: &str) -> Self {
        Self { client, resource_path: resource_path.to_string() }
    }
}
```

## References

- [Tradeoffs: T-8](../spec/tradeoffs.md#t-8-provider-authentication-vault--internal-vs-external)
- [Responsibilities: VaultProvider](../spec/responsibilities.md#vaultproviderc)
- [Operations: Self-Hosted Deployment](../spec/operations.md#self-hosted-vault)
- [Edge Cases: E-VAULT-1](../spec/edge-cases.md#e-vault-1-vault-token-expired)
