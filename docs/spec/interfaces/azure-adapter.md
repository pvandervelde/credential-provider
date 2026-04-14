# Azure Adapter

**Architectural layer:** Adapters (`credential-provider`)
**Source file:** `credential-provider/src/azure.rs`
**Feature flag:** `azure`
**External dependencies:** `azure_identity 0.19`, `azure_core 0.19`

The Azure adapter wraps `azure-identity` to supply `BearerToken` credentials
for Azure service authentication. It delegates entirely to the
`DefaultAzureCredential` chain, which handles environment detection
automatically.

---

## `AzureCredentialProvider`

### Location

`credential-provider/src/azure.rs`

### Purpose

A `CredentialProvider<BearerToken>` that resolves tokens via the Azure Identity
credential chain. Recommended when the service is running on Azure infrastructure
and needs to authenticate to Azure-managed resources.

### Fields (private)

| Field | Type | Description |
|---|---|---|
| `scope` | `String` | OAuth2 scope for the target Azure resource |
| `credential` | `DefaultAzureCredential` | Azure credential chain instance |

### Constructor: `new()`

```rust
pub fn new(scope: impl Into<String>) -> Self
```

**Parameters:**

- `scope` — the OAuth2 scope URI for the target resource.
  Must end with `"/.default"` for managed identity flows.
  Examples: `"https://servicebus.azure.net/.default"`,
  `"https://storage.azure.com/.default"`

**Behaviour:**

- Constructs a `DefaultAzureCredential` instance (this does not make any
  network calls at construction time)
- Stores the scope for use on each `get()` call

**Example:**

```rust
use credential_provider::azure::AzureCredentialProvider;

let provider = AzureCredentialProvider::new(
    "https://servicebus.azure.net/.default",
);
```

---

## `get()` Behaviour

1. Call `DefaultAzureCredential::get_token(&self.scope)` via `azure_core`
2. Extract the token string and expiry from the response
3. Construct and return `BearerToken::new(SecretString::new(token), Some(expires_at))`

### Credential Chain Order

`DefaultAzureCredential` tries the following sources in order:

1. Managed identity (when running on Azure VMs, App Service, AKS with pod identity, etc.)
2. Workload identity (Kubernetes workload identity federation via projected service account token)
3. Environment variables (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`)
4. Azure CLI (`az login` — for local development)

No application configuration changes are needed when moving between local
development and Azure deployment.

### Expiry Handling

The Azure token response includes an expiry timestamp. The implementation sets
`expires_at` on the returned `BearerToken` to this value. `CachingCredentialProvider`
will schedule proactive renewal using its `refresh_before_expiry` window.

---

## Error Mapping

| Azure Identity condition | `CredentialError` variant |
|---|---|
| No credential source found in the chain | `Configuration("azure: no credential source available: {detail}")` |
| Token endpoint unreachable (DNS/TCP failure) | `Unreachable("azure: {detail}")` |
| Token endpoint returned HTTP error | `Backend("azure: token request failed: {status} {detail}")` |
| Token response missing expiry field | `Backend("azure: token response missing expiry")` |

---

## Usage Pattern

This provider is typically not constructed by application code directly. It is
wired by the `queue-runtime` Azure Service Bus adapter when
`AzureAuthMethod::ManagedIdentity` or `AzureAuthMethod::WorkloadIdentity` is
configured. For direct use:

```rust
use std::{sync::Arc, time::Duration};
use credential_provider::azure::AzureCredentialProvider;
use credential_provider_core::CachingCredentialProvider;

let provider = Arc::new(CachingCredentialProvider::new(
    AzureCredentialProvider::new("https://servicebus.azure.net/.default"),
    Duration::from_secs(300),
));

let token = provider.get().await?;
```
