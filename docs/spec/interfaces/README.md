# Interface Specifications — `credential-provider`

This folder documents every public type, trait, and function contract in the
`credential-provider` workspace. These documents are the authoritative reference
for implementors. Source stubs reference back here; implementors must implement
the behaviour described here, not just satisfy the type signatures.

---

## Document Index

| Document | What it covers |
|---|---|
| [shared-types.md](shared-types.md) | `Credential` trait, `CredentialProvider<C>` trait, `CredentialError` enum |
| [credential-types.md](credential-types.md) | `UsernamePassword`, `BearerToken`, `HmacSecret`, `TlsClientCertificate` |
| [caching.md](caching.md) | `CachingCredentialProvider` — caching policy, stale fallback, concurrency |
| [env-adapters.md](env-adapters.md) | `EnvUsernamePasswordProvider`, `EnvHmacSecretProvider`, `EnvBearerTokenProvider` |
| [vault-adapter.md](vault-adapter.md) | `VaultExtractor<C>`, `VaultProvider<C>`, all convenience constructors |
| [azure-adapter.md](azure-adapter.md) | `AzureCredentialProvider` |
| [aws-adapter.md](aws-adapter.md) | `AwsCredentials`, `AwsCredentialProvider` |
| [test-support.md](test-support.md) | `MockCredentialProvider` |

---

## Dependency Graph

```
Consumer library
    └── depends on credential-provider-core (traits + types only)
            ├── Credential (trait)
            ├── CredentialProvider<C> (trait / port)
            ├── CachingCredentialProvider<C, P>
            ├── CredentialError
            └── Credential types: UsernamePassword, BearerToken, HmacSecret, TlsClientCertificate

Application binary
    └── depends on credential-provider (with feature flags)
            ├── re-exports all of credential-provider-core
            ├── [env]   EnvUsernamePasswordProvider, EnvHmacSecretProvider, EnvBearerTokenProvider
            ├── [vault] VaultProvider<C>, VaultExtractor<C>
            ├── [azure] AzureCredentialProvider
            └── [aws]   AwsCredentials, AwsCredentialProvider
```

---

## Hexagonal Architecture Map

```
┌─────────────────────────────────────────────────────┐
│  Business Logic (credential-provider-core)           │
│                                                       │
│  Credential (trait)   CredentialError                 │
│  UsernamePassword     BearerToken                     │
│  HmacSecret           TlsClientCertificate            │
│  CachingCredentialProvider<C, P>                      │
│                                                       │
│  ┌─────────────────────────────────┐                  │
│  │  Port                            │                  │
│  │  CredentialProvider<C> (trait)   │                  │
│  └────────────────┬─────────────────┘                  │
└───────────────────┼─────────────────────────────────────┘
                    │ implemented by
┌───────────────────┼─────────────────────────────────────┐
│  Adapters (credential-provider)                          │
│                    │                                      │
│  EnvUsernamePasswordProvider   ──► std::env              │
│  EnvHmacSecretProvider         ──► std::env              │
│  EnvBearerTokenProvider        ──► std::env              │
│  VaultProvider<C>              ──► HashiCorp Vault       │
│  AzureCredentialProvider       ──► Azure Identity        │
│  AwsCredentialProvider         ──► AWS IAM               │
└──────────────────────────────────────────────────────────┘
```

---

## Layer Legend

| Layer | Crate | Description |
|---|---|---|
| **Port** | `credential-provider-core` | The `CredentialProvider<C>` trait — the single abstraction boundary |
| **Business logic** | `credential-provider-core` | Validity rules, caching policy, error types, credential value types |
| **Adapters** | `credential-provider` | Concrete backend implementations, feature-flag isolated |

---

## Key Architectural Rules

- Consumer libraries depend **only** on `credential-provider-core` — never on `credential-provider`
- Applications depend on `credential-provider` (which re-exports core)
- Backend SDK types (`vaultrs`, `azure_identity`, `aws_config`) must **not** appear in adapter public API signatures — only core types cross the boundary
- Caching is **exclusively** the responsibility of `CachingCredentialProvider`; adapters must not cache internally
- All visible errors from adapters are `CredentialError` — no backend-specific error type leaks out
