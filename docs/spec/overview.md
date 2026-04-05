# System Overview

## Context

Rust services frequently need credentials at runtime — queue broker connections (RabbitMQ), webhook signature validation (GitHub), API tokens, TLS certificates, and cloud provider identities. Each service may run in different environments (local development, self-hosted infrastructure with Vault, Azure, AWS) and must obtain credentials from whichever secrets backend is available without coupling service logic to a specific backend.

`credential-provider` solves this by separating the *concept* of obtaining credentials from the *mechanism* of obtaining them.

## System Context Diagram

```mermaid
graph TB
    subgraph "Consumer Libraries"
        QR[queue-runtime]
        WH[webhook-handler]
        API[api-client]
    end

    subgraph "credential-provider workspace"
        CORE[credential-provider-core<br/>traits, types, caching]
        IMPL[credential-provider<br/>backend adapters]
    end

    subgraph "Secrets Backends"
        VAULT[HashiCorp Vault]
        AZURE[Azure Identity]
        AWS[AWS IAM]
        ENV[Environment Variables]
    end

    subgraph "Applications"
        APP[service binary<br/>wires providers at startup]
    end

    QR -->|depends on| CORE
    WH -->|depends on| CORE
    API -->|depends on| CORE

    APP -->|depends on| IMPL
    APP -->|constructs providers for| QR
    APP -->|constructs providers for| WH

    IMPL -->|depends on| CORE
    IMPL -->|"feature: vault"| VAULT
    IMPL -->|"feature: azure"| AZURE
    IMPL -->|"feature: aws"| AWS
    IMPL -->|"feature: env"| ENV
```

## Crate Relationship

The workspace contains exactly two crates with a strict dependency direction:

```
credential-provider-core    (port definitions — traits, types, caching)
        ↑
credential-provider         (adapter implementations — env, vault, azure, aws)
```

- **credential-provider-core** has no knowledge of any backend. It defines what credentials *are* and how they behave.
- **credential-provider** knows how to *fetch* credentials from specific backends and translate them into the core types.

Consumer libraries depend **only** on `credential-provider-core`. Applications depend on `credential-provider` (which re-exports core) and wire concrete providers at startup.

## High-Level Data Flow

```mermaid
sequenceDiagram
    participant Consumer as Library (e.g. queue-runtime)
    participant Cache as CachingCredentialProvider
    participant Provider as CredentialProvider impl
    participant Backend as Secrets Backend

    Consumer->>Cache: get()
    alt Cache hit (valid, outside refresh window)
        Cache-->>Consumer: cached credential
    else Cache miss or refresh needed
        Cache->>Provider: get()
        Provider->>Backend: fetch credential
        Backend-->>Provider: raw credential data
        Provider-->>Cache: Credential value
        Cache-->>Consumer: fresh credential
    end
```

## Design Goals

1. **Decoupling** — Service code never knows which backend provides credentials
2. **Minimal core** — The trait crate is cheap for any library to depend on
3. **Transparent lifecycle** — Caching, refresh, and fallback are invisible to consumers
4. **Memory safety for secrets** — All sensitive values are zeroed on drop
5. **Compile-time backend selection** — Feature flags prevent unused backend SDKs from being compiled
6. **Testability** — The `env` provider and `MockCredentialProvider` enable testing without external services
