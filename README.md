# credential-provider

[![CI](https://github.com/pvandervelde/credential-provider/actions/workflows/ci.yml/badge.svg)](https://github.com/pvandervelde/credential-provider/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/credential-provider-core.svg)](LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-1.90%2B-blue.svg)](https://www.rust-lang.org)

Provider-agnostic credential management for Rust — a shared abstraction for acquiring, caching, and refreshing secrets across any backing store.

## Overview

`credential-provider` is a Rust workspace containing two crates that together form a provider-agnostic credential management layer. The design follows hexagonal architecture: a small, dependency-free core defines the port interfaces, and a separate implementation crate provides adapters for each backing store.

Library crates depend only on `credential-provider-core`, keeping their dependency graph clean. Applications wire in whichever backing store they need from `credential-provider` via Cargo feature flags.

**Designed for**: any Rust service that needs to acquire credentials at runtime — queue brokers, databases, webhook secrets, PKI certificates, API tokens — without coupling the service to a specific secrets backend.

## Crates

### `credential-provider-core`

The trait definitions and common credential types. No external dependencies beyond `secrecy`. Safe for any library crate to depend on.

[→ Specification](docs/spec/credential-provider-core.md)

### `credential-provider`

Implementations of the `CredentialProvider` trait for each supported backend, each gated behind a Cargo feature flag. Applications depend on this crate and enable only the features they need.

[→ Specification](docs/spec/credential-provider.md)

## Workspace Layout

```
credential-provider/               # repository root
├── Cargo.toml                     # workspace manifest
├── Cargo.lock
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── CHANGELOG.md
├── AGENTS.md
├── cliff.toml                     # git-cliff changelog config
├── deny.toml                      # cargo-deny audit config
├── renovate.json
│
├── crates/
│   ├── credential-provider-core/  # trait definitions and credential types
│   │   ├── Cargo.toml
│   │   ├── README.md
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── credential.rs      # Credential trait + common types
│   │       ├── provider.rs        # CredentialProvider trait
│   │       ├── cache.rs           # CachingCredentialProvider wrapper
│   │       └── error.rs           # CredentialError type
│   │
│   └── credential-provider/       # backend implementations
│       ├── Cargo.toml
│       ├── README.md
│       └── src/
│           ├── lib.rs
│           ├── env.rs             # feature: env (always available)
│           ├── vault.rs           # feature: vault
│           ├── azure.rs           # feature: azure
│           └── aws.rs             # feature: aws
│
└── docs/
    └── spec/
        ├── credential-provider-core.md
        └── credential-provider.md
```

## Cargo Workspace

```toml
# Cargo.toml (workspace root)
[workspace]
members = [
    "crates/credential-provider-core",
    "crates/credential-provider",
]
resolver = "2"

[workspace.package]
version      = "0.1.0"
edition      = "2024"
rust-version = "1.90"
license      = "Apache-2.0"
authors      = ["Patrick van der Velde"]
repository   = "https://github.com/pvandervelde/credential-provider"

[workspace.dependencies]
# Core
secrecy     = { version = "0.8", features = ["serde"] }
thiserror   = "1"
tokio       = { version = "1", features = ["sync", "time"] }

# Implementations (optional)
vaultrs         = { version = "0.7", optional = true, default-features = false }
azure-identity  = { version = "0.19", optional = true }
aws-config      = { version = "1", optional = true }

# Testing
tokio-test = "0.4"
```

## Quick Start

Add `credential-provider-core` to a library crate:

```toml
[dependencies]
credential-provider-core = "0.1"
```

Add `credential-provider` to an application, enabling the required backends:

```toml
[dependencies]
credential-provider = { version = "0.1", features = ["vault", "env"] }
```

## Design Principles

**Zero-dependency core.** `credential-provider-core` must never take on external dependencies beyond `secrecy`, `thiserror`, and `tokio` primitives. This keeps the trait definition cheap for any library to depend on.

**Transparent caching.** Consumers call `get()` and always receive valid credentials. The caching and renewal lifecycle is owned entirely by the provider, not the consumer. Consumers never manage lease durations, renewal timers, or retry logic.

**Zeroize on drop.** All credential types use `secrecy::SecretString` and `secrecy::SecretVec<u8>` to ensure sensitive material is zeroed from memory when the value is dropped.

**Test-first.** The `env` feature is always compiled (no feature flag required) and is designed as both the development default and the test double. No external service is needed to test code that depends on `credential-provider-core`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, commit conventions, and release process.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
