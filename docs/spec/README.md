# Architectural Specification — credential-provider

## Purpose

This folder contains the architectural specification for the `credential-provider` workspace: a Rust workspace of two crates that provide provider-agnostic credential management for Rust services.

## Document Index

| Document | Contents |
|---|---|
| [overview.md](overview.md) | System context, high-level design, crate relationship diagram |
| [vocabulary.md](vocabulary.md) | Domain concepts, naming conventions, and definitions |
| [responsibilities.md](responsibilities.md) | Responsibility-Driven Design (RDD): what each component knows and does |
| [architecture.md](architecture.md) | Clean architecture boundaries: business logic, abstractions, infrastructure |
| [assertions.md](assertions.md) | Testable behavioral assertions for all components |
| [constraints.md](constraints.md) | Implementation rules: type system, module boundaries, error handling |
| [tradeoffs.md](tradeoffs.md) | Design alternatives considered, with pros/cons and decisions |
| [testing.md](testing.md) | Testing strategy: unit, integration, contract, and mock approaches |
| [security.md](security.md) | Threat model, mitigations, and security invariants |
| [edge-cases.md](edge-cases.md) | Non-standard flows, failure modes, and recovery behavior |
| [operations.md](operations.md) | Deployment patterns, observability, and configuration |
| [credential-provider-core.md](credential-provider-core.md) | Full crate specification for the core crate |
| [credential-provider.md](credential-provider.md) | Full crate specification for the adapter crate |

## Workflow

This specification was produced by the **Architect** and feeds the following downstream workflow:

```
Architect (this spec)
    ↓ docs/spec/
Interface Designer
    ↓ concrete types, module contracts, stubs
Planner
    ↓ tasks.md
Coder
    ↓ implementation
```

### For the Interface Designer

Start with:

1. **[vocabulary.md](vocabulary.md)** — establishes the names and definitions for all types
2. **[responsibilities.md](responsibilities.md)** — tells you what each component knows and does
3. **[architecture.md](architecture.md)** — shows the dependency direction and boundary rules
4. **[constraints.md](constraints.md)** — the hard rules your interfaces must satisfy
5. **[assertions.md](assertions.md)** — the behavioral contracts your types must support

The crate specifications ([credential-provider-core.md](credential-provider-core.md) and [credential-provider.md](credential-provider.md)) contain detailed API examples and usage patterns.

### Key Architectural Decisions

1. **Hexagonal architecture** — core defines ports (traits), adapter crate provides implementations
2. **Zero-dependency core** — `credential-provider-core` depends only on `secrecy`, `thiserror`, `tokio`
3. **Feature-flag isolation** — each backend is a separate Cargo feature in `credential-provider`
4. **Transparent caching with stale fallback** — `CachingCredentialProvider` handles all renewal; consumers just call `get()`
5. **Zeroize-on-drop** — all secret material uses `secrecy` types for automatic memory zeroing
6. **Result-based error handling** — `CredentialError` enum, no panics for expected failures
