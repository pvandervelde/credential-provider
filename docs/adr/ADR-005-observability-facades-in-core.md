# ADR-005: Permit Observability Facade Crates in credential-provider-core

Status: Accepted
Date: 2026-04-20
Owners: credential-provider team

## Context

The caching spec (`docs/spec/interfaces/caching.md`) requires two observability behaviours when a stale credential is returned on a refresh failure:

1. Emit a `warn!` log with the stale credential age and the refresh error
2. Increment a `credential_cache_stale_fallbacks_total` counter

These behaviours live inside `CachingCredentialProvider`, which is implemented in `credential-provider-core`. The existing constraints document (`docs/spec/constraints.md`) forbids "Any logging/tracing framework" from the core crate, stating that "consumers choose their own."

That constraint was written to prevent the core crate from forcing a concrete observability stack on consumers — for example, pulling in `tracing-subscriber`, `env_logger`, or a Prometheus exporter would dictate the runtime infrastructure for every consumer, regardless of their environment. The intent was correct and remains unchanged.

However, the ecosystem has a well-established pattern for this problem: **zero-implementation facade crates**. `tracing` (for structured logging) and `metrics` (for counters and gauges) declare the observability API — macros, traits, and registration hooks — but ship **no backend implementation**. By default, `tracing` discards every event and `metrics` is a no-op. Consumers opt in to a backend by installing a subscriber or recorder (e.g., `tracing-subscriber`, `metrics-exporter-prometheus`) without any change to the core crate.

The existing constraint conflated the facade with its backends. It was written before the caching observability requirements were finalised, and it must be amended to reflect the distinction.

## Decision

**Permit** zero-implementation observability facade crates (`tracing`, `metrics`) in `credential-provider-core`.

**Continue to forbid** concrete logging, tracing, or metrics implementations (e.g., `tracing-subscriber`, `env_logger`, `prometheus`, `metrics-exporter-prometheus`) from `credential-provider-core`.

The rule becomes: *the core crate may declare observability API surface through facades, but must not install any backend or force one on consumers.*

This ADR amends the "Forbidden Dependencies in Core" section of `docs/spec/constraints.md` accordingly (see Implementation notes).

## Consequences

**Enables:**

- `warn!` macro calls in `CachingCredentialProvider::get()` when returning a stale credential on refresh failure
- `metrics::counter!` instrumentation for `credential_cache_stale_fallbacks_total`
- Consumers who install a `tracing` subscriber see the structured logs automatically, with no change to core
- Consumers who install a `metrics` recorder see the counters automatically, with no change to core
- Consumers who install neither continue to work correctly — facades default to no-ops

**Forbids:**

- Concrete subscriber or exporter crates in `credential-provider-core` (these force a runtime implementation on consumers)
- Any crate that writes to stderr, stdout, or a file as a side-effect of being linked (e.g., `env_logger`)
- New observability dependencies that are not zero-implementation facades

**Trade-offs:**

- The core crate gains two small compile-time dependencies (`tracing` and `metrics`). Both are widely used in the Rust ecosystem and maintain stable APIs with a v1 commitment for `tracing` macros
- Consumers who do not want any observability must accept the facade as a transitive dependency; because the crates ship no runtime I/O, this is a compile-time cost only

## Alternatives considered

### Option A: Move observability to the adapter layer

Emit the `warn!` and counter from the adapter crate (`credential-provider`) rather than from the caching type itself.

**Why not:** `CachingCredentialProvider` lives in `credential-provider-core` and is the only code that knows whether a stale fallback occurred. The adapter has no visibility into the caching decision. Moving the type to the adapter crate would collapse the hexagonal boundary and add backend SDK dependencies to what is meant to be a portable, backend-agnostic core. This contradicts ADR-001.

### Option B: Skip observability in core

Remove the `warn!` and counter requirements from the caching spec.

**Why not:** Stale-fallback events represent a degraded operational state. Without a log or counter, operators have no signal that the system is serving outdated credentials. This violates the intent of ADR-003 (stale fallback is a recovery mechanism, not silent data) and the caching spec's Rule 5: "warn when serving stale credentials."

### Option C: Inject observability through callbacks or traits

Add a generic parameter or trait object to `CachingCredentialProvider` for event reporting:

```rust
pub struct CachingCredentialProvider<C, O: ObservabilityHook> { ... }
```

**Why not:** Facade crates are the standard Rust solution for this problem and are already ubiquitous in the ecosystem. Adding a custom hook API increases the public surface, complicates the type signature, requires consumers to implement a trait for a concern that facades handle automatically, and provides no benefit over the facade pattern. The API complexity cost is not justified.

## Implementation notes

- Add `tracing = "0.1"` and `metrics = "0.24"` to `[workspace.dependencies]` in the root `Cargo.toml`
- Add both as regular (non-optional) dependencies in `credential-provider-core/Cargo.toml`
- Use the `tracing::warn!` macro for stale-fallback log lines; include both the stale age and the refresh error
- Use `metrics::counter!("credential_cache_stale_fallbacks_total", 1)` on each stale return
- Do **not** call `tracing::subscriber::set_global_default` or `metrics::set_global_recorder` anywhere in core
- Amend `docs/spec/constraints.md`, "Forbidden Dependencies in Core" bullet, to read:
  > Concrete logging/tracing or metrics implementations (e.g., `tracing-subscriber`, `env_logger`, `prometheus`); use zero-implementation facade crates (`tracing`, `metrics`) instead — see ADR-005

## Examples

**Stale fallback with observability (in CachingCredentialProvider):**

```rust
use tracing::warn;
use metrics::counter;

// Refresh failed; return stale credential if available
if let Some(cached) = stale_cached {
    let age_secs = cached.fetched_at.elapsed().as_secs();
    warn!(
        stale_age_seconds = age_secs,
        error = %refresh_error,
        "Refresh failed; returning stale credential"
    );
    counter!("credential_cache_stale_fallbacks_total", 1);
    return Ok(cached.credential.clone());
}
```

**Consumer wiring — the consumer, not the core, installs the backend:**

```rust
// Application main — install backends once
tracing_subscriber::fmt::init();
let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
metrics::set_global_recorder(recorder).unwrap();

// Core crate usage is unchanged
let provider = CachingCredentialProvider::new(inner, config);
```

## References

- `docs/spec/interfaces/caching.md` — Rule 5 (stale fallback observability)
- `docs/spec/constraints.md` — Forbidden Dependencies in Core (amended by this ADR)
- ADR-001 — Hexagonal architecture (core must remain backend-agnostic)
- ADR-003 — Stale fallback on refresh failure
- [`tracing` crate](https://docs.rs/tracing) — zero-cost structured logging facade
- [`metrics` crate](https://docs.rs/metrics) — metrics recording facade
