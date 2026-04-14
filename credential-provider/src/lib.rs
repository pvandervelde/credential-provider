// credential-provider
//
// Backend adapters implementing CredentialProvider<C> for env, Vault,
// Azure, and AWS. Each backend is gated behind a Cargo feature flag.
//
// This crate re-exports credential-provider-core so applications can use
// a single dependency.
//
// SPEC: docs/spec/credential-provider.md

// Re-export the entire core public API so applications only need to depend
// on this crate.
pub use credential_provider_core::*;

#[cfg(feature = "env")]
pub mod env;

#[cfg(feature = "vault")]
pub mod vault;

#[cfg(feature = "azure")]
pub mod azure;

#[cfg(feature = "aws")]
pub mod aws;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
