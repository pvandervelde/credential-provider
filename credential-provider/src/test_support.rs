// SPEC: docs/spec/interfaces/test-support.md
//
// Re-exports MockCredentialProvider from credential-provider-core for use
// by downstream test code.
//
// This module must never be compiled into production builds. It is gated on
// cfg(any(test, feature = "test-support")) and the `test-support` Cargo feature
// must never appear in production profiles.

#[cfg(any(test, feature = "test-support"))]
pub use credential_provider_core::mock::MockCredentialProvider;
