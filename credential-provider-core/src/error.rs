// SPEC: docs/spec/interfaces/shared-types.md — CredentialError

/// Classified error from a credential fetch operation.
///
/// Each variant represents a distinct failure category so that consumers
/// can decide how to react (retry, fix configuration, fail the operation,
/// re-authenticate, etc.).
///
/// `CredentialError` messages must never include credential values — only
/// contextual information such as paths, variable names, or HTTP status codes.
///
/// New variants may be added in minor releases. Match arms against this type
/// should include a wildcard arm for forward compatibility.
///
/// See: docs/spec/interfaces/shared-types.md
#[derive(Debug, Clone, thiserror::Error)]
pub enum CredentialError {
    /// The backing store returned an error response (HTTP 500, malformed
    /// response body, unexpected format, etc.). The provider translated the
    /// backend-specific error into this variant.
    ///
    /// Typical consumer reaction: retry with backoff.
    #[error("credential backend error: {0}")]
    Backend(String),

    /// The backing store could not be contacted (connection refused, DNS
    /// failure, timeout).
    ///
    /// Distinguished from `Backend` because the remediation differs:
    /// `Unreachable` signals a network or infrastructure issue rather than
    /// a store-side error.
    ///
    /// Typical consumer reaction: retry, check network connectivity.
    #[error("credential backend unreachable: {0}")]
    Unreachable(String),

    /// The provider is misconfigured — a required environment variable is
    /// missing or empty, a Vault path does not exist, or a required field is
    /// absent from the backend response.
    ///
    /// This is a deployment-time error, not a runtime transient. Retrying
    /// will not help without a configuration change.
    ///
    /// Typical consumer reaction: surface to operator, fail the operation.
    #[error("invalid credential configuration: {0}")]
    Configuration(String),

    /// No credential is available and no cached value exists.
    ///
    /// This is the terminal state when both a live fetch and any cache
    /// fallback have failed (or when the cache is empty and the first fetch
    /// fails).
    ///
    /// Typical consumer reaction: fail the operation.
    #[error("no credential available")]
    Unavailable,

    /// The credential was explicitly revoked before its natural expiry.
    ///
    /// Distinct from expiry — revocation is an active action by an operator
    /// or policy, not a time-based event.
    ///
    /// Typical consumer reaction: re-authenticate or escalate to operator.
    #[error("credential revoked")]
    Revoked,
}
