// SPEC: docs/spec/interfaces/aws-adapter.md
//
// This module is gated behind the `aws` feature flag.
#![allow(dead_code)]

use std::time::Instant;

use credential_provider_core::{Credential, CredentialError, CredentialProvider};

// ---------------------------------------------------------------------------
// AwsCredentials
// ---------------------------------------------------------------------------

/// AWS credentials wrapping the `aws-credential-types` value type.
///
/// `AwsCredentials` is defined in this crate (not core) because it wraps
/// AWS-specific types. It implements [`Credential`] so it can be used with
/// `CachingCredentialProvider`.
///
/// # Fields
///
/// - `access_key_id` — the AWS access key ID (not a secret value)
/// - `secret_access_key` — the secret access key (secret, handled via the
///   underlying SDK type)
/// - `session_token` — optional STS session token for temporary credentials
/// - `expires_at` — expiry from the credential source, if any
///
/// # Validity
///
/// Valid until `expires_at` if set; always valid if `expires_at` is `None`
/// (e.g., long-lived access key credentials).
///
/// See: docs/spec/interfaces/aws-adapter.md
#[derive(Clone, Debug)]
pub struct AwsCredentials {
    inner: aws_credential_types::Credentials,
    expires_at: Option<Instant>,
}

impl Credential for AwsCredentials {
    fn is_valid(&self) -> bool {
        match self.expires_at {
            None => true,
            Some(expiry) => Instant::now() < expiry,
        }
    }

    fn expires_at(&self) -> Option<Instant> {
        self.expires_at
    }
}

impl AwsCredentials {
    /// Returns a reference to the underlying AWS SDK credentials.
    pub fn inner(&self) -> &aws_credential_types::Credentials {
        &self.inner
    }
}

// ---------------------------------------------------------------------------
// AwsCredentialProvider
// ---------------------------------------------------------------------------

/// A [`CredentialProvider<AwsCredentials>`] that delegates to the AWS
/// credential chain via `aws-config`.
///
/// `AwsCredentialProvider` wraps the standard AWS credential resolution chain,
/// which resolves credentials in the following order:
/// 1. IAM role (EC2 instance profile, ECS task role, EKS service account)
/// 2. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, etc.)
/// 3. `~/.aws/credentials` and `~/.aws/config`
/// 4. Instance metadata service (IMDS)
///
/// # Construction
///
/// `new()` is async because it loads the AWS configuration and initializes the
/// credential chain, which may involve network calls to IMDS or STS.
///
/// ```rust,ignore
/// use credential_provider::aws::AwsCredentialProvider;
///
/// let provider = AwsCredentialProvider::new().await?;
/// ```
///
/// # Token Expiry
///
/// The returned `AwsCredentials` carries the expiry from the credential source
/// when the source provides one (e.g., STS AssumeRole tokens). Long-lived
/// access key credentials have no expiry.
///
/// # Errors
///
/// | AWS condition                        | `CredentialError` variant      |
/// |--------------------------------------|-------------------------------|
/// | No credential source found           | `Configuration("…")`          |
/// | IMDS / STS endpoint unreachable      | `Unreachable("…")`            |
/// | STS returned an error response       | `Backend("…")`                |
///
/// See: docs/spec/interfaces/aws-adapter.md
pub struct AwsCredentialProvider {
    config: aws_config::SdkConfig,
}

impl AwsCredentialProvider {
    /// Loads the AWS configuration and initializes the credential chain.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::Configuration`] if no credential source is
    /// configured in the environment.
    pub async fn new() -> Result<Self, CredentialError> {
        unimplemented!("See docs/spec/interfaces/aws-adapter.md")
    }
}

impl CredentialProvider<AwsCredentials> for AwsCredentialProvider {
    async fn get(&self) -> Result<AwsCredentials, CredentialError> {
        unimplemented!("See docs/spec/interfaces/aws-adapter.md")
    }
}
