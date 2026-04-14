// SPEC: docs/spec/interfaces/credential-types.md

use std::time::Instant;

use secrecy::{SecretString, SecretVec};

use crate::Credential;
use secrecy::ExposeSecret;

/// A username and password pair, optionally carrying an expiry instant.
///
/// Used for queue brokers (RabbitMQ, NATS), databases, and similar
/// username/password authentication schemes.
///
/// The `password` field uses `SecretString` and is zeroed from memory on drop.
/// The `Debug` implementation redacts the password value automatically.
///
/// See: docs/spec/interfaces/credential-types.md
#[derive(Clone)]
pub struct UsernamePassword {
    /// The plaintext username.
    pub username: String,
    /// The password. Zeroed on drop; redacted in `Debug` output.
    pub password: SecretString,
    /// When these credentials expire, if known. `None` means no expiry.
    pub expires_at: Option<Instant>,
}

impl std::fmt::Debug for UsernamePassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsernamePassword")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Credential for UsernamePassword {
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

impl UsernamePassword {
    /// Constructs a new `UsernamePassword` credential.
    pub fn new(
        username: impl Into<String>,
        password: SecretString,
        expires_at: Option<Instant>,
    ) -> Self {
        Self {
            username: username.into(),
            password,
            expires_at,
        }
    }
}

// ---------------------------------------------------------------------------

/// An opaque bearer token used in HTTP `Authorization` headers.
///
/// Carries an optional expiry derived from the token issuer's response.
/// The `token` field uses `SecretString` and is zeroed from memory on drop.
///
/// See: docs/spec/interfaces/credential-types.md
#[derive(Clone)]
pub struct BearerToken {
    /// The token value. Zeroed on drop; redacted in `Debug` output.
    pub token: SecretString,
    /// When this token expires, if known. `None` means no expiry.
    pub expires_at: Option<Instant>,
}

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BearerToken")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Credential for BearerToken {
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

impl BearerToken {
    /// Constructs a new `BearerToken` credential.
    pub fn new(token: SecretString, expires_at: Option<Instant>) -> Self {
        Self { token, expires_at }
    }
}

// ---------------------------------------------------------------------------

/// A symmetric key used for HMAC signature verification.
///
/// Primarily used for GitHub webhook signature verification. HMAC keys do not
/// expire — rotation is handled externally on a policy schedule.
///
/// `is_valid()` always returns `true`. `expires_at()` always returns `None`.
///
/// The `key` field uses `SecretVec<u8>` and is zeroed from memory on drop.
///
/// See: docs/spec/interfaces/credential-types.md
pub struct HmacSecret {
    /// The raw key bytes. Zeroed on drop; redacted in `Debug` output.
    pub key: SecretVec<u8>,
}

impl std::fmt::Debug for HmacSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacSecret")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Credential for HmacSecret {
    /// Always returns `true`. HMAC secrets do not expire.
    fn is_valid(&self) -> bool {
        true
    }

    /// Always returns `None`. HMAC secrets do not have an expiry.
    fn expires_at(&self) -> Option<Instant> {
        None
    }
}

impl Clone for HmacSecret {
    fn clone(&self) -> Self {
        Self {
            key: SecretVec::new(self.key.expose_secret().to_vec()),
        }
    }
}

impl HmacSecret {
    /// Constructs a new `HmacSecret` from raw key bytes.
    pub fn new(key: SecretVec<u8>) -> Self {
        Self { key }
    }
}

// ---------------------------------------------------------------------------

/// A certificate and private key pair for mutual TLS (mTLS) authentication.
///
/// Used when connecting to services that require client certificate
/// verification (e.g., Vault PKI-issued certificates).
///
/// Both fields use `SecretVec<u8>` and are zeroed from memory on drop.
///
/// See: docs/spec/interfaces/credential-types.md
pub struct TlsClientCertificate {
    /// PEM-encoded certificate. Zeroed on drop; redacted in `Debug` output.
    pub certificate_pem: SecretVec<u8>,
    /// PEM-encoded private key. Zeroed on drop; redacted in `Debug` output.
    pub private_key_pem: SecretVec<u8>,
    /// When this certificate expires, if known.
    pub expires_at: Option<Instant>,
}

impl std::fmt::Debug for TlsClientCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClientCertificate")
            .field("certificate_pem", &"[REDACTED]")
            .field("private_key_pem", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Credential for TlsClientCertificate {
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

impl Clone for TlsClientCertificate {
    fn clone(&self) -> Self {
        Self {
            certificate_pem: SecretVec::new(self.certificate_pem.expose_secret().to_vec()),
            private_key_pem: SecretVec::new(self.private_key_pem.expose_secret().to_vec()),
            expires_at: self.expires_at,
        }
    }
}

impl TlsClientCertificate {
    /// Constructs a new `TlsClientCertificate`.
    pub fn new(
        certificate_pem: SecretVec<u8>,
        private_key_pem: SecretVec<u8>,
        expires_at: Option<Instant>,
    ) -> Self {
        Self {
            certificate_pem,
            private_key_pem,
            expires_at,
        }
    }
}
