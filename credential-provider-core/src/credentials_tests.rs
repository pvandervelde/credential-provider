//! Tests for credential value types.
//!
//! Coverage: A-CRED-1 through A-CRED-4 (docs/spec/assertions.md).
//! Exercises is_valid(), expires_at(), and Debug redaction for all four types.

use std::time::{Duration, Instant};

use secrecy::{ExposeSecret, SecretString, SecretVec};

use super::{BearerToken, HmacSecret, TlsClientCertificate, UsernamePassword};
use crate::Credential;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn past() -> Instant {
    Instant::now() - Duration::from_secs(10)
}

fn future() -> Instant {
    Instant::now() + Duration::from_secs(3600)
}

// ── UsernamePassword ─────────────────────────────────────────────────────────

/// A-CRED-1: no-expiry UsernamePassword is always valid.
#[test]
fn test_username_password_no_expiry_is_valid() {
    let cred = UsernamePassword::new("user", SecretString::new("pass".into()), None);
    assert!(cred.is_valid(), "no-expiry UsernamePassword must be valid");
}

/// A-CRED-1: no-expiry expires_at() is None.
#[test]
fn test_username_password_no_expiry_expires_at_is_none() {
    let cred = UsernamePassword::new("user", SecretString::new("pass".into()), None);
    assert!(cred.expires_at().is_none());
}

/// A-CRED-2: future-expiry UsernamePassword is valid.
#[test]
fn test_username_password_future_expiry_is_valid() {
    let cred = UsernamePassword::new("user", SecretString::new("pass".into()), Some(future()));
    assert!(
        cred.is_valid(),
        "future-expiry UsernamePassword must be valid"
    );
}

/// A-CRED-3: past-expiry UsernamePassword is invalid.
#[test]
fn test_username_password_past_expiry_is_invalid() {
    let cred = UsernamePassword::new("user", SecretString::new("pass".into()), Some(past()));
    assert!(
        !cred.is_valid(),
        "past-expiry UsernamePassword must be invalid"
    );
}

/// expires_at() returns the stored instant.
#[test]
fn test_username_password_expires_at_returns_stored_value() {
    let exp = future();
    let cred = UsernamePassword::new("user", SecretString::new("pass".into()), Some(exp));
    assert_eq!(cred.expires_at(), Some(exp));
}

/// Debug output: username is visible; password is redacted.
#[test]
fn test_username_password_debug_shows_username_and_redacts_password() {
    let cred = UsernamePassword::new("alice", SecretString::new("hunter2".into()), None);
    let debug = format!("{cred:?}");
    assert!(
        debug.contains("alice"),
        "username must be visible in Debug output; got: {debug}"
    );
    assert!(
        debug.contains("REDACTED"),
        "password must be redacted in Debug output; got: {debug}"
    );
    assert!(
        !debug.contains("hunter2"),
        "password value must not appear in Debug output; got: {debug}"
    );
}

// ── BearerToken ───────────────────────────────────────────────────────────────

/// A-CRED-1: no-expiry BearerToken is always valid.
#[test]
fn test_bearer_token_no_expiry_is_valid() {
    let cred = BearerToken::new(SecretString::new("tok".into()), None);
    assert!(cred.is_valid(), "no-expiry BearerToken must be valid");
}

/// A-CRED-1: no-expiry expires_at() is None.
#[test]
fn test_bearer_token_no_expiry_expires_at_is_none() {
    let cred = BearerToken::new(SecretString::new("tok".into()), None);
    assert!(cred.expires_at().is_none());
}

/// A-CRED-2: future-expiry BearerToken is valid.
#[test]
fn test_bearer_token_future_expiry_is_valid() {
    let cred = BearerToken::new(SecretString::new("tok".into()), Some(future()));
    assert!(cred.is_valid(), "future-expiry BearerToken must be valid");
}

/// A-CRED-3: past-expiry BearerToken is invalid.
///
/// Stub-killer: also kills `< → >` and `< → ==` mutations in is_valid().
#[test]
fn test_bearer_token_past_expiry_is_invalid() {
    let cred = BearerToken::new(SecretString::new("tok".into()), Some(past()));
    assert!(!cred.is_valid(), "past-expiry BearerToken must be invalid");
}

/// expires_at() returns the stored instant.
///
/// Stub-killer: kills `expires_at → None` mutation.
#[test]
fn test_bearer_token_expires_at_returns_stored_value() {
    let exp = future();
    let cred = BearerToken::new(SecretString::new("tok".into()), Some(exp));
    assert_eq!(
        cred.expires_at(),
        Some(exp),
        "expires_at must return the stored instant"
    );
}

/// Debug output: token value is redacted.
#[test]
fn test_bearer_token_debug_redacts_token() {
    let cred = BearerToken::new(SecretString::new("supersecrettoken".into()), None);
    let debug = format!("{cred:?}");
    assert!(
        debug.contains("REDACTED"),
        "token must be redacted in Debug output; got: {debug}"
    );
    assert!(
        !debug.contains("supersecrettoken"),
        "token value must not appear in Debug output; got: {debug}"
    );
}

// ── HmacSecret ────────────────────────────────────────────────────────────────

/// A-CRED-4: HmacSecret is always valid.
#[test]
fn test_hmac_secret_is_always_valid() {
    let cred = HmacSecret::new(SecretVec::new(vec![1u8, 2, 3, 4]));
    assert!(cred.is_valid(), "HmacSecret must always be valid");
}

/// A-CRED-4: HmacSecret expires_at() is always None.
#[test]
fn test_hmac_secret_expires_at_is_always_none() {
    let cred = HmacSecret::new(SecretVec::new(vec![1u8, 2, 3, 4]));
    assert!(
        cred.expires_at().is_none(),
        "HmacSecret must never have an expiry"
    );
}

/// Debug output: key bytes are redacted.
#[test]
fn test_hmac_secret_debug_redacts_key() {
    let cred = HmacSecret::new(SecretVec::new(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    let debug = format!("{cred:?}");
    assert!(
        debug.contains("REDACTED"),
        "key must be redacted in Debug output; got: {debug}"
    );
}

// ── TlsClientCertificate ──────────────────────────────────────────────────────

fn tls_cert(expires_at: Option<Instant>) -> TlsClientCertificate {
    TlsClientCertificate::new(
        SecretVec::new(b"cert-bytes".to_vec()),
        SecretVec::new(b"key-bytes".to_vec()),
        expires_at,
    )
}

/// A-CRED-1: no-expiry TlsClientCertificate is always valid.
#[test]
fn test_tls_client_cert_no_expiry_is_valid() {
    let cred = tls_cert(None);
    assert!(
        cred.is_valid(),
        "no-expiry TlsClientCertificate must be valid"
    );
}

/// A-CRED-1: no-expiry expires_at() is None.
#[test]
fn test_tls_client_cert_no_expiry_expires_at_is_none() {
    let cred = tls_cert(None);
    assert!(cred.expires_at().is_none());
}

/// A-CRED-2: future-expiry TlsClientCertificate is valid.
#[test]
fn test_tls_client_cert_future_expiry_is_valid() {
    let cred = tls_cert(Some(future()));
    assert!(
        cred.is_valid(),
        "future-expiry TlsClientCertificate must be valid"
    );
}

/// A-CRED-3: past-expiry TlsClientCertificate is invalid.
///
/// Stub-killer: also kills `< → >` and `< → ==` mutations in is_valid().
#[test]
fn test_tls_client_cert_past_expiry_is_invalid() {
    let cred = tls_cert(Some(past()));
    assert!(
        !cred.is_valid(),
        "past-expiry TlsClientCertificate must be invalid"
    );
}

/// expires_at() returns the stored instant.
///
/// Stub-killer: kills `expires_at → None` mutation.
#[test]
fn test_tls_client_cert_expires_at_returns_stored_value() {
    let exp = future();
    let cred = tls_cert(Some(exp));
    assert_eq!(
        cred.expires_at(),
        Some(exp),
        "expires_at must return the stored instant"
    );
}

/// Debug output: both PEM fields are redacted.
#[test]
fn test_tls_client_cert_debug_redacts_pem_fields() {
    let cred = TlsClientCertificate::new(
        SecretVec::new(b"cert-secret-material".to_vec()),
        SecretVec::new(b"key-secret-material".to_vec()),
        None,
    );
    let debug = format!("{cred:?}");
    assert!(
        debug.contains("REDACTED"),
        "PEM fields must be redacted in Debug output; got: {debug}"
    );
    assert!(
        !debug.contains("cert-secret-material"),
        "certificate PEM must not appear in Debug output; got: {debug}"
    );
    assert!(
        !debug.contains("key-secret-material"),
        "private key PEM must not appear in Debug output; got: {debug}"
    );
}

// ── Clone isolation ───────────────────────────────────────────────────────────
// HmacSecret and TlsClientCertificate both have hand-written Clone
// implementations that copy bytes via ExposeSecret rather than sharing memory.
// These tests verify that a clone is an independent allocation, not a shared
// reference — as required by docs/spec/testing.md.

/// Clone produces an independent copy of HmacSecret key bytes.
///
/// Verifies that the cloned SecretVec contains the same bytes at a different
/// memory address, confirming no shared allocation.
#[test]
fn test_hmac_secret_clone_is_independent() {
    let original = HmacSecret::new(SecretVec::new(vec![1u8, 2, 3, 4]));
    let cloned = original.clone();
    assert_eq!(
        original.key.expose_secret(),
        cloned.key.expose_secret(),
        "cloned HmacSecret must contain the same bytes as the original"
    );
    assert_ne!(
        original.key.expose_secret().as_ptr(),
        cloned.key.expose_secret().as_ptr(),
        "cloned HmacSecret must be a separate allocation, not a shared reference"
    );
}

/// Clone produces an independent copy of TlsClientCertificate PEM bytes.
///
/// Checks both the certificate and private key fields for independent
/// allocations.
#[test]
fn test_tls_client_cert_clone_is_independent() {
    let original = tls_cert(Some(future()));
    let cloned = original.clone();
    assert_eq!(
        original.certificate_pem.expose_secret(),
        cloned.certificate_pem.expose_secret(),
        "cloned TlsClientCertificate certificate_pem must contain the same bytes"
    );
    assert_ne!(
        original.certificate_pem.expose_secret().as_ptr(),
        cloned.certificate_pem.expose_secret().as_ptr(),
        "cloned TlsClientCertificate certificate_pem must be a separate allocation"
    );
    assert_eq!(
        original.private_key_pem.expose_secret(),
        cloned.private_key_pem.expose_secret(),
        "cloned TlsClientCertificate private_key_pem must contain the same bytes"
    );
    assert_ne!(
        original.private_key_pem.expose_secret().as_ptr(),
        cloned.private_key_pem.expose_secret().as_ptr(),
        "cloned TlsClientCertificate private_key_pem must be a separate allocation"
    );
}
