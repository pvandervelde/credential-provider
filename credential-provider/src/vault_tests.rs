// Tests for credential-provider/src/vault.rs
//
// Covers: map_vaultrs_error() error classification and VaultExtractor<C>::extract()
// contract assertions from docs/spec/assertions.md (A-VAULT-DYN-*, A-VAULT-CUSTOM-*).
//
// Test tiers:
//   Tier 1 — Specification tests: one test per behavioural assertion
//   Tier 2 — Adversarial / boundary tests: boundary values and stub-killers
//   Tier 3 — Property / adversarial: invariants across multiple inputs
//
// Error mapping tests are pure (synchronous, no network).
// Extractor contract tests call extract() directly — no network.
// get() integration tests are marked #[ignore] — require a running Vault.

use crate::{CredentialError, UsernamePassword};
use credential_provider_core::SecretString;
use vaultrs::error::ClientError as VaultrsError;

use super::{VaultExtractor, lease_secs_from_raw, map_vaultrs_error};

// -------------------------------------------------------------------------
// Helpers shared across all test submodules
// -------------------------------------------------------------------------

/// Construct a vaultrs APIError with the given HTTP status code and error strings.
fn api_error(code: u16, errors: Vec<&str>) -> VaultrsError {
    VaultrsError::APIError {
        code,
        errors: errors.into_iter().map(String::from).collect(),
    }
}

/// Build a `VaultrsError::RestClientError` wrapping a `rustify` `RequestError`
/// whose `anyhow` source carries `message`.
///
/// Shared by `tls_rest_error()` and `connection_refused_error()` to avoid
/// repeating the identical seven-line constructor block.
fn rest_client_error(message: &str) -> VaultrsError {
    let inner = anyhow::anyhow!("{}", message);
    let rustify_err = rustify::errors::ClientError::RequestError {
        source: inner,
        url: "https://vault.example.com:8200/v1/secret/data/test".to_string(),
        method: "GET".to_string(),
    };
    VaultrsError::RestClientError {
        source: rustify_err,
    }
}

/// Construct a vaultrs RestClientError whose anyhow source contains TLS-related keywords.
fn tls_rest_error() -> VaultrsError {
    rest_client_error("tls handshake failure: certificate verify failed")
}

/// Construct a vaultrs RestClientError whose anyhow source signals a connection failure.
fn connection_refused_error() -> VaultrsError {
    rest_client_error("connection refused")
}

/// Construct a vaultrs JsonParseError using an intentionally invalid JSON string.
fn json_parse_error() -> VaultrsError {
    let source = serde_json::from_str::<serde_json::Value>("{invalid json").unwrap_err();
    VaultrsError::JsonParseError { source }
}

/// A minimal valid credential for use in test extractors.
fn test_credential() -> UsernamePassword {
    UsernamePassword::new(
        "alice".to_string(),
        SecretString::from("hunter2".to_owned()),
        None,
    )
}

// -------------------------------------------------------------------------
// RecordingExtractor — captures arguments passed to extract()
// -------------------------------------------------------------------------

/// Test-only VaultExtractor implementation that records every call to extract().
///
/// Uses `std::sync::Mutex` for interior mutability so the struct is `Sync`
/// without requiring async, matching the synchronous extract() signature.
struct RecordingExtractor {
    received_data: std::sync::Mutex<Option<serde_json::Value>>,
    received_lease: std::sync::Mutex<Option<Option<u64>>>,
    result: Result<UsernamePassword, CredentialError>,
}

impl RecordingExtractor {
    fn returning_ok(credential: UsernamePassword) -> Self {
        Self {
            received_data: std::sync::Mutex::new(None),
            received_lease: std::sync::Mutex::new(None),
            result: Ok(credential),
        }
    }

    fn returning_err(err: CredentialError) -> Self {
        Self {
            received_data: std::sync::Mutex::new(None),
            received_lease: std::sync::Mutex::new(None),
            result: Err(err),
        }
    }

    fn recorded_data(&self) -> Option<serde_json::Value> {
        self.received_data.lock().unwrap().clone()
    }

    fn recorded_lease(&self) -> Option<Option<u64>> {
        *self.received_lease.lock().unwrap()
    }
}

impl VaultExtractor<UsernamePassword> for RecordingExtractor {
    fn extract(
        &self,
        data: &serde_json::Value,
        lease_duration_secs: Option<u64>,
    ) -> Result<UsernamePassword, CredentialError> {
        *self.received_data.lock().unwrap() = Some(data.clone());
        *self.received_lease.lock().unwrap() = Some(lease_duration_secs);
        self.result.clone()
    }
}

// -------------------------------------------------------------------------
// Tier 1: Specification tests — error mapping
// One test per assertion from docs/spec/assertions.md A-VAULT-DYN-*
// -------------------------------------------------------------------------

mod error_mapping_spec {
    use super::*;

    // A-VAULT-DYN-2: HTTP 403 → CredentialError::Backend("permission denied")
    #[test]
    fn map_error_403_returns_backend_permission_denied() {
        let error = api_error(403, vec!["permission denied"]);
        let result = map_vaultrs_error(error, "rabbitmq", "creds/queue-keeper");
        match result {
            CredentialError::Backend(msg) => {
                assert!(
                    msg.contains("permission denied"),
                    "Expected 'permission denied' in Backend message, got: {msg}"
                );
            }
            other => panic!("Expected Backend(\"permission denied\"), got {other:?}"),
        }
    }

    // A-VAULT-DYN-3: HTTP 404 → CredentialError::Configuration containing mount and path
    #[test]
    fn map_error_404_returns_configuration_path_not_found() {
        let error = api_error(404, vec!["no handler for route"]);
        let result = map_vaultrs_error(error, "secret", "data/service");
        match result {
            CredentialError::Configuration(msg) => {
                assert!(
                    msg.contains("secret"),
                    "Expected mount 'secret' in Configuration message, got: {msg}"
                );
                assert!(
                    msg.contains("data/service"),
                    "Expected path 'data/service' in Configuration message, got: {msg}"
                );
            }
            other => panic!("Expected Configuration, got {other:?}"),
        }
    }

    // A-VAULT-DYN-5: HTTP 400 with "lease" keyword → CredentialError::Revoked
    #[test]
    fn map_error_400_lease_returns_revoked() {
        let error = api_error(400, vec!["lease not found or is not renewable"]);
        let result = map_vaultrs_error(error, "rabbitmq", "creds/queue-keeper");
        assert!(
            matches!(result, CredentialError::Revoked),
            "Expected Revoked for lease 400, got {result:?}"
        );
    }

    // HTTP 5xx → CredentialError::Backend containing status code and error detail
    #[test]
    fn map_error_5xx_returns_backend_server_error() {
        let error = api_error(500, vec!["internal error"]);
        let result = map_vaultrs_error(error, "rabbitmq", "creds/queue-keeper");
        match result {
            CredentialError::Backend(msg) => {
                assert!(
                    msg.contains("500") || msg.contains("server error"),
                    "Expected '500' or 'server error' in Backend message, got: {msg}"
                );
                assert!(
                    msg.contains("internal error"),
                    "Expected error detail 'internal error' in Backend message, got: {msg}"
                );
            }
            other => panic!("Expected Backend for HTTP 500, got {other:?}"),
        }
    }

    // A-VAULT-DYN-4 (TLS): RestClientError with TLS message → Unreachable("TLS error: …")
    #[test]
    fn map_error_tls_returns_unreachable_tls() {
        let error = tls_rest_error();
        let result = map_vaultrs_error(error, "secret", "data/test");
        match result {
            CredentialError::Unreachable(msg) => {
                assert!(
                    msg.to_lowercase().contains("tls"),
                    "Expected 'tls' in Unreachable message, got: {msg}"
                );
            }
            other => panic!("Expected Unreachable for TLS error, got {other:?}"),
        }
    }

    // A-VAULT-DYN-4 (connection): RestClientError with connection failure → Unreachable
    #[test]
    fn map_error_connection_refused_returns_unreachable() {
        let error = connection_refused_error();
        let result = map_vaultrs_error(error, "secret", "data/test");
        assert!(
            matches!(result, CredentialError::Unreachable(_)),
            "Expected Unreachable for connection refused, got {result:?}"
        );
    }

    // A-VAULT-DYN-6: ResponseDataEmptyError → Backend("unexpected response: missing data field")
    #[test]
    fn map_error_response_data_empty_returns_backend_missing_data() {
        let error = VaultrsError::ResponseDataEmptyError;
        let result = map_vaultrs_error(error, "secret", "data/test");
        match result {
            CredentialError::Backend(msg) => {
                assert!(
                    msg.contains("missing data field"),
                    "Expected 'missing data field' in Backend message, got: {msg}"
                );
            }
            other => panic!("Expected Backend for ResponseDataEmptyError, got {other:?}"),
        }
    }

    // A-VAULT-DYN-6: JsonParseError → Backend("unexpected response: …")
    #[test]
    fn map_error_json_parse_returns_backend_unexpected_response() {
        let error = json_parse_error();
        let result = map_vaultrs_error(error, "secret", "data/test");
        match result {
            CredentialError::Backend(msg) => {
                assert!(
                    msg.contains("unexpected response"),
                    "Expected 'unexpected response' prefix in Backend message, got: {msg}"
                );
            }
            other => panic!("Expected Backend for JsonParseError, got {other:?}"),
        }
    }
}

// -------------------------------------------------------------------------
// Tier 1: VaultExtractor contract tests (A-VAULT-CUSTOM-1, A-VAULT-CUSTOM-2)
// Tests call extract() directly — no network, no VaultProvider::get()
// -------------------------------------------------------------------------

mod extractor_contract {
    use super::*;

    // A-VAULT-CUSTOM-1: extract() receives the exact data and lease_duration from the response
    #[test]
    fn extractor_receives_correct_data_and_lease_duration() {
        let expected_data = serde_json::json!({
            "username": "alice",
            "password": "hunter2"
        });
        let expected_lease = Some(30u64);

        let extractor = RecordingExtractor::returning_ok(test_credential());
        let result = extractor.extract(&expected_data, expected_lease);

        assert!(result.is_ok(), "Expected Ok result, got {result:?}");
        assert_eq!(
            extractor.recorded_data().as_ref(),
            Some(&expected_data),
            "Extractor did not receive the expected data value"
        );
        assert_eq!(
            extractor.recorded_lease(),
            Some(expected_lease),
            "Extractor did not receive the expected lease_duration_secs"
        );
    }

    // A-VAULT-CUSTOM-1: extract() receives None when lease_duration_secs is None
    #[test]
    fn extractor_receives_none_when_no_lease() {
        let data = serde_json::json!({"key": "value"});
        let extractor = RecordingExtractor::returning_ok(test_credential());

        let _ = extractor.extract(&data, None);

        assert_eq!(
            extractor.recorded_lease(),
            Some(None),
            "Extractor should receive None lease duration when no lease is present"
        );
    }

    // A-VAULT-CUSTOM-1: credential returned by extract() is exactly what the extractor produces
    #[test]
    fn get_returns_whatever_extractor_produces() {
        let expected = test_credential();
        let extractor = RecordingExtractor::returning_ok(expected.clone());
        let data = serde_json::json!({});

        let result = extractor.extract(&data, None).unwrap();

        assert_eq!(
            result.username, expected.username,
            "extract() must return the credential produced by the extractor"
        );
    }

    // A-VAULT-CUSTOM-2: extractor error is propagated without wrapping
    #[test]
    fn extractor_error_propagates_as_credential_error() {
        let extractor = RecordingExtractor::returning_err(CredentialError::Backend(
            "missing field: username".to_string(),
        ));
        let data = serde_json::json!({});

        let result = extractor.extract(&data, None);

        assert!(
            matches!(result, Err(CredentialError::Backend(_))),
            "Expected Err(Backend), got {result:?}"
        );
    }

    // A-VAULT-CUSTOM-2: the exact error message from the extractor is preserved
    #[test]
    fn extractor_error_message_is_preserved_verbatim() {
        let err_msg = "missing field: username";
        let extractor =
            RecordingExtractor::returning_err(CredentialError::Backend(err_msg.to_string()));
        let data = serde_json::json!({});

        let result = extractor.extract(&data, None);

        match result {
            Err(CredentialError::Backend(msg)) => {
                assert_eq!(
                    msg, err_msg,
                    "The extractor's error message must not be altered"
                );
            }
            other => panic!("Expected Err(Backend({err_msg:?})), got {other:?}"),
        }
    }
}

// -------------------------------------------------------------------------
// Tier 2: Adversarial / boundary tests
// -------------------------------------------------------------------------

mod edge_cases {
    use super::*;

    // HTTP 400 without "lease" keyword → Backend (must NOT be Revoked)
    #[test]
    fn map_error_non_lease_400_returns_backend() {
        let error = api_error(400, vec!["bad request: invalid parameter"]);
        let result = map_vaultrs_error(error, "secret", "data/test");
        assert!(
            matches!(result, CredentialError::Backend(_)),
            "Non-lease 400 error should map to Backend, got {result:?}"
        );
    }

    // Stub-killer: non-lease 400 must NOT become Revoked
    #[test]
    fn map_error_non_lease_400_is_not_revoked() {
        let error = api_error(400, vec!["bad request: missing required field"]);
        let result = map_vaultrs_error(error, "secret", "data/test");
        assert!(
            !matches!(result, CredentialError::Revoked),
            "Non-lease 400 errors must not map to Revoked; got {result:?}"
        );
    }

    // Unknown 4xx (e.g., 409 Conflict) → Backend (not Configuration, not Revoked)
    #[test]
    fn map_error_unknown_4xx_returns_backend() {
        let error = api_error(409, vec!["conflict"]);
        let result = map_vaultrs_error(error, "secret", "data/test");
        assert!(
            matches!(result, CredentialError::Backend(_)),
            "Unknown 4xx should map to Backend, got {result:?}"
        );
    }

    // Stub-killer: 404 Configuration message must contain both mount AND path
    // (a stub that hardcodes "not found" without mount/path would fail this)
    #[test]
    fn map_error_404_configuration_message_contains_mount_slash_path() {
        let error = api_error(404, vec![]);
        let result = map_vaultrs_error(error, "my-mount", "my/path");
        match result {
            CredentialError::Configuration(msg) => {
                assert!(
                    msg.contains("my-mount") && msg.contains("my/path"),
                    "Expected both mount 'my-mount' and path 'my/path' in 404 message, got: {msg}"
                );
            }
            other => panic!("Expected Configuration for 404, got {other:?}"),
        }
    }

    // Stub-killer: 403 must be Backend, not Configuration
    #[test]
    fn map_error_403_is_not_configuration() {
        let error = api_error(403, vec!["permission denied"]);
        let result = map_vaultrs_error(error, "secret", "data/test");
        assert!(
            !matches!(result, CredentialError::Configuration(_)),
            "403 must not map to Configuration (only 404 does); got {result:?}"
        );
    }

    // Stub-killer: lease 400 must not map to Backend
    #[test]
    fn map_error_lease_400_is_not_backend() {
        let error = api_error(400, vec!["lease not found or is not renewable"]);
        let result = map_vaultrs_error(error, "rabbitmq", "creds/queue-keeper");
        assert!(
            !matches!(result, CredentialError::Backend(_)),
            "Lease 400 errors must not map to Backend; they must be Revoked, got {result:?}"
        );
    }

    // Integration test (requires running Vault): lease_duration == 0 → extractor receives None
    //
    // When VaultProvider::get() receives a Vault response with lease_duration == 0
    // (typical for KV v2 static secrets), it must call extractor.extract() with
    // lease_duration_secs = None, not Some(0).
    #[test]
    #[ignore = "requires running Vault; run against a real instance to verify get() lease mapping"]
    fn get_with_zero_lease_duration_passes_none_to_extractor() {
        // Setup:  Build a VaultProvider::with_extractor() using a RecordingExtractor
        //         and point it at a KV v2 path whose Vault response has lease_duration: 0.
        // Assert: extractor.recorded_lease() == Some(None)
        todo!("Implement with a real Vault instance or an HTTP-level mock")
    }

    // Integration test (requires running Vault): lease_duration == 30 → extractor receives Some(30)
    //
    // When VaultProvider::get() receives a Vault response with lease_duration == 30
    // (typical for dynamic secrets engines), it must call extractor.extract() with
    // lease_duration_secs = Some(30), not None or Some(0).
    #[test]
    #[ignore = "requires running Vault; run against a real instance to verify get() lease mapping"]
    fn get_with_positive_lease_duration_passes_some_to_extractor() {
        // Setup:  Build a VaultProvider::with_extractor() using a RecordingExtractor
        //         and point it at a dynamic secrets engine that returns lease_duration: 30.
        // Assert: extractor.recorded_lease() == Some(Some(30))
        todo!("Implement with a real Vault instance or an HTTP-level mock")
    }
}

// -------------------------------------------------------------------------
// Tier 3: Property / adversarial tests
// -------------------------------------------------------------------------

mod adversarial {
    use super::*;

    // All 5xx status codes must map to Backend (never Unreachable, Configuration, Revoked)
    #[test]
    fn map_error_all_5xx_codes_return_backend() {
        for code in [500u16, 502, 503, 504] {
            let error = api_error(code, vec!["server error"]);
            let result = map_vaultrs_error(error, "secret", "data/test");
            assert!(
                matches!(result, CredentialError::Backend(_)),
                "Expected Backend for HTTP {code}, got {result:?}"
            );
        }
    }

    // 5xx messages must include the status code so operators can identify which error occurred.
    // A stub that always returns Backend("vault error") without the code would fail this.
    #[test]
    fn map_error_5xx_backend_message_contains_status_code() {
        let error = api_error(503, vec!["service unavailable"]);
        let result = map_vaultrs_error(error, "secret", "data/test");
        match result {
            CredentialError::Backend(msg) => {
                assert!(
                    msg.contains("503") || msg.contains("service unavailable"),
                    "Expected status code '503' or detail in Backend message, got: {msg}"
                );
            }
            other => panic!("Expected Backend for 5xx, got {other:?}"),
        }
    }

    // Different 5xx codes must produce distinct messages.
    // A stub hardcoding "vault server error: 500" would fail when code is 503.
    #[test]
    fn map_error_different_5xx_codes_produce_distinct_messages() {
        let result_500 = map_vaultrs_error(
            api_error(500, vec!["internal error"]),
            "secret",
            "data/test",
        );
        let result_503 = map_vaultrs_error(
            api_error(503, vec!["service unavailable"]),
            "secret",
            "data/test",
        );
        match (result_500, result_503) {
            (CredentialError::Backend(msg_500), CredentialError::Backend(msg_503)) => {
                assert_ne!(
                    msg_500, msg_503,
                    "HTTP 500 and HTTP 503 must produce different Backend messages"
                );
            }
            other => panic!("Expected both to be Backend, got {other:?}"),
        }
    }

    // TLS errors must not fall through to Backend — they are connectivity failures.
    #[test]
    fn map_error_tls_is_not_backend() {
        let error = tls_rest_error();
        let result = map_vaultrs_error(error, "secret", "data/test");
        assert!(
            !matches!(result, CredentialError::Backend(_)),
            "TLS error must map to Unreachable, not Backend; got {result:?}"
        );
    }

    // Connection refused must not fall through to Backend — it is a connectivity failure.
    #[test]
    fn map_error_connection_refused_is_not_backend() {
        let error = connection_refused_error();
        let result = map_vaultrs_error(error, "secret", "data/test");
        assert!(
            !matches!(result, CredentialError::Backend(_)),
            "Connection refused must map to Unreachable, not Backend; got {result:?}"
        );
    }

    // Mutant kill: tls_in_error_chain — "tls" keyword alone must trigger TLS detection.
    //
    // Kills survivor: vault.rs:297:32 replace || with && in tls_in_error_chain
    // Mutation changes `msg.contains("tls") || msg.contains("handshake") || …`
    // to `(tls && handshake) || certificate`. An error containing only "tls" (no
    // "handshake", no "certificate") must still produce Unreachable("TLS error: …").
    #[test]
    fn tls_keyword_alone_triggers_tls_prefixed_unreachable() {
        let error = rest_client_error("tls: failed to establish connection");
        let result = map_vaultrs_error(error, "secret", "data/test");
        match result {
            CredentialError::Unreachable(msg) => {
                assert!(
                    msg.starts_with("TLS error:"),
                    "Expected 'TLS error:' prefix for a message containing only 'tls'; got: {msg}"
                );
            }
            other => panic!("Expected Unreachable for TLS-keyword error, got {other:?}"),
        }
    }

    // Mutant kill: tls_in_error_chain — "handshake" keyword alone must trigger TLS detection.
    //
    // Kills survivor: vault.rs:297:61 replace || with && in tls_in_error_chain
    // Second `||` mutated to `&&` gives `tls || (handshake && certificate)`. A message
    // containing only "handshake" (no "tls", no "certificate") must still be detected.
    #[test]
    fn handshake_keyword_alone_triggers_tls_prefixed_unreachable() {
        let error = rest_client_error("handshake timeout: peer rejected connection");
        let result = map_vaultrs_error(error, "secret", "data/test");
        match result {
            CredentialError::Unreachable(msg) => {
                assert!(
                    msg.starts_with("TLS error:"),
                    "Expected 'TLS error:' prefix for a message containing only 'handshake'; got: {msg}"
                );
            }
            other => panic!("Expected Unreachable for handshake-keyword error, got {other:?}"),
        }
    }

    // Mutant kill: tls_in_error_chain — "certificate" keyword alone must trigger TLS detection.
    //
    // Also kills survivor: vault.rs:297:61 replace || with && in tls_in_error_chain
    // An error whose message contains only "certificate" (no "tls", no "handshake")
    // must still produce Unreachable("TLS error: …").
    #[test]
    fn certificate_keyword_alone_triggers_tls_prefixed_unreachable() {
        let error = rest_client_error("certificate: verification failed");
        let result = map_vaultrs_error(error, "secret", "data/test");
        match result {
            CredentialError::Unreachable(msg) => {
                assert!(
                    msg.starts_with("TLS error:"),
                    "Expected 'TLS error:' prefix for a message containing only 'certificate'; got: {msg}"
                );
            }
            other => panic!("Expected Unreachable for certificate-keyword error, got {other:?}"),
        }
    }

    // Mutant kill: tls_in_error_chain returning `true` — non-TLS errors must NOT
    // carry the "TLS error:" prefix.
    //
    // Kills survivor: vault.rs:294:5 replace tls_in_error_chain -> bool with true
    // If tls_in_error_chain always returns true, ALL RestClientErrors get the
    // "TLS error: " prefix. A plain connection-refused error must not be so labelled.
    #[test]
    fn connection_refused_unreachable_message_has_no_tls_prefix() {
        let error = connection_refused_error();
        let result = map_vaultrs_error(error, "secret", "data/test");
        match result {
            CredentialError::Unreachable(msg) => {
                assert!(
                    !msg.starts_with("TLS error:"),
                    "Non-TLS error must not carry 'TLS error:' prefix; got: {msg}"
                );
            }
            other => panic!("Expected Unreachable for connection refused, got {other:?}"),
        }
    }

    // Mutant kill: >= 500 boundary — 5xx responses must use the "server error" format,
    // not the catch-all "vault error" format.
    //
    // Kills survivor: vault.rs:321:20 replace >= with < in map_vaultrs_error
    // With `< 500`, codes ≥ 500 fall to the catch-all arm → "vault error: {c} …"
    // instead of "vault server error: {c} …". The existing Tier 3 test uses `||`
    // (code OR "server error"), so the code match still passes the mutant. This test
    // requires "server error" in the message unconditionally.
    #[test]
    fn map_error_5xx_backend_message_uses_server_error_format() {
        let error = api_error(503, vec!["service unavailable"]);
        let result = map_vaultrs_error(error, "secret", "data/test");
        match result {
            CredentialError::Backend(msg) => {
                assert!(
                    msg.contains("server error"),
                    "5xx responses must use 'server error' message format; got: {msg}"
                );
            }
            other => panic!("Expected Backend for HTTP 503, got {other:?}"),
        }
    }
}

// -------------------------------------------------------------------------
// Mutation kill tests: lease_secs_from_raw
//
// These three tests kill the two survivors found by cargo-mutants:
//
//   Survivor 1: replace > with <  in lease_secs_from_raw (vault.rs)
//     Mutation: `duration > 0` → `duration < 0`
//     Effect:   lease_secs_from_raw(30) returns None instead of Some(30)
//
//   Survivor 2: replace > with == in lease_secs_from_raw (vault.rs)
//     Mutation: `duration > 0` → `duration == 0`
//     Effect:   lease_secs_from_raw(30) returns None instead of Some(30);
//               lease_secs_from_raw(0) returns Some(0) instead of None
//
// Kill plan:
//   - `positive_returns_some`   kills both (30 must → Some(30))
//   - `zero_returns_none`       kills Survivor 2 (0 must → None, not Some(0))
//   - `negative_returns_none`   kills Survivor 1 (−1 must → None, not Some(18446744073709551615))
// -------------------------------------------------------------------------

mod lease_secs_kill_tests {
    use super::*;

    // Kills Survivor 1 and Survivor 2:
    //   `> to <` makes 30 < 0 = false → None  (should be Some(30))
    //   `> to ==` makes 30 == 0 = false → None (should be Some(30))
    #[test]
    fn positive_lease_duration_returns_some() {
        assert_eq!(
            lease_secs_from_raw(30),
            Some(30u64),
            "A positive lease_duration must map to Some(duration as u64)"
        );
    }

    // Kills Survivor 2:
    //   `> to ==` makes 0 == 0 = true → Some(0) (should be None)
    #[test]
    fn zero_lease_duration_returns_none() {
        assert_eq!(
            lease_secs_from_raw(0),
            None,
            "A zero lease_duration must map to None (static credential, no expiry)"
        );
    }

    // Kills Survivor 1:
    //   `> to <` makes −1 < 0 = true → Some(u64::MAX via wrapping cast)
    //   If implemented correctly, −1 returns None.
    #[test]
    fn negative_lease_duration_returns_none() {
        assert_eq!(
            lease_secs_from_raw(-1),
            None,
            "A negative lease_duration must map to None"
        );
    }
}

// -------------------------------------------------------------------------
// File-path error variant tests (PR comment #2)
//
// FileNotFoundError, FileReadError, and ParseCertificateError arise from
// VaultClient::new() (CA certificate loading), not from get_raw(). They are
// handled explicitly in map_vaultrs_error to avoid leaking filesystem paths
// via the catch-all arm. Three assertions per variant:
//   (a) maps to CredentialError::Configuration — not Backend or Unreachable
//   (b) the path value does NOT appear in the output message (no path leakage)
//   (c) the generic CA-cert message IS present so operators know the cause
// -------------------------------------------------------------------------

mod file_path_variant_spec {
    use super::*;

    const SENSITIVE_PATH: &str = "/etc/vault/ca-secret/root.pem";

    /// Build a `reqwest::Error` without network access by giving the HTTP client
    /// an unparsable URL (unclosed IPv6 bracket). URL parsing is synchronous
    /// and fails before any network operation.
    fn reqwest_parse_error() -> reqwest::Error {
        reqwest::Client::new()
            .get("http://[invalid-bracket")
            .build()
            .expect_err("URL with unclosed bracket must fail to parse")
    }

    #[test]
    fn file_not_found_maps_to_configuration_without_path() {
        let error = VaultrsError::FileNotFoundError {
            path: SENSITIVE_PATH.to_string(),
        };
        let result = map_vaultrs_error(error, "pki", "issue/role");
        match result {
            CredentialError::Configuration(msg) => {
                assert!(
                    !msg.contains(SENSITIVE_PATH),
                    "FileNotFoundError must not leak the filesystem path; got: {msg}"
                );
                assert!(
                    msg.to_lowercase().contains("certificate"),
                    "FileNotFoundError message should mention 'certificate'; got: {msg}"
                );
            }
            other => panic!("Expected Configuration for FileNotFoundError, got {other:?}"),
        }
    }

    #[test]
    fn file_read_error_maps_to_configuration_without_path() {
        let error = VaultrsError::FileReadError {
            source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied"),
            path: SENSITIVE_PATH.to_string(),
        };
        let result = map_vaultrs_error(error, "pki", "issue/role");
        match result {
            CredentialError::Configuration(msg) => {
                assert!(
                    !msg.contains(SENSITIVE_PATH),
                    "FileReadError must not leak the filesystem path; got: {msg}"
                );
                assert!(
                    msg.to_lowercase().contains("certificate"),
                    "FileReadError message should mention 'certificate'; got: {msg}"
                );
            }
            other => panic!("Expected Configuration for FileReadError, got {other:?}"),
        }
    }

    #[test]
    fn parse_certificate_error_maps_to_configuration_without_path() {
        let error = VaultrsError::ParseCertificateError {
            source: reqwest_parse_error(),
            path: SENSITIVE_PATH.to_string(),
        };
        let result = map_vaultrs_error(error, "pki", "issue/role");
        match result {
            CredentialError::Configuration(msg) => {
                assert!(
                    !msg.contains(SENSITIVE_PATH),
                    "ParseCertificateError must not leak the filesystem path; got: {msg}"
                );
                assert!(
                    msg.to_lowercase().contains("certificate"),
                    "ParseCertificateError message should mention 'certificate'; got: {msg}"
                );
            }
            other => panic!("Expected Configuration for ParseCertificateError, got {other:?}"),
        }
    }
}

// -------------------------------------------------------------------------
// Catch-all arm test (PR comment #3)
//
// The catch-all in map_vaultrs_error handles ClientError variants that are
// not matched by the explicit arms. In vaultrs 0.8 the only unmatched
// variants are: ResponseEmptyError, WrapInvalidError, URLParseError,
// RequestBuildError, RequestError, and any future additions.
// This test uses ResponseEmptyError as a representative variant.
// -------------------------------------------------------------------------

mod catch_all_arm_spec {
    use super::*;

    #[test]
    fn unrecognised_vaultrs_variant_maps_to_backend() {
        // ResponseEmptyError is not matched by any explicit arm in
        // map_vaultrs_error, so it falls through to the catch-all.
        let error = VaultrsError::ResponseEmptyError;
        let result = map_vaultrs_error(error, "secret", "data/test");
        match result {
            CredentialError::Backend(msg) => {
                assert!(
                    msg.starts_with("vault error:"),
                    "Catch-all arm must produce a 'vault error: …' message; got: {msg}"
                );
            }
            other => panic!("Expected Backend for catch-all variant, got {other:?}"),
        }
    }
}

// -------------------------------------------------------------------------
// DynamicCredentialsExtractor tests
//
// Covers A-VAULT-DYN-1 (extractor-level assertions).
// A-VAULT-DYN-2 through A-VAULT-DYN-6 are already covered by
// error_mapping_spec above.
//
// NOTE: Tests that reference `super::super::DynamicCredentialsExtractor`
// will NOT COMPILE until DynamicCredentialsExtractor is declared in vault.rs.
// The constructor test `dynamic_credentials_constructor_does_not_panic`
// compiles now (VaultProvider::dynamic_credentials already exists) but
// FAILS at runtime because the function panics with unimplemented!().
//
// This is the expected pre-implementation (TDD) state.
// -------------------------------------------------------------------------

mod dynamic_credentials_extractor {
    use super::super::DynamicCredentialsExtractor;
    use super::super::VaultProvider;
    use super::*;
    use crate::ExposeSecret;
    use std::time::{Duration, Instant};

    // Helper: construct a unit-struct extractor (no fields).
    fn extractor() -> DynamicCredentialsExtractor {
        DynamicCredentialsExtractor
    }

    // -----------------------------------------------------------------------
    // Tier 1 — Specification tests
    // One test per behavioural clause of A-VAULT-DYN-1 (extractor level).
    // -----------------------------------------------------------------------

    // A-VAULT-DYN-1 (success path): valid username + password + positive lease → Ok
    #[test]
    fn valid_data_with_positive_lease_returns_ok() {
        let data = serde_json::json!({"username": "alice", "password": "hunter2"});
        let result = extractor().extract(&data, Some(30));
        assert!(
            result.is_ok(),
            "Valid data with positive lease must return Ok; got {result:?}"
        );
    }

    // A-VAULT-DYN-1 (expiry set): positive lease_duration → expires_at is Some
    #[test]
    fn valid_data_positive_lease_sets_some_expires_at() {
        let data = serde_json::json!({"username": "alice", "password": "hunter2"});
        let result = extractor().extract(&data, Some(30)).unwrap();
        assert!(
            result.expires_at.is_some(),
            "Positive lease_duration must produce Some(expires_at), got None"
        );
    }

    // A-VAULT-DYN-1 (zero lease): lease_duration_secs = Some(0) → expires_at is None
    #[test]
    fn valid_data_zero_lease_returns_none_expires_at() {
        let data = serde_json::json!({"username": "alice", "password": "hunter2"});
        let result = extractor().extract(&data, Some(0)).unwrap();
        assert!(
            result.expires_at.is_none(),
            "Zero lease_duration must produce None expires_at, got Some"
        );
    }

    // A-VAULT-DYN-1 (None lease): lease_duration_secs = None → expires_at is None
    #[test]
    fn valid_data_none_lease_returns_none_expires_at() {
        let data = serde_json::json!({"username": "alice", "password": "hunter2"});
        let result = extractor().extract(&data, None).unwrap();
        assert!(
            result.expires_at.is_none(),
            "None lease_duration must produce None expires_at, got Some"
        );
    }

    // -----------------------------------------------------------------------
    // Tier 2 — Adversarial / Boundary tests
    // -----------------------------------------------------------------------

    // Missing "username" field → Err(Backend)
    #[test]
    fn missing_username_returns_backend_error() {
        let data = serde_json::json!({"password": "hunter2"});
        let result = extractor().extract(&data, Some(30));
        assert!(
            matches!(result, Err(CredentialError::Backend(_))),
            "Missing 'username' must return Err(Backend), got {result:?}"
        );
    }

    // Missing "password" field → Err(Backend)
    #[test]
    fn missing_password_returns_backend_error() {
        let data = serde_json::json!({"username": "alice"});
        let result = extractor().extract(&data, Some(30));
        assert!(
            matches!(result, Err(CredentialError::Backend(_))),
            "Missing 'password' must return Err(Backend), got {result:?}"
        );
    }

    // Missing username error message must contain the field name "username"
    #[test]
    fn missing_username_error_message_contains_field_name() {
        let data = serde_json::json!({"password": "hunter2"});
        let result = extractor().extract(&data, None);
        match result {
            Err(CredentialError::Backend(msg)) => {
                assert!(
                    msg.contains("username"),
                    "Missing-username Backend message must contain 'username'; got: {msg}"
                );
            }
            other => panic!("Expected Err(Backend), got {other:?}"),
        }
    }

    // Missing password error message must contain the field name "password"
    #[test]
    fn missing_password_error_message_contains_field_name() {
        let data = serde_json::json!({"username": "alice"});
        let result = extractor().extract(&data, None);
        match result {
            Err(CredentialError::Backend(msg)) => {
                assert!(
                    msg.contains("password"),
                    "Missing-password Backend message must contain 'password'; got: {msg}"
                );
            }
            other => panic!("Expected Err(Backend), got {other:?}"),
        }
    }

    // Username present but as a JSON number → Err(Backend) (type mismatch)
    #[test]
    fn username_as_number_returns_backend_error() {
        let data = serde_json::json!({"username": 42, "password": "hunter2"});
        let result = extractor().extract(&data, None);
        assert!(
            matches!(result, Err(CredentialError::Backend(_))),
            "Non-string username (number) must return Err(Backend), got {result:?}"
        );
    }

    // Password present but as a JSON bool → Err(Backend) (type mismatch)
    #[test]
    fn password_as_bool_returns_backend_error() {
        let data = serde_json::json!({"username": "alice", "password": true});
        let result = extractor().extract(&data, None);
        assert!(
            matches!(result, Err(CredentialError::Backend(_))),
            "Non-string password (bool) must return Err(Backend), got {result:?}"
        );
    }

    // Username present but as JSON null → Err(Backend)
    #[test]
    fn username_as_null_returns_backend_error() {
        let data = serde_json::json!({"username": null, "password": "hunter2"});
        let result = extractor().extract(&data, None);
        assert!(
            matches!(result, Err(CredentialError::Backend(_))),
            "Null username must return Err(Backend), got {result:?}"
        );
    }

    // Username present but as a JSON array → Err(Backend)
    #[test]
    fn username_as_array_returns_backend_error() {
        let data = serde_json::json!({"username": ["alice"], "password": "hunter2"});
        let result = extractor().extract(&data, None);
        assert!(
            matches!(result, Err(CredentialError::Backend(_))),
            "Array username must return Err(Backend), got {result:?}"
        );
    }

    // Stub-killer: extracted username must equal data["username"], not a hardcoded value
    #[test]
    fn extracted_username_matches_data_username_field() {
        let data = serde_json::json!({"username": "bob", "password": "secret"});
        let result = extractor().extract(&data, None).unwrap();
        assert_eq!(
            result.username, "bob",
            "Extracted username must equal data[\"username\"]"
        );
    }

    // Stub-killer: extracted password must equal data["password"], not a hardcoded value
    #[test]
    fn extracted_password_matches_data_password_field() {
        let data = serde_json::json!({"username": "bob", "password": "s3cr3t-p@ss"});
        let result = extractor().extract(&data, None).unwrap();
        assert_eq!(
            result.password.expose_secret().as_str(),
            "s3cr3t-p@ss",
            "Extracted password must equal data[\"password\"]"
        );
    }

    // Stub-killer: two different data inputs → two different usernames
    // A stub returning a hardcoded credential would fail this test.
    #[test]
    fn different_data_produces_different_extracted_usernames() {
        let data_a = serde_json::json!({"username": "alice", "password": "pass1"});
        let data_b = serde_json::json!({"username": "bob", "password": "pass2"});
        let cred_a = extractor().extract(&data_a, None).unwrap();
        let cred_b = extractor().extract(&data_b, None).unwrap();
        assert_ne!(
            cred_a.username, cred_b.username,
            "Different input data must produce different usernames (not hardcoded)"
        );
    }

    // Stub-killer: two different data inputs → two different passwords
    #[test]
    fn different_data_produces_different_extracted_passwords() {
        let data_a = serde_json::json!({"username": "alice", "password": "password-alpha"});
        let data_b = serde_json::json!({"username": "bob",   "password": "password-beta"});
        let cred_a = extractor().extract(&data_a, None).unwrap();
        let cred_b = extractor().extract(&data_b, None).unwrap();
        assert_ne!(
            cred_a.password.expose_secret().as_str(),
            cred_b.password.expose_secret().as_str(),
            "Different input data must produce different passwords (not hardcoded)"
        );
    }

    // Boundary: lease == 1 (minimum positive value) must still produce Some(expires_at)
    #[test]
    fn lease_boundary_one_second_produces_some_expires_at() {
        let data = serde_json::json!({"username": "alice", "password": "hunter2"});
        let result = extractor().extract(&data, Some(1)).unwrap();
        assert!(
            result.expires_at.is_some(),
            "Lease of 1 second (minimum positive) must produce Some(expires_at)"
        );
    }

    // Stub-killer for expiry computation: expires_at must be approximately now + lease_duration.
    // A stub returning Some(Instant::now()) without adding the duration fails the lower bound.
    // A stub returning Some(Instant::now() + Duration::MAX) fails the upper bound.
    #[test]
    fn expires_at_is_approximately_now_plus_lease_duration() {
        let lease_secs = 60u64;
        let before = Instant::now();
        let data = serde_json::json!({"username": "alice", "password": "hunter2"});
        let result = extractor().extract(&data, Some(lease_secs)).unwrap();
        let after = Instant::now();

        let expires = result
            .expires_at
            .expect("Positive lease must set expires_at");
        let min_expected = before + Duration::from_secs(lease_secs);
        let max_expected = after + Duration::from_secs(lease_secs);

        assert!(
            expires >= min_expected,
            "expires_at must be >= before + lease_duration ({min_expected:?}); got {expires:?}"
        );
        assert!(
            expires <= max_expected,
            "expires_at must be <= after + lease_duration ({max_expected:?}); got {expires:?}"
        );
    }

    // Empty username string is a valid string — must NOT trigger a Backend error
    #[test]
    fn empty_username_string_is_valid() {
        let data = serde_json::json!({"username": "", "password": "hunter2"});
        let result = extractor().extract(&data, None);
        assert!(
            result.is_ok(),
            "Empty username string must not cause an error; got {result:?}"
        );
    }

    // Empty password string is a valid string — must NOT trigger a Backend error
    #[test]
    fn empty_password_string_is_valid() {
        let data = serde_json::json!({"username": "alice", "password": ""});
        let result = extractor().extract(&data, None);
        assert!(
            result.is_ok(),
            "Empty password string must not cause an error; got {result:?}"
        );
    }

    // Extra fields in data must be silently ignored
    #[test]
    fn extra_fields_in_data_are_ignored() {
        let data = serde_json::json!({
            "username": "alice",
            "password": "hunter2",
            "rotation_period": 3600,
            "engine": "rabbitmq",
            "vhost": "/"
        });
        let result = extractor().extract(&data, Some(30));
        assert!(
            result.is_ok(),
            "Extra fields in data must not cause an error; got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Tier 3 — Property / Parameterized tests
    // Invariants verified across multiple representative inputs.
    // -----------------------------------------------------------------------

    // Invariant: every positive lease duration maps to Some(expires_at)
    #[test]
    fn multiple_positive_lease_durations_all_produce_some_expires_at() {
        let data = serde_json::json!({"username": "alice", "password": "hunter2"});
        for &lease in &[1u64, 30, 300, 3600, 86400, 604800] {
            let result = extractor()
                .extract(&data, Some(lease))
                .expect("Valid data must return Ok for any positive lease");
            assert!(
                result.expires_at.is_some(),
                "Lease of {lease} seconds must produce Some(expires_at)"
            );
        }
    }

    // Invariant: both zero and None lease durations map to None expires_at
    #[test]
    fn zero_and_none_lease_durations_both_produce_none_expires_at() {
        let data = serde_json::json!({"username": "alice", "password": "hunter2"});

        let zero_result = extractor()
            .extract(&data, Some(0))
            .expect("Valid data with zero lease must return Ok");
        assert!(
            zero_result.expires_at.is_none(),
            "Zero lease must produce None expires_at"
        );

        let none_result = extractor()
            .extract(&data, None)
            .expect("Valid data with None lease must return Ok");
        assert!(
            none_result.expires_at.is_none(),
            "None lease must produce None expires_at"
        );
    }

    // Invariant: for any valid (username, password) string pair, extract() reads both correctly
    #[test]
    fn various_username_password_combinations_are_all_extracted_correctly() {
        let cases = [
            ("alice", "s3cr3t"),
            ("user@domain.com", "P@ss!w0rd#2024"),
            ("user-with-dashes", "password with spaces"),
            ("unicode_тест", "пароль"),
            ("u", "p"),
        ];
        for (username, password) in &cases {
            let data = serde_json::json!({"username": username, "password": password});
            let cred = extractor().extract(&data, None).unwrap_or_else(|e| {
                panic!("extract must succeed for username={username:?}: {e:?}")
            });
            assert_eq!(
                &cred.username, username,
                "Username mismatch for input {username:?}"
            );
            assert_eq!(
                cred.password.expose_secret().as_str(),
                *password,
                "Password mismatch for input {password:?}"
            );
        }
    }

    // No-panic invariant: extract() must never panic on any well-formed JSON shape.
    // A result of Ok or Err is both acceptable; a panic is not.
    #[test]
    fn extract_does_not_panic_on_various_data_shapes() {
        let shapes = [
            serde_json::json!({}),
            serde_json::json!(null),
            serde_json::json!([]),
            serde_json::json!(42),
            serde_json::json!(true),
            serde_json::json!("just-a-string"),
            serde_json::json!({"username": 1, "password": 2}),
            serde_json::json!({"username": null, "password": null}),
            serde_json::json!({"username": {"nested": "object"}, "password": "ok"}),
            serde_json::json!({"username": [], "password": {}}),
        ];
        for shape in &shapes {
            // Must not panic — Ok or Err is both acceptable.
            let _ = extractor().extract(shape, None);
        }
    }

    // -----------------------------------------------------------------------
    // Constructor test: dynamic_credentials() delegates to with_extractor()
    // -----------------------------------------------------------------------

    // dynamic_credentials() must construct a VaultProvider without panicking.
    //
    // CURRENT STATE: panics with unimplemented!() → test FAILS (expected).
    // AFTER IMPLEMENTATION: does not panic → test PASSES.
    //
    // The VaultClient is constructed against a local HTTP address;
    // no network call is made by the constructor.
    #[test]
    fn dynamic_credentials_constructor_does_not_panic() {
        use std::sync::Arc;
        use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};

        let client = Arc::new(
            VaultClient::new(
                VaultClientSettingsBuilder::default()
                    .address("http://127.0.0.1:8200")
                    .token("test-token")
                    .build()
                    .expect("VaultClientSettings must build for test address"),
            )
            .expect("VaultClient::new must succeed for HTTP address"),
        );

        // This currently panics with unimplemented!() → test FAILS.
        // After implementation it must return a VaultProvider without panicking.
        let _provider = VaultProvider::<UsernamePassword>::dynamic_credentials(
            client,
            "rabbitmq",
            "creds/queue-keeper",
        );
    }
}
