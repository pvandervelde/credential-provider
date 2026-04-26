// Unit tests for credential-provider/src/env.rs
//
// Covers all A-ENV-UP-*, A-ENV-HMAC-*, and A-ENV-BT-* behavioral assertions
// from docs/spec/assertions.md.
//
// Environment isolation: every test that sets an env var uses temp_env::with_var
// (or async_with_vars), which restores the original value via a Mutex-guarded
// guard even if the test panics.  No serial_test dependency is required because
// temp_env v0.3 serialises mutations internally.

use credential_provider_core::{Credential, CredentialProvider, ExposeSecret};

use crate::env::{EnvBearerTokenProvider, EnvHmacSecretProvider, EnvUsernamePasswordProvider};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Assert that a `CredentialError` is a `Configuration` variant whose message
/// contains the supplied substring.
macro_rules! assert_configuration_error {
    ($result:expr, $substr:expr) => {{
        match $result {
            Err(credential_provider_core::CredentialError::Configuration(msg)) => {
                assert!(
                    msg.contains($substr),
                    "expected message to contain {:?}, got {:?}",
                    $substr,
                    msg
                );
            }
            other => panic!(
                "expected Err(Configuration(..)), got {:?}",
                other.map(|_| "<Ok>")
            ),
        }
    }};
}

// ---------------------------------------------------------------------------
// EnvUsernamePasswordProvider
// ---------------------------------------------------------------------------

/// A-ENV-UP-1: both variables set → correct username and password returned.
#[tokio::test]
async fn up_happy_path_returns_correct_username_and_password() {
    temp_env::async_with_vars(
        [
            ("UP_TEST_USER_1", Some("alice")),
            ("UP_TEST_PASS_1", Some("s3cr3t")),
        ],
        async {
            let provider =
                EnvUsernamePasswordProvider::new("UP_TEST_USER_1", "UP_TEST_PASS_1");
            let cred = provider.get().await.expect("should succeed");
            assert_eq!(cred.username, "alice");
            assert_eq!(cred.password.expose_secret(), "s3cr3t");
        },
    )
    .await;
}

/// A-ENV-UP-1 (username field): `credential.username()` equals the env var value.
#[tokio::test]
async fn up_username_field_matches_env_var() {
    temp_env::async_with_vars(
        [
            ("UP_TEST_USER_2", Some("bob")),
            ("UP_TEST_PASS_2", Some("pw")),
        ],
        async {
            let provider =
                EnvUsernamePasswordProvider::new("UP_TEST_USER_2", "UP_TEST_PASS_2");
            let cred = provider.get().await.expect("should succeed");
            assert_eq!(cred.username, "bob");
        },
    )
    .await;
}

/// A-ENV-UP-1 (password field): `credential.password().expose_secret()` equals the env var value.
#[tokio::test]
async fn up_password_field_matches_env_var() {
    temp_env::async_with_vars(
        [
            ("UP_TEST_USER_3", Some("carol")),
            ("UP_TEST_PASS_3", Some("hunter2")),
        ],
        async {
            let provider =
                EnvUsernamePasswordProvider::new("UP_TEST_USER_3", "UP_TEST_PASS_3");
            let cred = provider.get().await.expect("should succeed");
            assert_eq!(cred.password.expose_secret(), "hunter2");
        },
    )
    .await;
}

/// A-ENV-UP-2: missing username variable → Configuration error containing var name.
#[tokio::test]
async fn up_missing_username_returns_configuration_error() {
    temp_env::async_with_vars(
        [
            ("UP_TEST_MISSING_USER", None::<&str>),
            ("UP_TEST_MISSING_PASS", Some("pw")),
        ],
        async {
            let provider = EnvUsernamePasswordProvider::new(
                "UP_TEST_MISSING_USER",
                "UP_TEST_MISSING_PASS",
            );
            let result = provider.get().await;
            assert_configuration_error!(result, "UP_TEST_MISSING_USER");
        },
    )
    .await;
}

/// A-ENV-UP-3: missing password variable → Configuration error containing var name.
#[tokio::test]
async fn up_missing_password_returns_configuration_error() {
    temp_env::async_with_vars(
        [
            ("UP_TEST_MISSING_PASS2_USER", Some("alice")),
            ("UP_TEST_MISSING_PASS2_PASS", None::<&str>),
        ],
        async {
            let provider = EnvUsernamePasswordProvider::new(
                "UP_TEST_MISSING_PASS2_USER",
                "UP_TEST_MISSING_PASS2_PASS",
            );
            let result = provider.get().await;
            assert_configuration_error!(result, "UP_TEST_MISSING_PASS2_PASS");
        },
    )
    .await;
}

/// A-ENV-UP-4: empty username variable → Configuration error.
#[tokio::test]
async fn up_empty_username_returns_configuration_error() {
    temp_env::async_with_vars(
        [
            ("UP_TEST_EMPTY_USER", Some("")),
            ("UP_TEST_EMPTY_USER_PASS", Some("pw")),
        ],
        async {
            let provider = EnvUsernamePasswordProvider::new(
                "UP_TEST_EMPTY_USER",
                "UP_TEST_EMPTY_USER_PASS",
            );
            let result = provider.get().await;
            assert_configuration_error!(result, "UP_TEST_EMPTY_USER");
        },
    )
    .await;
}

/// A-ENV-UP-4: empty password variable → Configuration error.
#[tokio::test]
async fn up_empty_password_returns_configuration_error() {
    temp_env::async_with_vars(
        [
            ("UP_TEST_EMPTY_PASS_USER", Some("alice")),
            ("UP_TEST_EMPTY_PASS", Some("")),
        ],
        async {
            let provider = EnvUsernamePasswordProvider::new(
                "UP_TEST_EMPTY_PASS_USER",
                "UP_TEST_EMPTY_PASS",
            );
            let result = provider.get().await;
            assert_configuration_error!(result, "UP_TEST_EMPTY_PASS");
        },
    )
    .await;
}

/// A-ENV-UP-5: re-reads on every call — change var between two `get()` calls.
#[tokio::test]
async fn up_rereads_env_var_on_every_call() {
    temp_env::async_with_vars(
        [
            ("UP_TEST_REREAD_USER", Some("alice")),
            ("UP_TEST_REREAD_PASS", Some("secret1")),
        ],
        async {
            let provider =
                EnvUsernamePasswordProvider::new("UP_TEST_REREAD_USER", "UP_TEST_REREAD_PASS");
            let first = provider.get().await.expect("first call should succeed");
            assert_eq!(first.password.expose_secret(), "secret1");

            // Mutate the password variable and call again.
            temp_env::async_with_vars(
                [("UP_TEST_REREAD_PASS", Some("secret2"))],
                async {
                    let second = provider.get().await.expect("second call should succeed");
                    assert_eq!(second.password.expose_secret(), "secret2");
                },
            )
            .await;
        },
    )
    .await;
}

/// A-ENV-UP-6: returned credential has no expiry and is valid.
#[tokio::test]
async fn up_credential_has_no_expiry_and_is_valid() {
    temp_env::async_with_vars(
        [
            ("UP_TEST_EXPIRY_USER", Some("alice")),
            ("UP_TEST_EXPIRY_PASS", Some("pw")),
        ],
        async {
            let provider =
                EnvUsernamePasswordProvider::new("UP_TEST_EXPIRY_USER", "UP_TEST_EXPIRY_PASS");
            let cred = provider.get().await.expect("should succeed");
            assert!(cred.expires_at().is_none(), "expires_at should be None");
            assert!(cred.is_valid(), "is_valid should be true");
        },
    )
    .await;
}

/// Edge case: whitespace-only username passes through (not treated as empty).
#[tokio::test]
async fn up_whitespace_only_username_passes_through() {
    temp_env::async_with_vars(
        [
            ("UP_TEST_WS_USER", Some("   ")),
            ("UP_TEST_WS_PASS", Some("pw")),
        ],
        async {
            let provider =
                EnvUsernamePasswordProvider::new("UP_TEST_WS_USER", "UP_TEST_WS_PASS");
            let cred = provider.get().await.expect("whitespace should not be rejected");
            assert_eq!(cred.username, "   ");
        },
    )
    .await;
}

/// Edge case: whitespace-only password passes through (not treated as empty).
#[tokio::test]
async fn up_whitespace_only_password_passes_through() {
    temp_env::async_with_vars(
        [
            ("UP_TEST_WS_PASS_USER", Some("alice")),
            ("UP_TEST_WS_PASS_VAL", Some("   ")),
        ],
        async {
            let provider = EnvUsernamePasswordProvider::new(
                "UP_TEST_WS_PASS_USER",
                "UP_TEST_WS_PASS_VAL",
            );
            let cred = provider.get().await.expect("whitespace should not be rejected");
            assert_eq!(cred.password.expose_secret(), "   ");
        },
    )
    .await;
}

// ---------------------------------------------------------------------------
// EnvHmacSecretProvider
// ---------------------------------------------------------------------------

/// A-ENV-HMAC-1: hex-encoded value → decoded bytes match expected.
#[tokio::test]
async fn hmac_hex_lowercase_decodes_correctly() {
    temp_env::async_with_vars(
        [("HMAC_TEST_HEX_LC", Some("deadbeef"))],
        async {
            let provider = EnvHmacSecretProvider::new("HMAC_TEST_HEX_LC");
            let cred = provider.get().await.expect("hex should decode");
            assert_eq!(
                cred.key.expose_secret().as_slice(),
                &[0xDE, 0xAD, 0xBE, 0xEF]
            );
        },
    )
    .await;
}

/// A-ENV-HMAC-1: uppercase hex also decodes correctly.
#[tokio::test]
async fn hmac_hex_uppercase_decodes_correctly() {
    temp_env::async_with_vars(
        [("HMAC_TEST_HEX_UC", Some("DEADBEEF"))],
        async {
            let provider = EnvHmacSecretProvider::new("HMAC_TEST_HEX_UC");
            let cred = provider.get().await.expect("uppercase hex should decode");
            assert_eq!(
                cred.key.expose_secret().as_slice(),
                &[0xDE, 0xAD, 0xBE, 0xEF]
            );
        },
    )
    .await;
}

/// A-ENV-HMAC-2: base64-encoded value → decoded bytes match expected.
/// "3q2+7w==" is standard base64 for [0xDE, 0xAD, 0xBE, 0xEF].
#[tokio::test]
async fn hmac_base64_decodes_correctly() {
    temp_env::async_with_vars(
        [("HMAC_TEST_B64", Some("3q2+7w=="))],
        async {
            let provider = EnvHmacSecretProvider::new("HMAC_TEST_B64");
            let cred = provider.get().await.expect("base64 should decode");
            assert_eq!(
                cred.key.expose_secret().as_slice(),
                &[0xDE, 0xAD, 0xBE, 0xEF]
            );
        },
    )
    .await;
}

/// A-ENV-HMAC-1 vs A-ENV-HMAC-2 disambiguation: "deadbeef" is valid hex and
/// valid base64.  Hex wins, so result must be 4 bytes [DE AD BE EF], not the
/// 6-byte base64 decode.
#[tokio::test]
async fn hmac_hex_wins_for_ambiguous_value() {
    temp_env::async_with_vars(
        [("HMAC_TEST_AMBIG", Some("deadbeef"))],
        async {
            let provider = EnvHmacSecretProvider::new("HMAC_TEST_AMBIG");
            let cred = provider.get().await.expect("should succeed");
            // hex decode → 4 bytes
            assert_eq!(cred.key.expose_secret().len(), 4);
            assert_eq!(
                cred.key.expose_secret().as_slice(),
                &[0xDE, 0xAD, 0xBE, 0xEF]
            );
        },
    )
    .await;
}

/// A-ENV-HMAC-3: missing variable → Configuration error.
#[tokio::test]
async fn hmac_missing_var_returns_configuration_error() {
    temp_env::async_with_vars(
        [("HMAC_TEST_MISSING", None::<&str>)],
        async {
            let provider = EnvHmacSecretProvider::new("HMAC_TEST_MISSING");
            let result = provider.get().await;
            assert_configuration_error!(result, "HMAC_TEST_MISSING");
        },
    )
    .await;
}

/// A-ENV-HMAC-4: empty variable → Configuration error.
#[tokio::test]
async fn hmac_empty_var_returns_configuration_error() {
    temp_env::async_with_vars(
        [("HMAC_TEST_EMPTY", Some(""))],
        async {
            let provider = EnvHmacSecretProvider::new("HMAC_TEST_EMPTY");
            let result = provider.get().await;
            assert_configuration_error!(result, "HMAC_TEST_EMPTY");
        },
    )
    .await;
}

/// A-ENV-HMAC-5: invalid encoding (neither hex nor base64) → Configuration error
/// containing the var name.
#[tokio::test]
async fn hmac_invalid_encoding_returns_configuration_error_with_var_name() {
    temp_env::async_with_vars(
        [("HMAC_TEST_INVALID", Some("not-valid-hex-or-base64!!!"))],
        async {
            let provider = EnvHmacSecretProvider::new("HMAC_TEST_INVALID");
            let result = provider.get().await;
            assert_configuration_error!(result, "HMAC_TEST_INVALID");
        },
    )
    .await;
}

/// Edge case: HmacSecret has no expiry and is always valid.
#[tokio::test]
async fn hmac_credential_has_no_expiry_and_is_valid() {
    temp_env::async_with_vars(
        [("HMAC_TEST_EXPIRY", Some("deadbeef"))],
        async {
            let provider = EnvHmacSecretProvider::new("HMAC_TEST_EXPIRY");
            let cred = provider.get().await.expect("should succeed");
            assert!(cred.expires_at().is_none(), "expires_at should be None");
            assert!(cred.is_valid(), "is_valid should be true");
        },
    )
    .await;
}

/// Edge case: re-reads on every call — change var between two `get()` calls.
#[tokio::test]
async fn hmac_rereads_env_var_on_every_call() {
    temp_env::async_with_vars(
        [("HMAC_TEST_REREAD", Some("deadbeef"))],
        async {
            let provider = EnvHmacSecretProvider::new("HMAC_TEST_REREAD");
            let first = provider.get().await.expect("first call should succeed");
            assert_eq!(first.key.expose_secret().as_slice(), &[0xDE, 0xAD, 0xBE, 0xEF]);

            // Change to a different hex value.
            temp_env::async_with_vars(
                [("HMAC_TEST_REREAD", Some("cafebabe"))],
                async {
                    let second = provider.get().await.expect("second call should succeed");
                    assert_eq!(
                        second.key.expose_secret().as_slice(),
                        &[0xCA, 0xFE, 0xBA, 0xBE]
                    );
                },
            )
            .await;
        },
    )
    .await;
}

// ---------------------------------------------------------------------------
// EnvBearerTokenProvider
// ---------------------------------------------------------------------------

/// A-ENV-BT-1: variable set → correct token value returned.
#[tokio::test]
async fn bt_happy_path_returns_correct_token() {
    temp_env::async_with_vars(
        [("BT_TEST_TOKEN_1", Some("my-api-token"))],
        async {
            let provider = EnvBearerTokenProvider::new("BT_TEST_TOKEN_1");
            let cred = provider.get().await.expect("should succeed");
            assert_eq!(cred.token.expose_secret(), "my-api-token");
        },
    )
    .await;
}

/// A-ENV-BT-1: `token.expose_secret()` equals var value.
#[tokio::test]
async fn bt_token_field_matches_env_var() {
    temp_env::async_with_vars(
        [("BT_TEST_TOKEN_2", Some("Bearer eyJhbGciOiJSUzI1NiJ9"))],
        async {
            let provider = EnvBearerTokenProvider::new("BT_TEST_TOKEN_2");
            let cred = provider.get().await.expect("should succeed");
            assert_eq!(
                cred.token.expose_secret(),
                "Bearer eyJhbGciOiJSUzI1NiJ9"
            );
        },
    )
    .await;
}

/// A-ENV-BT-2: missing variable → Configuration error containing var name.
#[tokio::test]
async fn bt_missing_var_returns_configuration_error() {
    temp_env::async_with_vars(
        [("BT_TEST_MISSING", None::<&str>)],
        async {
            let provider = EnvBearerTokenProvider::new("BT_TEST_MISSING");
            let result = provider.get().await;
            assert_configuration_error!(result, "BT_TEST_MISSING");
        },
    )
    .await;
}

/// A-ENV-BT-3: empty variable → Configuration error.
#[tokio::test]
async fn bt_empty_var_returns_configuration_error() {
    temp_env::async_with_vars(
        [("BT_TEST_EMPTY", Some(""))],
        async {
            let provider = EnvBearerTokenProvider::new("BT_TEST_EMPTY");
            let result = provider.get().await;
            assert_configuration_error!(result, "BT_TEST_EMPTY");
        },
    )
    .await;
}

/// Edge case: whitespace-only token passes through (not treated as empty).
#[tokio::test]
async fn bt_whitespace_only_token_passes_through() {
    temp_env::async_with_vars(
        [("BT_TEST_WS", Some("   "))],
        async {
            let provider = EnvBearerTokenProvider::new("BT_TEST_WS");
            let cred = provider.get().await.expect("whitespace should not be rejected");
            assert_eq!(cred.token.expose_secret(), "   ");
        },
    )
    .await;
}

/// Edge case: BearerToken has no expiry and is valid.
#[tokio::test]
async fn bt_credential_has_no_expiry_and_is_valid() {
    temp_env::async_with_vars(
        [("BT_TEST_EXPIRY", Some("tok"))],
        async {
            let provider = EnvBearerTokenProvider::new("BT_TEST_EXPIRY");
            let cred = provider.get().await.expect("should succeed");
            assert!(cred.expires_at().is_none(), "expires_at should be None");
            assert!(cred.is_valid(), "is_valid should be true");
        },
    )
    .await;
}

/// Edge case: re-reads on every call — change var between two `get()` calls.
#[tokio::test]
async fn bt_rereads_env_var_on_every_call() {
    temp_env::async_with_vars(
        [("BT_TEST_REREAD", Some("token-v1"))],
        async {
            let provider = EnvBearerTokenProvider::new("BT_TEST_REREAD");
            let first = provider.get().await.expect("first call should succeed");
            assert_eq!(first.token.expose_secret(), "token-v1");

            temp_env::async_with_vars(
                [("BT_TEST_REREAD", Some("token-v2"))],
                async {
                    let second = provider.get().await.expect("second call should succeed");
                    assert_eq!(second.token.expose_secret(), "token-v2");
                },
            )
            .await;
        },
    )
    .await;
}

// ---------------------------------------------------------------------------
// GAP-1: Error message prefix for absent/empty variables
//
// Tests verify that the error message begins with "missing env var: " so that
// a mutation swapping the NotPresent and NotUnicode arm messages is detectable.
// ---------------------------------------------------------------------------

/// GAP-1 (UP): absent username error message starts with "missing env var: ".
#[tokio::test]
async fn up_missing_var_error_message_starts_with_missing_env_var() {
    temp_env::async_with_vars(
        [
            ("UP_GAP1_USER", None::<&str>),
            ("UP_GAP1_PASS", Some("pw")),
        ],
        async {
            let provider =
                EnvUsernamePasswordProvider::new("UP_GAP1_USER", "UP_GAP1_PASS");
            let result = provider.get().await;
            match result {
                Err(credential_provider_core::CredentialError::Configuration(msg)) => {
                    assert!(
                        msg.starts_with("missing env var: "),
                        "expected message to start with 'missing env var: ', got: {msg:?}"
                    );
                    assert!(msg.contains("UP_GAP1_USER"));
                }
                other => panic!(
                    "expected Err(Configuration(..)), got {:?}",
                    other.map(|_| "<Ok>")
                ),
            }
        },
    )
    .await;
}

/// GAP-1 (HMAC): absent var error message starts with "missing env var: ".
#[tokio::test]
async fn hmac_missing_var_error_message_starts_with_missing_env_var() {
    temp_env::async_with_vars(
        [("HMAC_GAP1_SECRET", None::<&str>)],
        async {
            let provider = EnvHmacSecretProvider::new("HMAC_GAP1_SECRET");
            let result = provider.get().await;
            match result {
                Err(credential_provider_core::CredentialError::Configuration(msg)) => {
                    assert!(
                        msg.starts_with("missing env var: "),
                        "expected message to start with 'missing env var: ', got: {msg:?}"
                    );
                    assert!(msg.contains("HMAC_GAP1_SECRET"));
                }
                other => panic!(
                    "expected Err(Configuration(..)), got {:?}",
                    other.map(|_| "<Ok>")
                ),
            }
        },
    )
    .await;
}

// ---------------------------------------------------------------------------
// GAP-2: HMAC invalid-encoding message is distinct from missing-var message
//
// A mutation that returns "missing env var: {name}" instead of
// "invalid encoding for env var: {name}" on decode failure would survive
// any test that only checks for the var name substring.
// ---------------------------------------------------------------------------

/// GAP-2: HMAC invalid-encoding error message contains "invalid encoding".
#[tokio::test]
async fn hmac_invalid_encoding_error_message_distinguishable_from_missing_var() {
    temp_env::async_with_vars(
        [("HMAC_GAP2_SECRET", Some("not-valid-hex-or-base64!!!"))],
        async {
            let provider = EnvHmacSecretProvider::new("HMAC_GAP2_SECRET");
            let result = provider.get().await;
            match result {
                Err(credential_provider_core::CredentialError::Configuration(msg)) => {
                    assert!(
                        msg.contains("invalid encoding"),
                        "expected 'invalid encoding' in message, got: {msg:?}"
                    );
                    assert!(
                        !msg.starts_with("missing env var: "),
                        "decode-failure message must not look like an absent-var error, got: {msg:?}"
                    );
                    assert!(msg.contains("HMAC_GAP2_SECRET"));
                }
                other => panic!(
                    "expected Err(Configuration(..)), got {:?}",
                    other.map(|_| "<Ok>")
                ),
            }
        },
    )
    .await;
}

// ---------------------------------------------------------------------------
// GAP-3: Username/password read order
//
// When both vars are absent the implementation must read username first.
// Swapping the two read_env_var() calls is undetectable by any test that
// only has one var absent at a time.
// ---------------------------------------------------------------------------

/// GAP-3: both vars absent → error names the username var, not the password var.
#[tokio::test]
async fn up_both_absent_error_names_username_var_not_password_var() {
    temp_env::async_with_vars(
        [
            ("UP_GAP3_USER", None::<&str>),
            ("UP_GAP3_PASS", None::<&str>),
        ],
        async {
            let provider =
                EnvUsernamePasswordProvider::new("UP_GAP3_USER", "UP_GAP3_PASS");
            let result = provider.get().await;
            match result {
                Err(credential_provider_core::CredentialError::Configuration(msg)) => {
                    assert!(
                        msg.contains("UP_GAP3_USER"),
                        "error must name the username var when both are absent, got: {msg:?}"
                    );
                    assert!(
                        !msg.contains("UP_GAP3_PASS"),
                        "error must NOT name the password var when username is read first, got: {msg:?}"
                    );
                }
                other => panic!(
                    "expected Err(Configuration(..)), got {:?}",
                    other.map(|_| "<Ok>")
                ),
            }
        },
    )
    .await;
}

// ---------------------------------------------------------------------------
// GAP-4: Absent-to-present transitions rule out construction-time caching
//
// The re-read tests in the main suite only exercise present→present transitions
// (provider constructed while var is already set).  A provider that caches the
// value at construction time would pass those tests.  These tests construct the
// provider while the var is absent, confirm the first call fails, then set the
// var and confirm the second call succeeds.
// ---------------------------------------------------------------------------

/// GAP-4 (UP): provider constructed before vars set — second call picks up the vars.
#[tokio::test]
async fn up_provider_constructed_before_vars_set_rereads_on_get() {
    let provider =
        EnvUsernamePasswordProvider::new("UP_GAP4_USER", "UP_GAP4_PASS");

    // First call: vars not set → expect Configuration error.
    let first_result = temp_env::async_with_vars(
        [
            ("UP_GAP4_USER", None::<&str>),
            ("UP_GAP4_PASS", None::<&str>),
        ],
        async { provider.get().await },
    )
    .await;
    assert!(
        matches!(
            first_result,
            Err(credential_provider_core::CredentialError::Configuration(_))
        ),
        "first call with vars absent must fail, got: {:?}",
        first_result.map(|_| "<Ok>")
    );

    // Second call: vars now set → expect success with correct values.
    let second_result = temp_env::async_with_vars(
        [
            ("UP_GAP4_USER", Some("dave")),
            ("UP_GAP4_PASS", Some("secret")),
        ],
        async { provider.get().await },
    )
    .await;
    let cred = second_result.expect("second call with vars set must succeed");
    assert_eq!(cred.username, "dave");
    assert_eq!(cred.password.expose_secret(), "secret");
}

/// GAP-4 (HMAC): provider constructed before var set — second call picks up the var.
#[tokio::test]
async fn hmac_provider_constructed_before_var_set_rereads_on_get() {
    let provider = EnvHmacSecretProvider::new("HMAC_GAP4_SECRET");

    // First call: var not set → expect Configuration error.
    let first_result = temp_env::async_with_vars(
        [("HMAC_GAP4_SECRET", None::<&str>)],
        async { provider.get().await },
    )
    .await;
    assert!(
        matches!(
            first_result,
            Err(credential_provider_core::CredentialError::Configuration(_))
        ),
        "first call with var absent must fail"
    );

    // Second call: var now set → expect success.
    let second_result = temp_env::async_with_vars(
        [("HMAC_GAP4_SECRET", Some("deadbeef"))],
        async { provider.get().await },
    )
    .await;
    let cred = second_result.expect("second call with var set must succeed");
    assert_eq!(
        cred.key.expose_secret().as_slice(),
        &[0xDE, 0xAD, 0xBE, 0xEF]
    );
}

/// GAP-4 (BT): provider constructed before var set — second call picks up the var.
#[tokio::test]
async fn bt_provider_constructed_before_var_set_rereads_on_get() {
    let provider = EnvBearerTokenProvider::new("BT_GAP4_TOKEN");

    // First call: var not set → expect Configuration error.
    let first_result = temp_env::async_with_vars(
        [("BT_GAP4_TOKEN", None::<&str>)],
        async { provider.get().await },
    )
    .await;
    assert!(
        matches!(
            first_result,
            Err(credential_provider_core::CredentialError::Configuration(_))
        ),
        "first call with var absent must fail"
    );

    // Second call: var now set → expect success.
    let second_result = temp_env::async_with_vars(
        [("BT_GAP4_TOKEN", Some("my-token"))],
        async { provider.get().await },
    )
    .await;
    let cred = second_result.expect("second call with var set must succeed");
    assert_eq!(cred.token.expose_secret(), "my-token");
}

// ---------------------------------------------------------------------------
// GAP-6: NotUnicode branch of read_env_var (Unix only)
//
// std::env::VarError::NotUnicode is only reachable on Unix where env vars are
// arbitrary byte sequences.  On Windows, vars are UTF-16 and the stdlib always
// produces valid String, so this branch is unreachable there.
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn up_non_utf8_username_returns_configuration_error_with_utf8_message() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let var_name = "UP_GAP6_NON_UTF8_USER";
    let non_utf8 = OsStr::from_bytes(&[0xFF, 0xFE]);

    // temp_env does not accept OsStr values, so set/remove manually.
    // Safety: single-threaded test; temp_env's mutex serialises concurrent env
    // mutations so no other test races with this unsafe block.
    unsafe { std::env::set_var(var_name, non_utf8) };

    let provider = EnvUsernamePasswordProvider::new(var_name, "UP_GAP6_PASS");
    let result = temp_env::async_with_vars(
        [("UP_GAP6_PASS", Some("pw"))],
        async { provider.get().await },
    )
    .await;

    unsafe { std::env::remove_var(var_name) };

    match result {
        Err(credential_provider_core::CredentialError::Configuration(msg)) => {
            assert!(
                msg.contains("invalid UTF-8"),
                "expected 'invalid UTF-8' in message, got: {msg:?}"
            );
            assert!(msg.contains(var_name));
        }
        other => panic!(
            "expected Err(Configuration(..)), got {:?}",
            other.map(|_| "<Ok>")
        ),
    }
}
