# Test Coverage

Maps behavioral assertions to test cases. Updated when new test suites are added.

---

## Credential Types (UsernamePassword, BearerToken, HmacSecret, TlsClientCertificate)

**Source:** `credential-provider-core/src/credentials_tests.rs` (linked via `#[path]` in `credentials.rs`)
**Criticality:** Core value types — Tier 1 required

### Specification Tests (Tier 1 — from assertions.md)

| Assertion | Type | Test name |
|---|---|---|
| A-CRED-1: no-expiry is always valid | UsernamePassword | `test_username_password_no_expiry_is_valid` |
| A-CRED-1: no-expiry expires_at is None | UsernamePassword | `test_username_password_no_expiry_expires_at_is_none` |
| A-CRED-2: future expiry is valid | UsernamePassword | `test_username_password_future_expiry_is_valid` |
| A-CRED-3: past expiry is invalid | UsernamePassword | `test_username_password_past_expiry_is_invalid` |
| A-CRED-1: no-expiry is always valid | BearerToken | `test_bearer_token_no_expiry_is_valid` |
| A-CRED-1: no-expiry expires_at is None | BearerToken | `test_bearer_token_no_expiry_expires_at_is_none` |
| A-CRED-2: future expiry is valid | BearerToken | `test_bearer_token_future_expiry_is_valid` |
| A-CRED-3: past expiry is invalid | BearerToken | `test_bearer_token_past_expiry_is_invalid` |
| A-CRED-4: HmacSecret is always valid | HmacSecret | `test_hmac_secret_is_always_valid` |
| A-CRED-4: HmacSecret expires_at is None | HmacSecret | `test_hmac_secret_expires_at_is_always_none` |
| A-CRED-1: no-expiry is always valid | TlsClientCertificate | `test_tls_client_cert_no_expiry_is_valid` |
| A-CRED-1: no-expiry expires_at is None | TlsClientCertificate | `test_tls_client_cert_no_expiry_expires_at_is_none` |
| A-CRED-2: future expiry is valid | TlsClientCertificate | `test_tls_client_cert_future_expiry_is_valid` |
| A-CRED-3: past expiry is invalid | TlsClientCertificate | `test_tls_client_cert_past_expiry_is_invalid` |

### Boundary / Security Tests (Tier 2)

| Scenario | Type | Test name |
|---|---|---|
| expires_at() returns stored value | UsernamePassword | `test_username_password_expires_at_returns_stored_value` |
| expires_at() returns stored value | BearerToken | `test_bearer_token_expires_at_returns_stored_value` |
| expires_at() returns stored value | TlsClientCertificate | `test_tls_client_cert_expires_at_returns_stored_value` |
| Debug redacts password, shows username | UsernamePassword | `test_username_password_debug_shows_username_and_redacts_password` |
| Debug redacts token | BearerToken | `test_bearer_token_debug_redacts_token` |
| Debug redacts key bytes | HmacSecret | `test_hmac_secret_debug_redacts_key` |
| Debug redacts both PEM fields | TlsClientCertificate | `test_tls_client_cert_debug_redacts_pem_fields` |
| Clone produces independent copy (different allocation) | HmacSecret | `test_hmac_secret_clone_is_independent` |
| Clone produces independent copy — cert and key fields | TlsClientCertificate | `test_tls_client_cert_clone_is_independent` |

---

## MockCredentialProvider

**Source:** `credential-provider-core/src/mock_tests.rs` (linked via `#[path]` in `mock.rs`)

| Scenario | Test name |
|---|---|
| call_count() is 0 before any calls | `test_call_count_is_zero_before_any_calls` |
| call_count() is 1 after one get() | `test_call_count_is_one_after_one_call` |
| call_count() increments correctly | `test_call_count_increments_over_multiple_calls` |
| returning_ok repeats credential | `test_returning_ok_repeats_credential` |
| returning_err repeats error | `test_returning_err_repeats_error` |
| from_sequence delivers in order, repeats last | `test_from_sequence_delivers_in_order_and_repeats_last` |

---

## CachingCredentialProvider::get()

**Source:** `credential-provider-core/src/caching.rs` — `#[cfg(test)] mod tests`
**Criticality:** Domain business logic — Tiers 1 + 2 required

### Specification Tests (Tier 1 — from assertions.md)

| Assertion | Test name |
|---|---|
| A-CACHE-1: empty cache triggers fetch | `test_empty_cache_calls_inner_and_returns_result` |
| A-CACHE-1: first fetch result is cached | `test_empty_cache_result_is_cached_second_call_does_not_refetch` |
| A-CACHE-1 + E-CACHE-1: first fetch failure returns `Unavailable` | `test_empty_cache_inner_failure_returns_unavailable` |
| A-CACHE-2: valid outside window — inner NOT called | `test_valid_credential_outside_refresh_window_not_fetched_again` |
| A-CACHE-2: cached value returned | `test_valid_credential_outside_refresh_window_returns_cached_value` |
| A-CACHE-3: inside window triggers refresh, returns new credential | `test_credential_inside_refresh_window_triggers_refresh_and_returns_new` |
| A-CACHE-3: old credential not returned when refresh succeeds | `test_credential_inside_refresh_window_does_not_return_old_value_on_success` |
| A-CACHE-4: refresh failure inside window → stale returned (not error) | `test_credential_inside_refresh_window_refresh_failure_returns_stale_not_error` |
| A-CACHE-4: stale fallback username matches cached credential | `test_stale_fallback_returns_specifically_the_still_valid_cached_username` |
| A-CACHE-5: expired cache + refresh failure → error propagated | `test_expired_credential_refresh_failure_propagates_error_not_stale` |
| A-CACHE-5: expired cache + failure propagates inner variant (not `Unavailable`) | `test_expired_credential_refresh_failure_propagates_original_error_variant_not_unavailable` |
| A-CACHE-6: concurrent calls serialize to one fetch | `test_concurrent_calls_on_empty_cache_serialize_to_one_fetch` |
| A-CACHE-7: no-expiry credential — inner called only once | `test_no_expiry_credential_inner_called_only_once_across_many_calls` |
| A-CACHE-7: no-expiry credential returns same bytes every call | `test_no_expiry_credential_returns_same_bytes_on_every_call` |
| A-CACHE-8: successful refresh returns new credential | `test_successful_refresh_returns_new_credential_not_old` |
| A-CACHE-8: subsequent call after refresh returns new credential from cache | `test_after_successful_refresh_subsequent_call_returns_new_credential` |

### Adversarial / Boundary Tests (Tier 2)

| Edge case | Test name |
|---|---|
| E-CACHE-2: credential at exact refresh window boundary triggers refresh | `test_credential_at_boundary_of_refresh_window_triggers_refresh` |

### Stub-killing strategy

- `test_empty_cache_result_is_cached_second_call_does_not_refetch` — the second response is `Err`; a non-caching stub would surface it.
- `test_empty_cache_inner_failure_returns_unavailable` + `test_expired_credential_refresh_failure_propagates_original_error_variant_not_unavailable` — together forbid both "always `Unavailable`" and "always propagate" stubs.
- `test_credential_inside_refresh_window_does_not_return_old_value_on_success` — forbids a stub that returns the cached value instead of the refresh result.
- `test_concurrent_calls_on_empty_cache_serialize_to_one_fetch` — the mock returns `"fetched-once"` on the first call and `"fetched-again"` on every subsequent call; all 8 tasks must return `"fetched-once"`.
- `test_no_expiry_credential_inner_called_only_once_across_many_calls` — the second inner response is `Err`; any extra fetch surfaces it.
- `test_after_successful_refresh_subsequent_call_returns_new_credential` — third inner response is `Err`; if the cache was not updated, the third call hits inner and fails.

### Gaps / Known Limitations

- **ADR-003 re-check timing**: the boundary between Rule 4 (stale fallback) and Rule 5 (propagate error) depends on `is_valid()` being evaluated *after* the failed refresh. This is partially covered by `expired_credential_refresh_failure_propagates_error_not_stale` but would benefit from an integration test using real time progression.
- **E-CACHE-3 (lease shorter than window)**: not covered — requires property-based tests across arbitrary `(expires_at, refresh_window)` pairs.
- **E-CACHE-6 (provider panic)**: not covered — panic propagation through `tokio::sync::RwLock` is a runtime concern; would require a purpose-built panicking mock.
- **Concurrency on stale cache**: A-CACHE-6 covers an empty cache; serialization on a stale-but-valid cache (Rules 3/4) is not covered by a dedicated concurrency test.
- **Fuzz concurrency path**: `fuzz_caching.rs` uses `new_current_thread()` and cannot exercise the concurrent thundering-herd path (A-CACHE-6). This is acceptable — A-CACHE-6 is covered by the dedicated unit test.

---

## VaultProvider — Task 3.0: map_vaultrs_error() and VaultExtractor contract

**Source:** `credential-provider/src/vault_tests.rs` (linked via `#[path]` in `vault.rs`)
**Criticality:** Domain business logic — Tiers 1 + 2 + 3 required
**Feature gate:** `vault`
**Status:** GREEN — 96 passing, 0 failing, 2 ignored (integration); mutation score 100% (28/28 viable)

### Specification Tests (Tier 1 — from assertions.md A-VAULT-*)

| Assertion | Test name |
|---|---|
| A-VAULT-DYN-2: 403 → Backend("permission denied") | `error_mapping_spec::map_error_403_returns_backend_permission_denied` |
| A-VAULT-DYN-3: 404 → Configuration with mount and path | `error_mapping_spec::map_error_404_returns_configuration_path_not_found` |
| A-VAULT-DYN-5: 400 + "lease" → Revoked | `error_mapping_spec::map_error_400_lease_returns_revoked` |
| HTTP 5xx → Backend with code and detail | `error_mapping_spec::map_error_5xx_returns_backend_server_error` |
| A-VAULT-DYN-4 (TLS): TLS RestClientError → Unreachable("TLS error: …") | `error_mapping_spec::map_error_tls_returns_unreachable_tls` |
| A-VAULT-DYN-4 (conn): connection refused → Unreachable | `error_mapping_spec::map_error_connection_refused_returns_unreachable` |
| A-VAULT-DYN-6: ResponseDataEmptyError → Backend("…missing data field") | `error_mapping_spec::map_error_response_data_empty_returns_backend_missing_data` |
| A-VAULT-DYN-6: JsonParseError → Backend("unexpected response: …") | `error_mapping_spec::map_error_json_parse_returns_backend_unexpected_response` |
| A-VAULT-CUSTOM-1: extractor receives full data and lease metadata | `extractor_contract::extractor_receives_correct_data_and_lease_duration` |
| A-VAULT-CUSTOM-1: extractor receives None when no lease | `extractor_contract::extractor_receives_none_when_no_lease` |
| A-VAULT-CUSTOM-1: get() returns whatever extractor produces | `extractor_contract::get_returns_whatever_extractor_produces` |
| A-VAULT-CUSTOM-2: extractor error propagates as CredentialError | `extractor_contract::extractor_error_propagates_as_credential_error` |
| A-VAULT-CUSTOM-2: extractor error message is preserved verbatim | `extractor_contract::extractor_error_message_is_preserved_verbatim` |

### Adversarial / Boundary Tests (Tier 2)

| Scenario | Test name |
|---|---|
| 400 without "lease" keyword → Backend (not Revoked) | `edge_cases::map_error_non_lease_400_returns_backend` |
| Non-lease 400 is not Revoked (stub-killer) | `edge_cases::map_error_non_lease_400_is_not_revoked` |
| Unknown 4xx (409) → Backend | `edge_cases::map_error_unknown_4xx_returns_backend` |
| 404 message contains both mount AND path (stub-killer) | `edge_cases::map_error_404_configuration_message_contains_mount_slash_path` |
| 403 must not be Configuration (stub-killer) | `edge_cases::map_error_403_is_not_configuration` |
| Lease 400 must not be Backend (stub-killer) | `edge_cases::map_error_lease_400_is_not_backend` |
| get() passes None when lease_duration == 0 (integration, `#[ignore]`) | `edge_cases::get_with_zero_lease_duration_passes_none_to_extractor` |
| get() passes Some(N) when lease_duration == N>0 (integration, `#[ignore]`) | `edge_cases::get_with_positive_lease_duration_passes_some_to_extractor` |

### Property / Adversarial Tests (Tier 3)

| Scenario | Test name |
|---|---|
| All 5xx codes (500, 502, 503, 504) → Backend | `adversarial::map_error_all_5xx_codes_return_backend` |
| 5xx Backend message contains status code | `adversarial::map_error_5xx_backend_message_contains_status_code` |
| Different 5xx codes → distinct messages | `adversarial::map_error_different_5xx_codes_produce_distinct_messages` |
| TLS error is not Backend (must be Unreachable) | `adversarial::map_error_tls_is_not_backend` |
| Connection refused is not Backend (must be Unreachable) | `adversarial::map_error_connection_refused_is_not_backend` |

### Stub-killing strategy

- `map_error_403_is_not_configuration` + `map_error_404_returns_configuration_path_not_found` — together forbid a stub that maps all 4xx → Configuration.
- `map_error_non_lease_400_is_not_revoked` + `map_error_400_lease_returns_revoked` — together forbid both "always Revoked" and "never Revoked" stubs for 400 errors.
- `map_error_404_configuration_message_contains_mount_slash_path` — forbids a stub that returns a hardcoded "not found" without embedding the actual mount and path values.
- `map_error_different_5xx_codes_produce_distinct_messages` — forbids a stub that hardcodes a fixed 5xx message regardless of status code.
- `map_error_tls_is_not_backend` + `map_error_connection_refused_is_not_backend` — together forbid a stub that maps all RestClientErrors → Backend.
- `extractor_error_message_is_preserved_verbatim` — forbids a stub that wraps the extractor error in a new Backend message.

### Gaps / Known Limitations

- `get()` lease_duration mapping (tests 13 and 14) is not covered by unit tests — requires an HTTP-level mock or a live Vault instance. Tracked as `#[ignore]` integration test placeholders.
- `map_vaultrs_error` for `RestClientError` variants other than `RequestError` (e.g., `ServerResponseError`, `ReqwestBuildError`) is not explicitly tested; they fall through to the "any other" → Backend path.
- Property-based testing with `proptest` across arbitrary API error codes is not included; the Tier 3 tests use a fixed set of representative 5xx codes.

---

## VaultProvider — Task 4.0: DynamicCredentialsExtractor and VaultProvider\<UsernamePassword\>

**Source:** `credential-provider/src/vault_tests.rs` — `mod dynamic_credentials_extractor`
**Criticality:** Domain business logic — mutation score target: 85%
**Feature gate:** `vault`
**Status:** GREEN — 96 passing, 0 failing, 2 ignored (integration); mutation score 100% (28/28 viable)

### Specification Tests (Tier 1 — A-VAULT-DYN-1, extractor level)

| Assertion | Test name |
|---|---|
| A-VAULT-DYN-1: valid data + positive lease → Ok | `dynamic_credentials_extractor::valid_data_with_positive_lease_returns_ok` |
| A-VAULT-DYN-1: positive lease → expires_at is Some | `dynamic_credentials_extractor::valid_data_positive_lease_sets_some_expires_at` |
| A-VAULT-DYN-1: zero lease → expires_at is None | `dynamic_credentials_extractor::valid_data_zero_lease_returns_none_expires_at` |
| A-VAULT-DYN-1: None lease → expires_at is None | `dynamic_credentials_extractor::valid_data_none_lease_returns_none_expires_at` |

### Adversarial / Boundary Tests (Tier 2)

| Scenario | Test name |
|---|---|
| Missing "username" field → Err(Backend) | `dynamic_credentials_extractor::missing_username_returns_backend_error` |
| Missing "password" field → Err(Backend) | `dynamic_credentials_extractor::missing_password_returns_backend_error` |
| Missing-username error contains "username" | `dynamic_credentials_extractor::missing_username_error_message_contains_field_name` |
| Missing-password error contains "password" | `dynamic_credentials_extractor::missing_password_error_message_contains_field_name` |
| Username as number → Err(Backend) | `dynamic_credentials_extractor::username_as_number_returns_backend_error` |
| Password as bool → Err(Backend) | `dynamic_credentials_extractor::password_as_bool_returns_backend_error` |
| Username as null → Err(Backend) | `dynamic_credentials_extractor::username_as_null_returns_backend_error` |
| Username as array → Err(Backend) | `dynamic_credentials_extractor::username_as_array_returns_backend_error` |
| Extracted username matches data["username"] (stub-killer) | `dynamic_credentials_extractor::extracted_username_matches_data_username_field` |
| Extracted password matches data["password"] (stub-killer) | `dynamic_credentials_extractor::extracted_password_matches_data_password_field` |
| Different inputs → different usernames (stub-killer) | `dynamic_credentials_extractor::different_data_produces_different_extracted_usernames` |
| Different inputs → different passwords (stub-killer) | `dynamic_credentials_extractor::different_data_produces_different_extracted_passwords` |
| Lease == 1 (boundary) → Some(expires_at) | `dynamic_credentials_extractor::lease_boundary_one_second_produces_some_expires_at` |
| expires_at ≈ now + lease_duration (stub-killer for expiry math) | `dynamic_credentials_extractor::expires_at_is_approximately_now_plus_lease_duration` |
| Empty username string is valid | `dynamic_credentials_extractor::empty_username_string_is_valid` |
| Empty password string is valid | `dynamic_credentials_extractor::empty_password_string_is_valid` |
| Extra fields in data are ignored | `dynamic_credentials_extractor::extra_fields_in_data_are_ignored` |
| dynamic_credentials() constructor does not panic | `dynamic_credentials_extractor::dynamic_credentials_constructor_does_not_panic` |

### Property / Parameterized Tests (Tier 3)

| Scenario | Test name |
|---|---|
| All positive lease durations [1, 30, 300, 3600, 86400, 604800] → Some(expires_at) | `dynamic_credentials_extractor::multiple_positive_lease_durations_all_produce_some_expires_at` |
| Both zero and None leases → None expires_at | `dynamic_credentials_extractor::zero_and_none_lease_durations_both_produce_none_expires_at` |
| Diverse (username, password) pairs all extracted correctly | `dynamic_credentials_extractor::various_username_password_combinations_are_all_extracted_correctly` |
| No panic on any well-formed JSON shape | `dynamic_credentials_extractor::extract_does_not_panic_on_various_data_shapes` |

### Audit Report — Task 4.0

#### Tier 4 — Mutation Testing (cargo-mutants)

| Module | Score | Target | Status |
|--------|-------|--------|--------|
| `credential-provider/src/vault.rs` | 100% (28/28) | 85% | ✅ |

**Survivors found:** 0  
**Survivors killed:** 0 (none required)  
**New kill tests added:** 0  
**Report:** `docs/spec/mutation-report-task4.0-vault.json`

All 28 viable mutants were caught by the existing test suite. No new kill tests were required.

Key mutants caught in the new `DynamicCredentialsExtractor` code (lines 180–184):

| Mutant | Caught by |
|--------|-----------|
| `extract → Ok(Default::default())` (line 180) | `extracted_username_matches_data_username_field`, `extracted_password_matches_data_password_field` |
| `filter > to ==` for zero-lease (line 183) | `valid_data_zero_lease_returns_none_expires_at`, `zero_and_none_lease_durations_both_produce_none_expires_at` |
| `filter > to <` for zero-lease (line 183) | `lease_boundary_one_second_produces_some_expires_at` |
| `+ to -` for expiry calculation (line 184) | `expires_at_is_approximately_now_plus_lease_duration` |
| `+ to *` for expiry calculation (line 184) | `expires_at_is_approximately_now_plus_lease_duration` |
| `extract_str_field → Ok("")` (line 341) | `extracted_username_matches_data_username_field`, `extracted_password_matches_data_password_field` |
| `extract_str_field → Ok("xyzzy")` (line 341) | `extracted_username_matches_data_username_field`, `extracted_password_matches_data_password_field` |

#### Tier 5 — Fuzz Testing

The existing fuzz target `fuzz/fuzz_targets/fuzz_caching.rs` covers only the `CachingCredentialProvider` state machine. It does **not** cover `extract_str_field` or `DynamicCredentialsExtractor::extract()`.

**Assessment:** `extract_str_field` receives untrusted JSON from the Vault API response, making it a candidate for fuzz coverage. However, per task scope, creating a new fuzz target is deferred to a separate fuzz infrastructure task. The no-panic invariant is covered by `extract_does_not_panic_on_various_data_shapes` (unit test) and by the type-safety of `serde_json::Value` indexing.

**New fuzz targets created:** 0 (out of scope for this task)

#### Tier 6 — Formal Verification

Not required — domain-logic criticality tier.

#### Verdict: CLEAR

No survivors, no crashes, no blockers.
