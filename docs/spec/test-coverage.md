# Test Coverage

Maps behavioral assertions to test cases. Updated when new test suites are added.

---

## Credential Types (UsernamePassword, BearerToken, HmacSecret, TlsClientCertificate)

**Source:** `credential-provider-core/src/credentials.rs` — `#[cfg(test)] mod tests`
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

**Source:** `credential-provider-core/src/mock.rs` — `#[cfg(test)] mod tests`

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
