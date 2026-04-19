# Test Coverage

Maps behavioral assertions to test cases. Updated when new test suites are added.

---

## CachingCredentialProvider::get()

**Source:** `credential-provider-core/src/caching.rs` — `#[cfg(test)] mod tests`
**Criticality:** Domain business logic — Tiers 1 + 2 required

### Specification Tests (Tier 1 — from assertions.md)

| Assertion | Test name |
|---|---|
| A-CACHE-1: empty cache triggers fetch | `empty_cache_calls_inner_and_returns_result` |
| A-CACHE-1: first fetch result is cached | `empty_cache_result_is_cached_second_call_does_not_refetch` |
| A-CACHE-1 + E-CACHE-1: first fetch failure returns `Unavailable` | `empty_cache_inner_failure_returns_unavailable` |
| A-CACHE-2: valid outside window — inner NOT called | `valid_credential_outside_refresh_window_not_fetched_again` |
| A-CACHE-2: cached value returned | `valid_credential_outside_refresh_window_returns_cached_value` |
| A-CACHE-3: inside window triggers refresh, returns new credential | `credential_inside_refresh_window_triggers_refresh_and_returns_new` |
| A-CACHE-3: old credential not returned when refresh succeeds | `credential_inside_refresh_window_does_not_return_old_value_on_success` |
| A-CACHE-4: refresh failure inside window → stale returned (not error) | `credential_inside_refresh_window_refresh_failure_returns_stale_not_error` |
| A-CACHE-4: stale fallback username matches cached credential | `stale_fallback_returns_specifically_the_still_valid_cached_username` |
| A-CACHE-5: expired cache + refresh failure → error propagated | `expired_credential_refresh_failure_propagates_error_not_stale` |
| A-CACHE-5: expired cache + failure propagates inner variant (not `Unavailable`) | `expired_credential_refresh_failure_propagates_original_error_variant_not_unavailable` |
| A-CACHE-6: concurrent calls serialize to one fetch | `concurrent_calls_on_empty_cache_serialize_to_one_fetch` |
| A-CACHE-7: no-expiry credential — inner called only once | `no_expiry_credential_inner_called_only_once_across_many_calls` |
| A-CACHE-7: no-expiry credential returns same bytes every call | `no_expiry_credential_returns_same_bytes_on_every_call` |
| A-CACHE-8: successful refresh returns new credential | `successful_refresh_returns_new_credential_not_old` |
| A-CACHE-8: subsequent call after refresh returns new credential from cache | `after_successful_refresh_subsequent_call_returns_new_credential` |

### Adversarial / Boundary Tests (Tier 2)

| Edge case | Test name |
|---|---|
| E-CACHE-2: credential at exact refresh window boundary triggers refresh | `credential_at_boundary_of_refresh_window_triggers_refresh` |

### Stub-killing strategy

- `empty_cache_result_is_cached_second_call_does_not_refetch` — the second response is `Err`; a non-caching stub would surface it.
- `empty_cache_inner_failure_returns_unavailable` + `expired_credential_refresh_failure_propagates_original_error_variant_not_unavailable` — together forbid both "always `Unavailable`" and "always propagate" stubs.
- `credential_inside_refresh_window_does_not_return_old_value_on_success` — forbids a stub that returns the cached value instead of the refresh result.
- `concurrent_calls_on_empty_cache_serialize_to_one_fetch` — the mock returns `"fetched-once"` on the first call and `"fetched-again"` on every subsequent call; all 8 tasks must return `"fetched-once"`.
- `no_expiry_credential_inner_called_only_once_across_many_calls` — the second inner response is `Err`; any extra fetch surfaces it.
- `after_successful_refresh_subsequent_call_returns_new_credential` — third inner response is `Err`; if the cache was not updated, the third call hits inner and fails.

### Gaps / Known Limitations

- **ADR-003 re-check timing**: the boundary between Rule 4 (stale fallback) and Rule 5 (propagate error) depends on `is_valid()` being evaluated *after* the failed refresh. This is partially covered by `expired_credential_refresh_failure_propagates_error_not_stale` but would benefit from an integration test using real time progression.
- **E-CACHE-3 (lease shorter than window)**: not covered — requires property-based tests across arbitrary `(expires_at, refresh_window)` pairs.
- **E-CACHE-6 (provider panic)**: not covered — panic propagation through `tokio::sync::RwLock` is a runtime concern; would require a purpose-built panicking mock.
- **Concurrency on stale cache**: A-CACHE-6 covers an empty cache; serialization on a stale-but-valid cache (Rules 3/4) is not covered by a dedicated concurrency test.
