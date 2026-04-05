# Edge Cases

Non-standard flows, failure modes, and recovery behavior that need explicit handling or documentation.

---

## Caching Edge Cases

### E-CACHE-1: First call fails (empty cache, backend unreachable)

- **Scenario:** Application starts, cache is empty, first `get()` call fails because Vault is still starting up
- **Behavior:** Returns `CredentialError::Unreachable` (no stale fallback because cache is empty)
- **Consumer impact:** Application should retry with backoff at startup. This is expected during rolling deployments where the application may start before Vault is ready.
- **See:** A-CACHE-5

### E-CACHE-2: Credential expires exactly at refresh window boundary

- **Scenario:** `refresh_before_expiry` is 60 seconds, credential `expires_at` is exactly 60 seconds from now
- **Behavior:** The cache should treat this as "within the refresh window" (inclusive boundary) and trigger a refresh
- **Implementation note:** Use `<=` comparison, not `<`

### E-CACHE-3: Backend returns credential with very short lease

- **Scenario:** Vault returns a credential with a 5-second lease, but `refresh_before_expiry` is 60 seconds
- **Behavior:** The credential is immediately within (or past) the refresh window. The cache will attempt to refresh on the very next `get()` call.
- **Risk:** If every returned credential has a shorter lease than the refresh window, the cache degrades to pass-through mode (every call fetches). This is not a bug but should be monitored.

### E-CACHE-4: Backend returns credential with no expiry after previous expiring credential

- **Scenario:** Cache held an expiring credential, refresh returns a credential with `expires_at: None`
- **Behavior:** The new credential is cached and never refreshed (since it has no expiry). This is correct behavior — the backend changed its mind about expiry.

### E-CACHE-5: Clock drift or `Instant` overflow

- **Scenario:** System clock jumps, or `Instant::now()` behaves unexpectedly
- **Behavior:** `Instant` is monotonic in Rust, so clock drift (NTP adjustments) does not affect it. `Instant` cannot overflow in practice. No special handling needed.
- **Note:** This is a non-issue in Rust but worth documenting as explicitly safe.

### E-CACHE-6: Provider panics during refresh

- **Scenario:** The inner provider's `get()` panics (e.g., due to a bug in vaultrs)
- **Behavior:** The panic propagates through the `RwLock`. If a `Mutex` or `RwLock` is poisoned by a panic, subsequent calls will also fail.
- **Mitigation:** Providers should never panic — they should return `CredentialError` for all failure modes. A panic in a provider indicates a bug in the provider or its SDK.
- **Implementation note:** Consider using `tokio::sync::RwLock` (which does not poison on panic) rather than `std::sync::RwLock` (which does).

---

## Env Provider Edge Cases

### E-ENV-1: Environment variable contains only whitespace

- **Scenario:** `VAR_USER` = "   " (spaces only)
- **Behavior:** Should be treated as a non-empty value and returned as-is. Whitespace trimming is the consumer's responsibility, not the provider's.
- **Rationale:** The provider cannot know whether whitespace is meaningful (it usually isn't, but trimming silently could mask configuration errors).

### E-ENV-2: Environment variable contains non-UTF-8 bytes

- **Scenario:** On Unix, environment variables can contain arbitrary bytes
- **Behavior:** `std::env::var()` returns `Err(VarError::NotUnicode)` for non-UTF-8 values. This should map to `CredentialError::Configuration("variable contains invalid UTF-8: {name}")`.

### E-ENV-3: Environment variable changed between username and password reads

- **Scenario:** `EnvUsernamePasswordProvider` reads `VAR_USER`, then between that read and the `VAR_PASS` read, another thread changes the variables
- **Behavior:** A race condition. The provider may return a mismatched username/password pair.
- **Mitigation:** This is inherent to environment variables and is documented as a limitation. The env provider is intended for development/testing where this race is extremely unlikely. Production should use Vault.

### E-ENV-4: HMAC secret encoding ambiguity

- **Scenario:** Value `"deadbeef"` is valid as both hex and base64 (but decodes to different bytes)
- **Behavior:** Hex-first heuristic means hex wins. The value is decoded as 4 bytes `[0xDE, 0xAD, 0xBE, 0xEF]`, not as the base64 decoding.
- **Mitigation:** Document the hex-first priority. If this causes real issues, add an explicit encoding parameter as an alternative constructor.

---

## Vault Provider Edge Cases

### E-VAULT-1: Vault token expired

- **Scenario:** The `VaultClient`'s authentication token has expired. Provider calls to Vault fail with 403.
- **Behavior:** Returns `CredentialError::Backend("permission denied")`. The provider cannot distinguish between "token expired" and "policy denies access".
- **Consumer impact:** The application is responsible for renewing the Vault token. The `CachingCredentialProvider` stale fallback may buy time.

### E-VAULT-2: Vault returns empty credential fields

- **Scenario:** A dynamic engine role is misconfigured, Vault returns a response with empty username or password fields
- **Behavior:** The provider should still construct the credential with the empty values. It is not the provider's job to validate whether the credential is useful — that is the consumer's responsibility when it tries to authenticate.
- **Rationale:** The provider faithfully translates what the backend returns. Business rules about credential quality belong elsewhere.

### E-VAULT-3: KV v2 secret has no matching field

- **Scenario:** A `VaultProvider` configured with `kv2_secret` specifies field name `"value"`, but the KV secret only has `"key"` and `"data"`
- **Behavior:** Returns `CredentialError::Configuration("field not found: value in secret at {path}")`.
- **See:** A-VAULT-KV-3

### E-VAULT-4: Vault response with zero lease duration

- **Scenario:** Vault returns a valid credential but with `lease_duration: 0`
- **Behavior:** The credential is constructed with `expires_at: None` (treat zero as "no expiry"). A zero lease typically means the secret is static.
- **Alternative:** Treat as immediate expiry. But this would cause the caching layer to refresh on every call, which is undesirable for static secrets.

### E-VAULT-5: Response field value is not a string

- **Scenario:** The field value in a KV v2 response is a number, boolean, or nested object instead of a string
- **Behavior:** Returns `CredentialError::Backend("unexpected response: field '{name}' is not a string")`.

### E-VAULT-6: Custom extractor receives unexpected response shape

- **Scenario:** A `VaultProvider` configured with a custom extractor encounters a response that the extractor does not understand (e.g., engine was reconfigured)
- **Behavior:** The extractor returns an error, which the provider translates to `CredentialError::Backend("unexpected response: ...")`.
- **Rationale:** The provider itself does not know the expected shape — that is the extractor's responsibility.

---

## Azure Provider Edge Cases

### E-AZURE-1: Token refresh race with Azure SDK

- **Scenario:** Azure Identity SDK has its own internal caching/refresh logic
- **Behavior:** The `CachingCredentialProvider` and Azure SDK may both try to refresh tokens. This is harmless — the worst case is a redundant token request.
- **Note:** The Azure provider should pass through the SDK's token as-is, including its expiry. The SDK's internal caching should not conflict with ours.

### E-AZURE-2: Scope mismatch

- **Scenario:** The configured OAuth2 scope does not match the target resource
- **Behavior:** Azure Identity will return an error (token acquisition fails). Maps to `CredentialError::Backend`.

---

## AWS Provider Edge Cases

### E-AWS-1: Instance metadata service (IMDS) timeout

- **Scenario:** Running on EC2 but IMDS is temporarily unavailable
- **Behavior:** AWS SDK will timeout after its configured period. Maps to `CredentialError::Unreachable`.
- **Note:** The stale fallback in `CachingCredentialProvider` is particularly valuable here, as IMDS can be briefly unavailable during instance lifecycle events.

### E-AWS-2: Multiple credential sources available

- **Scenario:** Both environment variables and IAM role credentials are available
- **Behavior:** AWS SDK credential chain resolves in priority order. The provider does not control this ordering — it delegates entirely to `aws-config`.
