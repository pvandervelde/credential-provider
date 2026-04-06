# Behavioral Assertions

Testable behavioral specifications for all components. Each assertion follows Given/When/Then format and maps to one or more test cases.

---

## Credential Validity

### A-CRED-1: Credential with no expiry is always valid

- **Given:** A credential where `expires_at()` returns `None`
- **When:** `is_valid()` is called
- **Then:** Returns `true`

### A-CRED-2: Credential with future expiry is valid

- **Given:** A credential where `expires_at()` returns `Some(instant)` and `instant` is in the future
- **When:** `is_valid()` is called
- **Then:** Returns `true`

### A-CRED-3: Credential with past expiry is invalid

- **Given:** A credential where `expires_at()` returns `Some(instant)` and `instant` is in the past
- **When:** `is_valid()` is called
- **Then:** Returns `false`

### A-CRED-4: HmacSecret is always valid

- **Given:** An `HmacSecret` with any key value
- **When:** `is_valid()` is called
- **Then:** Returns `true`
- **And:** `expires_at()` returns `None`

---

## CachingCredentialProvider

### A-CACHE-1: Empty cache triggers fetch

- **Given:** A `CachingCredentialProvider` with no cached credential
- **When:** `get()` is called
- **Then:** The inner provider's `get()` is called exactly once
- **And:** The result is returned to the caller
- **And:** The result is cached for subsequent calls

### A-CACHE-2: Valid cached credential outside refresh window is returned directly

- **Given:** A `CachingCredentialProvider` with a cached credential that:
  - `is_valid()` returns `true`
  - `expires_at()` is more than `refresh_before_expiry` in the future
- **When:** `get()` is called
- **Then:** The cached credential is returned
- **And:** The inner provider's `get()` is NOT called

### A-CACHE-3: Credential within refresh window triggers refresh — success

- **Given:** A `CachingCredentialProvider` with a cached credential that:
  - `is_valid()` returns `true`
  - `expires_at()` is within `refresh_before_expiry` of now
- **And:** The inner provider returns a new credential successfully
- **When:** `get()` is called
- **Then:** The inner provider's `get()` is called
- **And:** The new credential is cached
- **And:** The new credential is returned

### A-CACHE-4: Credential within refresh window triggers refresh — failure with stale fallback

- **Given:** A `CachingCredentialProvider` with a cached credential that:
  - `is_valid()` returns `true`
  - `expires_at()` is within `refresh_before_expiry` of now
- **And:** The inner provider returns `Err(CredentialError)`
- **When:** `get()` is called
- **Then:** The stale cached credential is returned (not the error)

### A-CACHE-5: Expired cached credential, refresh fails, propagates error

- **Given:** A `CachingCredentialProvider` with a cached credential that:
  - `is_valid()` returns `false` (expired)
- **And:** The inner provider returns `Err(CredentialError)`
- **When:** `get()` is called
- **Then:** The `CredentialError` is propagated to the caller

### A-CACHE-6: Concurrent calls serialize to one fetch

- **Given:** A `CachingCredentialProvider` with a stale or empty cache
- **When:** Multiple tasks call `get()` concurrently
- **Then:** The inner provider's `get()` is called exactly once
- **And:** All callers receive the result of that single fetch

### A-CACHE-7: Cache with no-expiry credential never refreshes

- **Given:** A `CachingCredentialProvider` with a cached `HmacSecret` (no expiry)
- **When:** `get()` is called repeatedly
- **Then:** The inner provider's `get()` is called only once (the initial fetch)
- **And:** The cached value is returned on all subsequent calls

### A-CACHE-8: Successful refresh replaces the cached value

- **Given:** A `CachingCredentialProvider` that has just refreshed successfully
- **When:** `get()` is called again (within the new credential's validity window)
- **Then:** The newly cached credential is returned, not the original

---

## EnvUsernamePasswordProvider

### A-ENV-UP-1: Both variables set returns credential

- **Given:** Environment variables `VAR_USER` = "alice" and `VAR_PASS` = "secret"
- **When:** `get()` is called on `EnvUsernamePasswordProvider::new("VAR_USER", "VAR_PASS")`
- **Then:** Returns `Ok(UsernamePassword { username: "alice", password: "secret", expires_at: None })`

### A-ENV-UP-2: Missing username variable returns Configuration error

- **Given:** `VAR_USER` is not set, `VAR_PASS` = "secret"
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Configuration(...))`

### A-ENV-UP-3: Missing password variable returns Configuration error

- **Given:** `VAR_USER` = "alice", `VAR_PASS` is not set
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Configuration(...))`

### A-ENV-UP-4: Empty variable returns Configuration error

- **Given:** `VAR_USER` = "" (empty string)
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Configuration(...))`

### A-ENV-UP-5: Re-reads on every call

- **Given:** `VAR_USER` = "alice", `VAR_PASS` = "secret1"
- **When:** `get()` is called, then `VAR_PASS` is changed to "secret2", then `get()` is called again
- **Then:** First call returns password "secret1", second call returns password "secret2"

### A-ENV-UP-6: Returned credential has no expiry

- **Given:** Both variables set
- **When:** `get()` returns successfully
- **Then:** `credential.expires_at()` is `None`
- **And:** `credential.is_valid()` is `true`

---

## EnvHmacSecretProvider

### A-ENV-HMAC-1: Hex-encoded variable returns decoded secret

- **Given:** `VAR_SECRET` = "deadbeef" (valid hex)
- **When:** `get()` is called on `EnvHmacSecretProvider::new("VAR_SECRET")`
- **Then:** Returns `Ok(HmacSecret)` with `key` = `[0xDE, 0xAD, 0xBE, 0xEF]`

### A-ENV-HMAC-2: Base64-encoded variable returns decoded secret

- **Given:** `VAR_SECRET` = "3q2+7w==" (valid base64 for `[0xDE, 0xAD, 0xBE, 0xEF]`)
- **When:** `get()` is called
- **Then:** Returns `Ok(HmacSecret)` with correctly decoded key bytes

### A-ENV-HMAC-3: Missing variable returns Configuration error

- **Given:** `VAR_SECRET` is not set
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Configuration(...))`

### A-ENV-HMAC-4: Empty variable returns Configuration error

- **Given:** `VAR_SECRET` = ""
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Configuration(...))`

### A-ENV-HMAC-5: Invalid encoding returns Configuration error

- **Given:** `VAR_SECRET` = "not-valid-hex-or-base64!!!"
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Configuration(...))`

---

## EnvBearerTokenProvider

### A-ENV-BT-1: Variable set returns token

- **Given:** `VAR_TOKEN` = "my-api-token"
- **When:** `get()` is called on `EnvBearerTokenProvider::new("VAR_TOKEN")`
- **Then:** Returns `Ok(BearerToken { token: "my-api-token", expires_at: None })`

### A-ENV-BT-2: Missing variable returns Configuration error

- **Given:** `VAR_TOKEN` is not set
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Configuration(...))`

### A-ENV-BT-3: Empty variable returns Configuration error

- **Given:** `VAR_TOKEN` = ""
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Configuration(...))`

---

## VaultProvider — Dynamic Credentials

### A-VAULT-DYN-1: Valid path returns credential with expiry

- **Given:** Vault is reachable, mount path and role path exist and are authorized
- **When:** `get()` is called on a `VaultProvider` configured for a dynamic engine
- **Then:** Returns `Ok(UsernamePassword)` with `username`, `password`, and `expires_at` derived from Vault's `lease_duration`

### A-VAULT-DYN-2: 403 Forbidden maps to Backend error

- **Given:** Vault returns HTTP 403
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Backend("permission denied"))`

### A-VAULT-DYN-3: 404 Not Found maps to Configuration error

- **Given:** Vault returns HTTP 404 (mount or role path does not exist)
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Configuration("role or path not found: {path}"))`

### A-VAULT-DYN-4: Connection failure maps to Unreachable

- **Given:** Vault is not reachable (connection refused, DNS failure, timeout)
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Unreachable("..."))`

### A-VAULT-DYN-5: Revoked lease maps to Revoked

- **Given:** The previously issued lease has been revoked
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Revoked)`

### A-VAULT-DYN-6: Malformed response maps to Backend error

- **Given:** Vault returns a response that cannot be parsed by the extractor
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Backend("unexpected response: ..."))`

---

## VaultProvider — KV v2

### A-VAULT-KV-1: Valid path and field returns secret

- **Given:** Vault is reachable, KV v2 path exists, field exists in the secret
- **When:** `get()` is called on a `VaultProvider` configured with `kv2_secret`
- **Then:** Returns `Ok` with the field value extracted into the credential type

### A-VAULT-KV-2: Path not found returns Configuration error

- **Given:** The KV v2 path does not exist
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Configuration("role or path not found: ..."))`

### A-VAULT-KV-3: Field not found returns Configuration error

- **Given:** The path exists but the specified field does not
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Configuration("field not found: ..."))`

### A-VAULT-KV-4: Permission denied returns Backend error

- **Given:** Vault returns HTTP 403
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Backend("permission denied"))`

---

## VaultProvider — Custom Extractor

### A-VAULT-CUSTOM-1: Custom extractor receives full Vault response

- **Given:** A `VaultProvider` configured with a custom extractor
- **When:** Vault returns a successful response
- **Then:** The extractor receives the full response data and lease metadata
- **And:** The credential returned by `get()` is whatever the extractor produces

### A-VAULT-CUSTOM-2: Extractor failure maps to Backend error

- **Given:** The custom extractor returns an error (e.g., unexpected response shape)
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Backend("..."))`

---

## AzureCredentialProvider

### A-AZURE-1: Managed identity available returns token with expiry

- **Given:** Running on Azure infrastructure with managed identity
- **When:** `get()` is called
- **Then:** Returns `Ok(BearerToken)` with token and `expires_at` from Azure response

### A-AZURE-2: No identity available returns Configuration error

- **Given:** No Azure identity source is available
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Configuration(...))`

### A-AZURE-3: Token acquisition failure returns Backend error

- **Given:** Identity source exists but token request fails
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Backend(...))`

---

## AwsCredentialProvider

### A-AWS-1: IAM role available returns credentials with expiry

- **Given:** Running on AWS infrastructure with IAM role
- **When:** `get()` is called
- **Then:** Returns `Ok(AwsCredentials)` with credentials and `expires_at` from AWS response

### A-AWS-2: No credentials available returns Configuration error

- **Given:** No AWS credential source is available
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Configuration(...))`

### A-AWS-3: Credential resolution failure returns Backend error

- **Given:** Credential source exists but resolution fails
- **When:** `get()` is called
- **Then:** Returns `Err(CredentialError::Backend(...))`
