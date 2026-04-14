# Environment Variable Adapters

**Architectural layer:** Adapters (`credential-provider`)
**Source file:** `credential-provider/src/env.rs`
**Feature flag:** `env` (default)
**External dependencies:** None

The three env providers read credentials from environment variables. They are
the simplest possible implementations and serve two purposes:

1. **Development default** — provide credentials without an external service
2. **Test double** — stand in for real providers in unit and integration tests

---

## Common Behaviour

- Variables are read on **every call to `get()`**, not at construction time.
  If the variable changes between calls (e.g., a secrets sidecar rewrites the
  environment), the change is picked up on the next `CachingCredentialProvider`
  refresh cycle.
- Returned credentials always have `is_valid() == true` and `expires_at() == None`
  (no expiry for env-sourced credentials).
- If a required variable is not set or is empty, `get()` returns
  `CredentialError::Configuration` with a message naming the variable.

---

## `EnvUsernamePasswordProvider`

### Purpose

Reads a username and password from a pair of named environment variables.
Returns a `UsernamePassword` credential.

### Constructor

```rust
pub fn new(username_var: impl Into<String>, password_var: impl Into<String>) -> Self
```

### Parameters

- `username_var` — name of the environment variable holding the username
- `password_var` — name of the environment variable holding the password

Both names are stored at construction time and used on every `get()` call.

### `get()` Behaviour

1. Read `username_var` from the environment
2. Return `CredentialError::Configuration("missing env var: {username_var}")` if absent or empty
3. Read `password_var` from the environment
4. Return `CredentialError::Configuration("missing env var: {password_var}")` if absent or empty
5. Construct and return `UsernamePassword::new(username, SecretString::new(password), None)`

### Error Conditions

| Condition | Error |
|---|---|
| `username_var` not set | `Configuration("missing env var: {name}")` |
| `username_var` set but empty | `Configuration("missing env var: {name}")` |
| `password_var` not set | `Configuration("missing env var: {name}")` |
| `password_var` set but empty | `Configuration("missing env var: {name}")` |

### Example

```rust
use credential_provider::env::EnvUsernamePasswordProvider;

let provider = EnvUsernamePasswordProvider::new("RABBITMQ_USERNAME", "RABBITMQ_PASSWORD");
```

---

## `EnvHmacSecretProvider`

### Purpose

Reads a hex- or base64-encoded HMAC key from a named environment variable.
Returns an `HmacSecret` credential.

### Constructor

```rust
pub fn new(secret_var: impl Into<String>) -> Self
```

### Parameters

- `secret_var` — name of the environment variable holding the hex or base64 key

### `get()` Behaviour

1. Read `secret_var` from the environment
2. Return `CredentialError::Configuration` if absent or empty
3. Attempt hex decode. If successful, use the decoded bytes.
4. If hex decode fails, attempt base64 decode (standard alphabet, with padding).
5. If both decode attempts fail, return `CredentialError::Configuration("invalid encoding for env var: {name}")`
6. Construct and return `HmacSecret::new(SecretVec::new(bytes))`

### Encoding Detection

Detection is attempted in this order: hex first, then base64. A value that is
valid hex will never be interpreted as base64. Applications should use hex
encoding for HMAC keys to avoid ambiguity.

### Error Conditions

| Condition | Error |
|---|---|
| `secret_var` not set | `Configuration("missing env var: {name}")` |
| `secret_var` set but empty | `Configuration("missing env var: {name}")` |
| Value not valid hex or base64 | `Configuration("invalid encoding for env var: {name}")` |

### Example

```rust
use credential_provider::env::EnvHmacSecretProvider;

let provider = EnvHmacSecretProvider::new("GITHUB_WEBHOOK_SECRET");
```

---

## `EnvBearerTokenProvider`

### Purpose

Reads an opaque bearer token from a named environment variable.
Returns a `BearerToken` credential.

### Constructor

```rust
pub fn new(token_var: impl Into<String>) -> Self
```

### Parameters

- `token_var` — name of the environment variable holding the token string

### `get()` Behaviour

1. Read `token_var` from the environment
2. Return `CredentialError::Configuration` if absent or empty
3. Construct and return `BearerToken::new(SecretString::new(token), None)`

### Error Conditions

| Condition | Error |
|---|---|
| `token_var` not set | `Configuration("missing env var: {name}")` |
| `token_var` set but empty | `Configuration("missing env var: {name}")` |

### Example

```rust
use credential_provider::env::EnvBearerTokenProvider;

let provider = EnvBearerTokenProvider::new("API_TOKEN");
```

---

## Security Note

The `env` provider is intended for **local development and testing only**.
Production deployments should use the Vault, Azure, or AWS providers.
Environment variables are readable by any code running in the same process and
by privileged users via `/proc/<pid>/environ` on Linux. See [security.md S-3].

[security.md S-3]: ../../security.md#s-3-environment-variable-exposure-env-provider
