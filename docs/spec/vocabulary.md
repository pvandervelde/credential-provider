# Domain Vocabulary

This document defines the domain language used throughout the `credential-provider` workspace. The interface designer should use these names and definitions when creating concrete types.

---

## Core Concepts

### Credential

A set of data that proves identity or grants access to a resource. All credentials can report whether they are currently valid and when they expire (if known).

- **Trait bound:** `Send + Sync + Clone + 'static`
- **Key operations:** `is_valid()`, `expires_at()`

### CredentialProvider

A component that fetches fresh credentials from a specific backing store. A provider does **not** cache — it performs a live fetch every time `get()` is called.

- **Generic over:** The credential type it returns (`C: Credential`)
- **Key operation:** `get() -> Result<C, CredentialError>`
- **Concurrency:** Must be safe to call from multiple tasks simultaneously

### CachingCredentialProvider

A wrapper that sits between consumers and a raw `CredentialProvider`. It holds a cached credential and transparently refreshes it before expiry. Consumers interact with this wrapper exclusively — they never call the raw provider directly.

- **Key behavior:** Returns cached value when valid; fetches fresh when approaching expiry; falls back to stale-but-valid credential on fetch failure
- **Concurrency:** Serializes concurrent refresh requests (only one fetch in flight)

---

## Credential Types

### UsernamePassword

A pair of username (plain string) and password (secret string), optionally carrying an expiry. Used for queue brokers (RabbitMQ, NATS), databases, and similar username/password authentication.

- **Fields:** `username` (String), `password` (SecretString), `expires_at` (Option\<Instant\>)
- **Validity:** Valid until `expires_at`; always valid if no expiry set

### BearerToken

An opaque token string used in HTTP `Authorization` headers. Carries an optional expiry derived from the token issuer's response.

- **Fields:** `token` (SecretString), `expires_at` (Option\<Instant\>)
- **Validity:** Valid until `expires_at`; always valid if no expiry set

### HmacSecret

A symmetric key used for HMAC signature verification — primarily GitHub webhook signatures in this stack.

- **Fields:** `key` (SecretVec\<u8\>)
- **Validity:** Always valid (`is_valid() = true`, `expires_at() = None`)
- **Rotation:** Handled externally on a policy schedule, not by expiry

### TlsClientCertificate

A certificate and private key pair for mutual TLS authentication. Used when connecting to services that require client certificate verification (e.g., Vault PKI-issued certificates).

- **Fields:** `certificate_pem` (SecretVec\<u8\>), `private_key_pem` (SecretVec\<u8\>), `expires_at` (Option\<Instant\>)
- **Validity:** Valid until `expires_at`; always valid if no expiry set

### AwsCredentials

A wrapper around the AWS SDK credential type. Carries access key, secret key, optional session token, and optional expiry.

- **Defined in:** `credential-provider` crate (not core), since it wraps AWS-specific types
- **Validity:** Valid until expiry from credential source

---

## Error Concepts

### CredentialError

A classified error from credential fetching. Each variant carries a context message.

#### Backend

The backing store responded with an error (HTTP 500, malformed response, etc.). The provider translated it but the fetch failed.

#### Unreachable

The backing store could not be contacted (connection refused, DNS failure, timeout). Distinguished from Backend because the remediation differs (network issue vs. store issue).

#### Configuration

The provider is misconfigured — a required environment variable is missing, a Vault path does not exist, or a required field is absent. This is a deployment-time error, not a runtime transient.

#### Unavailable

No credential is available and no cached value exists. This is the terminal state when both fetch and cache fallback fail.

#### Revoked

The credential was explicitly revoked before its natural expiry. Distinct from expiry — revocation is an active action by an operator or policy, not a time-based event.

---

## Caching Concepts

### Refresh Window

The duration before expiry at which `CachingCredentialProvider` proactively fetches fresh credentials. For example, a 60-second refresh window means renewal starts when the cached credential has less than 60 seconds of remaining validity.

- **Configured per provider instance** via `refresh_before_expiry` parameter
- **Purpose:** Prevents using credentials that are about to expire during in-flight operations

### Stale Fallback

The behavior where `CachingCredentialProvider` returns a cached credential that is still technically valid (not yet expired) even when a refresh attempt fails. This provides resilience against transient backend outages.

- **Applies only when:** Cached credential exists AND `is_valid() = true`
- **Does not apply when:** Cache is empty or cached credential has expired

### Concurrent Refresh Serialization

When multiple tasks call `get()` simultaneously and the cache needs refreshing, only one fetch is dispatched. All other callers wait for that single fetch to complete and then receive the same result.

- **Purpose:** Prevents thundering herd against the backend
- **Implementation concern:** Requires synchronization primitive (e.g., `RwLock` or similar)

---

## Backend Concepts

### Secrets Engine

A Vault concept — a backend within Vault that generates or stores secrets. Vault ships with many secrets engines, and the `vault` feature is designed to work with any of them. Common categories:

- **Static secrets engines** (e.g., KV v1, KV v2): Store and retrieve key-value pairs. No lease or expiry.
- **Dynamic secrets engines** (e.g., RabbitMQ, database, AWS, PKI, SSH, Consul, etc.): Generate credentials on demand with a lease duration.
- **Crypto/utility engines** (e.g., Transit, TOTP): Perform operations rather than issuing credentials. Out of scope for this crate — these do not map to the `CredentialProvider<C>` model.

### Lease Duration

The time window during which a dynamic credential (from Vault) is valid. The Vault response includes this value, and providers translate it to `expires_at` on the credential.

### Credential Chain

A resolution strategy used by Azure Identity and AWS Config that tries multiple credential sources in order (managed identity → workload identity → environment → CLI/profile). The Azure and AWS providers delegate to these chains rather than implementing source resolution themselves.

### Mount Path

A Vault concept — the URL path prefix where a secrets engine is mounted (e.g., `"secret"` for KV, `"rabbitmq"` for the RabbitMQ engine, `"database"` for the database engine).

### Role Path

A Vault concept — the path within a secrets engine that identifies which set of permissions a dynamic credential will have (e.g., `"rabbitmq/creds/queue-keeper"`, `"database/creds/readonly"`).

### Response Extractor

A strategy that knows how to extract a specific credential type from a Vault secrets engine response. Each Vault engine returns data in a different JSON structure; the extractor translates that structure into the appropriate `Credential` type. This allows a single generic Vault provider to work with any secrets engine.
