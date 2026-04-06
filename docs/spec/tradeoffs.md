# Design Tradeoffs

Alternatives considered during architectural design, with rationale for the chosen approach.

---

## T-1: Single trait vs. typed provider traits

### Options

**A) Single generic trait `CredentialProvider<C>`** (chosen)

- One trait, generic over the credential type
- Implementations specify which `C` they provide

**B) Separate traits per credential type**

- `UsernamePasswordProvider`, `BearerTokenProvider`, `HmacSecretProvider`, etc.
- Each with its own `get()` returning the specific type

### Decision: Option A

**Pros:**

- Single abstraction to learn and implement
- `CachingCredentialProvider<C, P>` works for any credential type without specialization
- Adding a new credential type doesn't require a new trait
- Consumers can be generic over the credential type

**Cons:**

- Slightly more complex type signatures with generics
- Cannot have a provider that returns different credential types from the same instance

**Rationale:** The caching wrapper is the deciding factor. A single generic trait means one `CachingCredentialProvider` implementation covers all credential types. With separate traits, caching would need to be duplicated or use a more complex macro-based approach.

---

## T-2: RwLock vs. Mutex for cache

### Options

**A) `tokio::sync::RwLock<Option<C>>`** (chosen)

- Multiple concurrent readers (the common case: cache hit)
- Exclusive writer during refresh

**B) `tokio::sync::Mutex<Option<C>>`**

- Simpler implementation
- All access serialized (blocks reads during refresh)

**C) `std::sync::RwLock` with `tokio::sync::Notify`**

- No async lock dependency
- Manual notification for refresh completion

### Decision: Option A

**Rationale:** The dominant operation is reading the cache (cache hit path). `RwLock` allows all concurrent reads to proceed without blocking. Writes (refresh) are infrequent. The `tokio::sync` variant is required because the lock must be held across an `.await` point during refresh.

**Note:** Concurrent refresh serialization (only one fetch in flight) is handled by a separate `Mutex<()>` field (`refresh_lock`) on `CachingCredentialProvider`. The `RwLock` protects the cached value; the `Mutex` ensures a single writer performs the fetch while other tasks wait. See the struct definition in [credential-provider-core.md](credential-provider-core.md#cachingcredentialprovider).

---

## T-3: Stale fallback vs. strict freshness

### Options

**A) Stale fallback** (chosen)

- On refresh failure, return cached credential if still technically valid
- Prevents hard failure during transient outages

**B) Strict freshness**

- Any refresh failure propagates immediately
- Consumer knows credentials are always recent

### Decision: Option A

**Pros:**

- Resilience against transient Vault/backend outages
- A 5-second Vault restart doesn't cascade into application failures
- Credentials in the stale window are still technically valid (within their lease)

**Cons:**

- Application may use credentials closer to expiry, increasing risk of mid-operation expiry
- If the backend has actually revoked the credential but the cache doesn't know, the stale credential will fail when used
- Harder to reason about exactly when credentials changed

**Rationale:** Services running on self-hosted infrastructure will experience transient backend outages (e.g., secrets manager restarts for upgrades or config changes). The stale fallback window is bounded by the credential's actual expiry — it is never truly unbounded.

**Mitigation:** Consumers that need strict freshness can set `refresh_before_expiry` to the full credential lifetime, effectively disabling caching. But this is not recommended.

---

## T-4: secrecy 0.8 vs. 0.10+

### Options

**A) secrecy 0.8** (chosen)

- `SecretString` is a type alias for `Secret<String>`
- Stable, widely used in the ecosystem
- `serde` feature for optional serialization support

**B) secrecy 0.10+**

- Breaking API changes from 0.8
- Different `Zeroize` trait integration
- Fewer downstream crates have adopted it yet

### Decision: Option A

**Rationale:** The 0.8 line is well-established and compatible with `vaultrs` and other dependencies in the ecosystem. Migration to 0.10+ can happen in a future major release when the ecosystem has caught up.

---

## T-5: TlsClientCertificate in core vs. separate crate

### Options

**A) In core** (chosen)

- Available to any consumer without additional dependencies
- Consistent with the other credential types

**B) Separate feature or crate**

- Keeps core smaller
- Only used by mTLS scenarios (currently uncommon in the stack)

### Decision: Option A

**Rationale:** `TlsClientCertificate` has no dependencies beyond `secrecy` (which core already uses). It costs nothing to include. mTLS may be used by any connection type (database, queue broker, API), not just Vault PKI. Keeping it in core prevents a future breaking change when mTLS is needed.

---

## T-6: Auto-detect hex/base64 encoding vs. explicit configuration

### Options

**A) Auto-detect** (chosen as specified)

- `EnvHmacSecretProvider` tries hex first, then base64
- No configuration for encoding format

**B) Explicit encoding parameter**

- Constructor takes an `Encoding` enum: `Hex`, `Base64`, `Raw`
- No ambiguity in parsing

### Decision: Option A (with caveats)

**Rationale:** The spec states the provider reads "hex- or base64-encoded" secrets. Auto-detection keeps the API simple for the common case. The detection heuristic is: try hex decode first (all characters are `[0-9a-fA-F]` and even length); if that fails, try base64; if both fail, return `Configuration` error.

**Caveat:** A string like `"deadbeef"` is valid both as hex and as base64 (decoding to different bytes). The hex-first heuristic means hex wins in ambiguous cases. This should be documented. If this causes real-world confusion, Option B can be added as an alternative constructor without breaking the existing API.

---

## T-7: AwsCredentials in core vs. adapter crate

### Options

**A) In adapter crate** (chosen)

- Wraps `aws-credential-types::Credentials` which is an AWS SDK type
- Cannot be in core without adding AWS dependency to core

**B) Define a generic cloud credential type in core**

- e.g., `CloudCredential { access_key, secret_key, session_token, expiry }`
- Core stays backend-agnostic

### Decision: Option A

**Rationale:** The AWS credential type wraps SDK-specific internals. Modeling it abstractly in core would either lose information or create a leaky abstraction. The adapter crate is the right place for backend-specific credential types. The `Credential` trait in core is sufficient to handle it generically.

---

## T-8: Provider authentication (Vault) — internal vs. external

### Options

**A) External authentication** (chosen)

- Application authenticates `VaultClient` before passing it to providers
- Provider receives an authenticated client

**B) Provider manages authentication**

- Provider takes auth credentials and authenticates on first use or reconnection

### Decision: Option A

**Pros:**

- Separation of concerns: authentication strategy is independent of secrets engine access
- Application can use any Vault auth method (AppRole, JWT, Kubernetes, certificate)
- Provider code is simpler
- No authentication retry logic in the provider

**Cons:**

- Application must handle Vault token renewal separately
- If the Vault token expires, provider calls fail until the application re-authenticates

**Rationale:** Authentication method varies by deployment environment (AppRole for services, JWT for CI, Kubernetes for K8s). Baking this into each provider would create a combinatorial explosion. The application is the right place to manage the Vault client lifecycle.
