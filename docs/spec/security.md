# Security

Threat model, mitigations, and security invariants for the `credential-provider` workspace.

---

## Threat Model

### Assets

| Asset | Sensitivity | Location |
|---|---|---|
| Passwords | High | In-memory (`SecretString`) |
| Bearer tokens | High | In-memory (`SecretString`) |
| HMAC keys | High | In-memory (`SecretVec<u8>`) |
| TLS private keys | Critical | In-memory (`SecretVec<u8>`) |
| AWS credentials | High | In-memory (wrapped SDK type) |
| Vault client token | High | Held by application, not by this crate |

### Threats and Mitigations

#### S-1: Secret material in memory after drop

**Threat:** Sensitive data remains in freed memory (heap or stack) after a credential is dropped, potentially recoverable via memory dumps or core dumps.

**Mitigation:** All secret fields use `secrecy::SecretString` or `secrecy::SecretVec<u8>`, which implement `Zeroize` on drop. This zeroes the memory before it is deallocated.

**Residual risk:** Intermediate copies made by the Rust runtime, allocator, or OS page cache are not zeroed. This is a known limitation of user-space zeroize.

---

#### S-2: Secret material in logs or debug output

**Threat:** Credential values appear in application logs via `Debug`, `Display`, or error messages.

**Mitigation:**

- `SecretString` and `SecretVec<u8>` implement `Debug` as `"[REDACTED]"`
- No `Display` implementation should render secret material
- `CredentialError` messages must never include credential values — only contextual information (paths, variable names, HTTP status codes)

**Constraint:** Credential type `Debug` implementations must be verified in code review. No custom `Debug` impl should bypass secrecy's redaction.

---

#### S-3: Environment variable exposure (env provider)

**Threat:** Environment variables are readable by any code running in the same process, and by privileged users via `/proc/<pid>/environ` on Linux.

**Mitigation:**

- The `env` provider is intended for local development and testing only
- Production deployments should use Vault, Azure, or AWS providers
- Documentation must clearly state this limitation
- The `env` provider re-reads on every call, so clearing env vars after startup is possible but not enforced

**Residual risk:** If used in production, environment variables are a weaker secret storage mechanism than a dedicated secrets manager.

---

#### S-4: Network interception of Vault communications

**Threat:** Credentials fetched from Vault could be intercepted in transit.

**Mitigation:**

- The `vaultrs` dependency is configured with the `rustls` feature (TLS by default)
- Vault communication must use HTTPS in production
- The application is responsible for providing the correct Vault address (HTTPS URL) and verifying the Vault TLS certificate

**Constraint:** The `vaultrs` dependency must never be configured with `native-tls` or TLS-disabled features.

---

#### S-5: Stale credential after backend revocation

**Threat:** A credential is revoked on the backend (e.g., Vault lease revocation), but the cached copy is still returned to consumers because it hasn't expired yet.

**Mitigation:**

- This is an accepted tradeoff (see T-3 in tradeoffs.md)
- The stale fallback window is bounded by the credential's actual `expires_at`
- Consumers performing sensitive operations should handle authentication failures as a signal to force refresh

**Residual risk:** During the stale window, the application may attempt operations with a revoked credential, which will fail at the backend (e.g., RabbitMQ rejects the connection).

---

#### S-6: Timing attacks on HMAC validation

**Threat:** Non-constant-time comparison of HMAC digests could leak information about the secret through timing side channels.

**Mitigation:** This is the **consumer's** responsibility, not the provider's. The provider only stores and delivers the HMAC key. Consumers (e.g., `webhook-handler`) must use constant-time comparison (e.g., `ring::hmac::verify` or `subtle::ConstantTimeEq`).

**Constraint:** Documentation should note this responsibility.

---

#### S-7: MockCredentialProvider in production

**Threat:** The mock provider is compiled into a production binary, allowing an attacker to inject arbitrary credentials.

**Mitigation:**

- Gated on `cfg(any(test, feature = "test-support"))`
- The `test-support` feature must never appear in production Cargo profiles
- A compile-time warning is emitted if `test-support` is enabled outside a test profile

**Constraint:** CI should verify that production builds do not enable `test-support`.

---

#### S-8: Dependency supply chain

**Threat:** A compromised version of a dependency (vaultrs, secrecy, etc.) introduces malicious behavior.

**Mitigation:**

- Use `cargo-deny` (configured via `deny.toml`) to audit dependencies for known vulnerabilities
- Pin workspace dependencies to specific versions in `Cargo.toml`
- Use `Cargo.lock` for reproducible builds
- Renovate (configured via `renovate.json`) for automated dependency update PRs with CI checks

---

## Security Invariants

These must hold at all times:

1. **No secret in logs:** No credential value appears in any `Debug`, `Display`, `Error`, or log output
2. **Zeroize on drop:** All secret material is zeroed when the credential is dropped
3. **TLS for Vault:** Vault communication uses TLS (rustls)
4. **No mock in prod:** `MockCredentialProvider` is not available in production builds
5. **No backend types in core:** Core crate has no dependency on any backend SDK
6. **Errors are safe:** `CredentialError` messages contain paths, status codes, and context — never credential values
