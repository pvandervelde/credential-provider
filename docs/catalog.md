# Abstraction Catalog

A searchable inventory of every reusable function, type, and pattern in the workspace.
Coders must consult this before creating new abstractions.
Updated by the Refactor agent after each task.

The canonical type registry (traits, credential structs, provider structs) lives in
[`docs/spec/shared-registry.md`](spec/shared-registry.md).
This file records **implementation-level** helper abstractions: pure functions,
test utilities, and patterns that are candidates for reuse.

---

## Column guide

| Column | Meaning |
|--------|---------|
| Name | Symbol name wrapped in backticks |
| Kind | `fn`, `struct`, `trait`, `macro`, `const` |
| Location | `crate::module` path |
| Description | One sentence: what it does and when to reuse it |
| Tags | Comma-separated keywords for searching |

---

## Error Mapping

| Name | Kind | Location | Description | Tags |
|------|------|----------|-------------|------|
| `lease_secs_from_raw` | `fn` | `credential-provider::vault` | Converts a raw Vault `lease_duration` (`i32`) to `Option<u64>`: positive → `Some(secs)`, zero or negative → `None`. Use wherever a Vault API response's `lease_duration` field must be converted to an optional expiry duration. | vault, lease, conversion |
| `map_vaultrs_error` | `fn` | `credential-provider::vault` | Maps a `vaultrs::error::ClientError` to `CredentialError` using the classification table in `docs/spec/interfaces/vault-adapter.md`. Use wherever a `vaultrs` call result must cross the `CredentialError` boundary. | vault, error-mapping, error-handling |
| `tls_in_error_chain` | `fn` | `credential-provider::vault` | Walks the full `std::error::Error` source chain and returns `true` if any message contains TLS-related keywords. Use inside `RestClientError` arms to distinguish TLS failures from plain network failures. | vault, tls, error-handling, error-chain |
| `extract_str_field` | `fn` | `credential-provider::vault` | Reads a named string field from a Vault response `data` JSON object. Returns `CredentialError::Backend("missing field: {name}")` when the field is absent or not a JSON string. Use in every `VaultExtractor` impl that needs to pull a string value from the response `data`. | vault, extractor, json, error-handling |

---

## Test Utilities

| Name | Kind | Location | Description | Tags |
|------|------|----------|-------------|------|
| `rest_client_error` | `fn` | `credential-provider::vault` (test-only) | Builds a `VaultrsError::RestClientError` from a plain message string by wrapping it in a `rustify::errors::ClientError::RequestError`. Use in vault tests to construct network-error fixtures without repeating the seven-line constructor. | vault, test-utilities, fixtures |
