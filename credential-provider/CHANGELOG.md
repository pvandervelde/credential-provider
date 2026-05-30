# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/pvandervelde/credential-provider/releases/tag/credential-provider-v0.1.0) - 2026-05-30

### Added

- *(vault)* implement DynamicCredentialsExtractor and dynamic_credentials()
- *(vault)* implement map_vaultrs_error and VaultProvider::get()
- *(env)* implement get() methods for env credential providers
- add workspace scaffolding and interface stubs (Phases 1-3)

### Fixed

- *(vault)* address PR review comments — harmonise SecretString::new, scope catalog entry, update spec example
- *(vault)* address PR #19 review comments
- *(vault)* resolve all VERIFY findings — prefix stub params, fix doc order, add catalog entry, update test-coverage status
- *(env)* address PR review comments
- *(ci)* resolve all failing PR checks
- address PR review feedback

### Other

- *(vault)* fix stale TDD comments, update test-coverage count, mark task 4.0 complete
- *(vault)* add S-2 sentinel tests — error messages must not contain field values
- *(vault)* add audit and security certification evidence for task 4.0
- *(vault)* add DynamicCredentialsExtractor tests for A-VAULT-DYN-1 (auto via agent)
- Fix rust formatting
- Fix typo
- *(vault)* kill lease_duration survivors; fix(vault): extract lease_secs_from_raw, add file-path error arms, add security note; chore: update rustls-webpki 0.103.11->0.103.13 (RUSTSEC-2026-0098/0099/0104), add review-by dates to deny.toml
- *(vault)* extract rest_client_error helper in vault_tests; create docs/catalog.md
- *(vault)* add map_vaultrs_error and VaultExtractor contract tests (RED)
- *(env)* replace partial JWT test token to avoid secret scanner noise
- normalise line endings in aws and azure adapter stubs
- *(env)* add QA-identified gap tests for env credential providers
