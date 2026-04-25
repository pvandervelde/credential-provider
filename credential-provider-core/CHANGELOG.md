# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/pvandervelde/credential-provider/releases/tag/credential-provider-core-v0.1.0) - 2026-04-25

### Added

- *(caching)* emit credential_cache_stale_fallbacks_total metric on stale fallback
- *(caching)* implement CachingCredentialProvider::get()
- add workspace scaffolding and interface stubs (Phases 1-3)

### Fixed

- *(ci,tests)* address PR review comments
- address second round of PR review issues
- *(ci)* resolve all failing PR checks
- *(caching)* address PR review issues 1-5
- *(caching)* assert refresh_before_expiry is positive in constructor
- *(caching)* restructure hot path and fix stale-fallback post-lock classification
- *(caching)* include refresh error in stale fallback warn log
- address PR review feedback

### Other

- *(credentials,mock)* add tests for A-CRED-1 to A-CRED-4 and call_count
- *(caching)* move tests to caching_tests.rs per testing standard
- *(caching)* add tests for A-CACHE-1 through A-CACHE-8
