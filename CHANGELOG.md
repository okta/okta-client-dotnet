# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 0.2.0 - 2026-11-17

First release published from this repository.

### Added

- Device Authorization and Token Exchange flows.
- Confidential client authentication: client secret and private key JWT.
- Token introspection, revocation, and userinfo.
- `OktaConfiguration` for loading configuration from a file.
- Dependency injection through `OktaServices`, so the storage, validation,
  and HTTP components can be replaced.
- Typed claim access on tokens and ID tokens.
- Rate limit reporting and configurable retry on the HTTP layer.
- Token hash validation of `at_hash` and `c_hash`.

### Changed

- Token storage is now platform-native and encrypted at rest: DPAPI on
  Windows, and a file key or the system keyring on Linux.
- The ID token issuer is validated against the configured base URL, and the
  discovery URL is derived structurally rather than by string concatenation.
- Token values on `Token` are set at construction and can no longer be
  reassigned by consumers.
- Claims are no longer written to stored metadata unless explicitly enabled.

### Deprecated

- The Resource Owner flow.

## 0.1.0 - 2026-03-10

Internal release only. Focused on the Authorization Code flow.
