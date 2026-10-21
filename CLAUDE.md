# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Windows (all projects including WPF sample)
dotnet build Okta.Client.Sdk.sln

# Linux/macOS or when excluding Windows-only projects
dotnet build Okta.Client.Sdk.CrossPlatform.slnf

# Run all tests
dotnet test Okta.Client.Sdk.CrossPlatform.slnf

# Run tests (Release, with TRX output - matches CI)
dotnet test --no-build --configuration Release --logger "trx;LogFileName=test_results.trx"

# Run a single test
dotnet test --filter "FullyQualifiedName~TestClassName.TestMethodName"
```

Requires .NET 8.0 SDK. All projects target `net8.0` with nullable reference types and implicit usings enabled.

## Project Structure

- **`Okta.AuthFoundation/`** — Foundation library. OAuth2 HTTP client, token/credential management, JWT validation, HTTP abstractions. No external auth-flow logic.
- **`Okta.OAuth2/`** — Authentication flows (Authorization Code + PKCE, Resource Owner Password, Session Logout). Depends only on `Okta.AuthFoundation`.
- **`Okta.Idx/`** / **`Okta.DirectAuth/`** — Stubs, not yet implemented.
- **`Okta.Client.Sdk.Tests/`** — xUnit tests with NSubstitute mocking. References both `Okta.AuthFoundation` and `Okta.OAuth2`.
- **`Samples/`** — Console and WPF sample apps showing end-to-end flows.

## Architecture

### Layers

```
Samples
  └─ Okta.OAuth2 (flows: AuthorizationCode, ResourceOwner, SessionLogout)
       └─ Okta.AuthFoundation
            ├─ OAuth2/ (OAuth2Client, configuration, token requests/responses)
            ├─ TokenManagement/ (Token, Credential, CredentialCoordinator, storage)
            ├─ Jwt/ (ID token, JWK, and token hash validation)
            └─ Http/ (ApiClient, ApiRequest, ApiResponse<T>, UserAgent)
```

### Key Types

**`OAuth2Client`** (`Okta.AuthFoundation/OAuth2/`) — Handles all HTTP interactions with the authorization server: token exchange, refresh, revocation, introspection, userinfo, and JWKS fetching. Accepts optional `HttpClient`, `IIdTokenValidator`, and `ITokenHashValidator` via constructor injection.

**`Token`** (`Okta.AuthFoundation/TokenManagement/`) — Token class. Parses scope list and ID token claims on construction. Has `Merge()` for applying refresh responses.

**`Credential`** (`Okta.AuthFoundation/TokenManagement/`) — Combines a `Token` with its `OAuth2Client` and metadata. The main object consumers interact with. Provides `RefreshAsync()`, `RevokeAsync()`, `IntrospectAsync()`, `GetUserInfoAsync()`, and `AuthorizeAsync()` convenience methods.

**`CredentialCoordinator`** (`Okta.AuthFoundation/TokenManagement/`) — Singleton-like coordinator managing credential lifecycle: loading from storage, caching, refresh deduplication via `CoalescedResult<T>`, and write-back. Accessed via `Credential.DefaultCredentialAsync()` and other static methods on `Credential`.

**`ITokenStorage`** / implementations — `FileTokenStorage` (cross-platform JSON at `{LocalApplicationData}/OktaSdk/tokens.json`); `EncryptedTokenStorage` (Windows-only DPAPI, `tokens.encrypted.json`). Both are write-through with in-memory cache and a lock for thread safety.

**`AuthorizationCodeFlow`** (`Okta.OAuth2/Flows/`) — Start: generates PKCE challenge + authorization URL. Resume: exchanges code for tokens via `OAuth2Client`. State held in-memory between start and resume.

**`ApiResponse<T>`** — Result wrapper used throughout. Check `.IsSuccess` before accessing `.Result`. Created via static `Success()` / `Failure()` factories.

### Patterns

- **Module initialization**: `[ModuleInitializer]` in each project's `ModuleInit.cs` auto-registers user-agent strings at load time — no explicit setup required.
- **Dependency injection**: All major types take interface dependencies. `CredentialCoordinator` defaults to `FileTokenStorage` + `DefaultCredentialDataSource` but these are swappable.
- **Thread safety**: Storage classes use `lock`; `CredentialCoordinator` uses `SemaphoreSlim` for async coordination.
- **Events**: `OAuth2Client.TokenRefreshed`, `ITokenStorage.DefaultTokenChanged`, `ICredentialDataSource.CredentialAdded` — coordinator subscribes to wire up the lifecycle.
- **`CoalescedResult<T>`**: Deduplicates concurrent refresh calls so only one HTTP request fires.
- **Error messages**: When re-throwing or wrapping an error, pass the original message directly — do not concatenate your own prefix onto it.

### Versioning

`Sdk.props` (imported by all projects) runs a build target that generates `VersionInfo.g.cs` with the SDK version constant.
