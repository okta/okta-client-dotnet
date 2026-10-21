# Okta Client SDK for .NET

A .NET SDK for integrating [Okta](https://www.okta.com/) authentication and OAuth2 flows into your applications. The SDK provides token management, credential storage, JWT validation, and support for multiple OAuth2 authentication flows.

> **Status:** This SDK is currently in early development (v0.1.0, MVP) and currently focuses on the Authorization Code grant with PKCE.

## Packages

| Package | Description |
|---|---|
| **Okta.AuthFoundation** | Core library providing OAuth2 client, token management, credential storage, JWT validation, and HTTP abstractions. |
| **Okta.OAuth2** | OAuth2 authentication flows including Authorization Code (with PKCE), Resource Owner Password, and Session Logout. |


## Prerequisites

- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) or later
- An [Okta Developer Account](https://developer.okta.com/signup/)
- An Okta application configured with the appropriate grant types (e.g., Authorization Code, Refresh Token)

## Installation

```bash
dotnet add package Okta.AuthFoundation
dotnet add package Okta.OAuth2
```

## Quick Start

### Authorization Code Flow (with PKCE)

```csharp
using Okta.AuthFoundation.OAuth2;
using Okta.OAuth2.Flows;

var config = new OAuth2ClientConfiguration(
    new Uri("https://your-domain.okta.com/oauth2/default"),
    "your-client-id",
    new List<string> { "openid", "profile", "email", "offline_access" }
);

var client = new OAuth2Client(config);
var flow = new AuthorizationCodeFlow(client, "http://localhost:8080/callback");

// 1. Generate the authorization URL and redirect the user
Uri authorizeUrl = await flow.StartAsync();

// 2. After the user authenticates, exchange the callback for tokens
var response = await flow.ResumeAsync(callbackUri);

if (response.IsSuccess)
{
    Token token = response.Result;
    Console.WriteLine($"Access Token: {token.AccessToken}");
}
```


## Samples

The repository includes sample applications demonstrating SDK usage:

| Sample | Description | Platform |
|---|---|---|
| **ConsoleWebRedirectSample** | Console app using the Authorization Code flow with a loopback HTTP listener | Cross-platform |
| **WebRedirectSample** | WPF desktop app using the Authorization Code flow | Windows only |
| **ResourceOwnerFlowSample** | Console app using the Resource Owner Password flow | Cross-platform |

### Running the Console Sample

1. Copy the example configuration and fill in your Okta settings:

```json
{
  "OAuth2": {
    "IssuerUrl": "https://your-domain.okta.com/oauth2/default",
    "ClientId": "your-client-id",
    "RedirectUri": "http://localhost:8080/callback",
    "Scopes": [ "openid", "profile", "email", "offline_access" ]
  }
}
```

2. Run the sample:

```bash
cd Samples/ConsoleWebRedirectSample
# Edit appsettings.json with your Okta configuration
dotnet run
```

## Time Coordination

Device clocks cannot be relied on. Users adjust them manually for a variety of reasons (including changing the date to claim daily rewards in games), devices drift, and portable devices roam across time zones. A clock that is wildly off affects every time-sensitive operation in the SDK: token expiration checks, `iat`/`auth_time`/`max_age` validation, token acquisition timestamps, proactive refresh decisions, rate limit header parsing, retry delay calculation, and device code expiry tracking.

The SDK routes every time query through `ITimeCoordinator`. The default implementation observes the `Date` header returned by the authorization server on each response and offsets the system clock accordingly, converging on the server's view of time after the first request.

Consumers who need a different source (e.g. a network time service, a hardware-backed clock, or a fixed clock in tests) can register their own at app startup:

```csharp
using Okta.AuthFoundation;

OktaServices.AddSingleton<ITimeCoordinator>(new MyCustomTimeCoordinator());
```

**Multiple authorization servers:** `DefaultTimeCoordinator` is a process-wide singleton, so all `OAuth2Client` instances share the same offset. Each response's `Date` header replaces the previous offset entirely — there is no per-server isolation. When communicating with multiple authorization servers whose clocks differ, the effective adjustment at any point is whatever the last-responding server reported, not the one whose tokens are currently being validated. This is a known characteristic of the design. A custom `ITimeCoordinator` can be registered via `OktaServices.AddSingleton<ITimeCoordinator>(...)`.

## Building

### Windows

```bash
dotnet build Okta.Client.Sdk.sln
```

### Linux / macOS / WSL

Use the cross-platform solution filter, which excludes the Windows-only WPF sample:

```bash
dotnet build Okta.Client.Sdk.CrossPlatform.slnf
```

## Running Tests

```bash
dotnet test Okta.Client.Sdk.CrossPlatform.slnf
```

## License

Copyright 2026 Okta, Inc. Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for third-party attributions.

