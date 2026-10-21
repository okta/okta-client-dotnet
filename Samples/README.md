# Samples

Interactive console and desktop samples demonstrating the Okta .NET SDK's OAuth 2.0 flows.

## Shared Setup

All samples require:

- .NET 8.0 SDK
- An Okta developer account ([sign up](https://developer.okta.com/signup))

### Configuration

Each sample looks for `config/okta-native.json` starting from the working directory and searching up the directory tree. A minimal config:

```json
{
  "IssuerUrl": "https://{yourOktaDomain}/oauth2/default",
  "ClientId": "{yourClientId}",
  "Scopes": ["openid", "profile", "email", "offline_access"]
}
```

Some samples require additional fields (e.g., `RedirectUri`, `Audience`) — see individual READMEs.

### Credential Storage

All samples persist tokens using platform-specific encryption:

- **Windows:** DPAPI (`tokens.encrypted.json`)
- **Linux:** AES-256-GCM with a locally-generated key

Credentials survive across sessions. On startup, samples load the default credential and welcome you by name if a valid session exists.

### Common Token Operations

After authenticating, all samples expose the same token lifecycle menu:

- **Show credential** — displays access token, expiration, scopes, and user info from the ID token
- **Show ID token claims** — decodes and lists all claims (name, email, groups, etc.)
- **Refresh token** — immediately refreshes the access token
- **Introspect token** — queries the authorization server for live token status
- **Revoke token** — permanently revokes access, refresh, or all tokens
- **Fetch user info** — calls the UserInfo endpoint for the full user profile

## Samples

| Sample | Flow | Use Case |
|--------|------|----------|
| [ConsoleWebRedirectSample](ConsoleWebRedirectSample/) | Authorization Code + PKCE | Desktop/CLI apps — the recommended default |
| [DeviceAuthCodeFlowSample](DeviceAuthCodeFlowSample/) | Device Authorization (RFC 8628) | Devices without a browser or with limited input |
| [ResourceOwnerFlowSample](ResourceOwnerFlowSample/) | Resource Owner Password | Legacy migration only |
| [DeviceSsoSample](DeviceSsoSample/) | Token Exchange (RFC 8693) | Native SSO across multiple apps |
| [WebRedirectSample](WebRedirectSample/) | Authorization Code + PKCE (WPF) | Windows desktop apps with a GUI |
