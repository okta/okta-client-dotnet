# Console Web Redirect Sample

Demonstrates **Authorization Code with PKCE** — the recommended OAuth 2.0 flow for native desktop and CLI applications. The user authenticates in their default browser and the app receives the callback via a local HTTP listener.

## Okta Configuration

Create a **Native** application with:

- **Grant types:** Authorization Code, Refresh Token
- **Redirect URI:** `http://localhost:8080/callback`

## Additional Config

Add `RedirectUri` to your `config/okta-native.json` (alongside the standard fields from the [shared setup](../README.md#configuration)):

```json
{
  "RedirectUri": "http://localhost:8080/callback"
}
```

## Running

```bash
dotnet run --project Samples/ConsoleWebRedirectSample
```

## What's Unique

Beyond the [common token operations](../README.md#common-token-operations), this sample also demonstrates:

- **Logout** — revokes the credential and clears the browser session via Okta's logout endpoint
- **Import from refresh token** — restore a session by pasting a refresh token directly
- **Credential storage management** — list all stored credentials, set/query tags, remove credentials
- **Authorize HTTP request** — demonstrates adding a Bearer token to an outgoing request

## Troubleshooting

**"Address already in use" on port 8080**
- Another process is using the port. Close it or change the redirect URI and port in both the config and Okta app settings.

**Browser opens but callback fails**
- Verify `http://localhost:8080/callback` is listed in your Okta app's redirect URIs (exact match required).
