# WPF Web Redirect Sample

Demonstrates **Authorization Code with PKCE** in a **WPF desktop application**. Same flow as ConsoleWebRedirectSample but with a native Windows GUI. Windows-only.

## Okta Configuration

Create a **Native** application with:

- **Grant types:** Authorization Code, Refresh Token
- **Redirect URI:** `http://localhost:8080/callback`

## Additional Config

Add `RedirectUri` to your `config/okta-native.json`:

```json
{
  "RedirectUri": "http://localhost:8080/callback"
}
```

## Running

```bash
dotnet run --project Samples/WebRedirectSample
```

## What's Unique

- **WPF GUI** — buttons for login, logout, refresh, and revoke instead of a text menu
- **Visual token display** — shows credential status and user info in the window

## Platform

Windows 10+ only (WPF). For cross-platform, use [ConsoleWebRedirectSample](../ConsoleWebRedirectSample/). The SDK libraries themselves are fully cross-platform.
