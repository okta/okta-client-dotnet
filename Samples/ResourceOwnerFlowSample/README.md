# Resource Owner Password Flow Sample

Demonstrates the **Resource Owner Password Credentials** flow. The application directly accepts a username and password and exchanges them for tokens. **This flow is legacy** — use Authorization Code with PKCE for new applications.

## Okta Configuration

Create a **Native** application with:

- **Grant types:** Resource Owner Password, Refresh Token
- **Redirect URIs:** None required

Your Okta org must permit Resource Owner Password grants (check org-level security policies).

## Running

```bash
dotnet run --project Samples/ResourceOwnerFlowSample
```

## What's Unique

- **Direct credential entry** — prompts for username and password (masked input)
- **List stored credentials** — shows all previously authenticated sessions

## When to Use

- Legacy application migration to OAuth 2.0
- Trusted first-party internal tools
- Integration testing before implementing a browser-based flow

## Security Considerations

This flow requires the application to handle the user's password directly. It cannot support MFA and offers no browser-based security boundary. Prefer:

- **Authorization Code + PKCE** ([ConsoleWebRedirectSample](../ConsoleWebRedirectSample/)) for interactive apps
- **Device Authorization** ([DeviceAuthCodeFlowSample](../DeviceAuthCodeFlowSample/)) for headless devices
