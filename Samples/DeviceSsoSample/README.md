# Device SSO / Token Exchange Sample

Demonstrates **Token Exchange** (RFC 8693) for Native SSO. An ID token and device secret from one application are exchanged for new tokens in a second application — the user authenticates once and gains access to both apps without re-entering credentials.

This is the pattern used by Okta mobile SDKs for Native SSO on iOS and Android.

## Okta Configuration

This sample requires **two applications**:

### App 1: SSO Source (ConsoleWebRedirectSample)

Create a **Native** application with:

- **Grant types:** Authorization Code, Refresh Token
- **Redirect URI:** `http://localhost:8080/callback`
- **Scopes:** Must include `device_sso`

### App 2: Token Exchange Target (this sample)

Create a **Native** application with:

- **Grant types:** Token Exchange, Refresh Token
- **Redirect URIs:** None required

### Authorization Server Policy

On your authorization server (e.g., `default`):

- Add an access policy rule allowing App 2 to use the **Token Exchange** grant type
- Ensure the `device_sso` scope is available and included in App 1's policy rule

## Additional Config

Add `Audience` to your `config/okta-native.json`:

```json
{
  "ClientId": "{app2ClientId}",
  "Audience": "api://default"
}
```

The `Audience` must match your authorization server's audience setting (usually `api://default`).

## Running

```bash
# Terminal 1: SSO source
dotnet run --project Samples/ConsoleWebRedirectSample

# Terminal 2: Token exchange target
dotnet run --project Samples/DeviceSsoSample
```

## Workflow

1. In **ConsoleWebRedirectSample**, authenticate (option 1) then select "Show current credential" (option 4). The output includes the full ID token and device secret — copy both values.
2. In **DeviceSsoSample**, select "Sign in with Native SSO" (option 1) and choose "Enter manually" (option 2). Paste the ID token and device secret when prompted.
3. The sample performs the token exchange and stores the new credential.

## Troubleshooting

**"invalid_audience"** — verify `Audience` in config matches the authorization server setting.

**"invalid_grant"** — the ID token or device secret may be expired. Re-authenticate in App 1.
