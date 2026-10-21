# Device Authorization Code Flow Sample

Demonstrates the **Device Authorization Code** flow (RFC 8628). Designed for devices that lack a browser or have limited input — smart TVs, IoT devices, CLI tools. The device displays a code and URL; the user visits the URL on a separate device to authenticate.

## Okta Configuration

Create a **Native** application with:

- **Grant types:** Device Authorization, Refresh Token
- **Redirect URIs:** None required

## Running

```bash
dotnet run --project Samples/DeviceAuthCodeFlowSample
```

## What's Unique

- **Device flow authentication** — displays a verification URL and user code, then polls Okta until the user completes authentication on another device
- **Animated polling** — shows a spinner while waiting; press Ctrl+C to cancel
- **No browser required on the device** — authentication happens entirely on a separate machine

### Typical Walkthrough

1. Select "Authenticate (device flow)"
2. Note the verification URL and user code displayed
3. On another device, open the URL and enter the code
4. Authenticate with your Okta credentials
5. The sample detects authorization and stores the credential
