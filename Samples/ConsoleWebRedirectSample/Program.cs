// Copyright 2026 Okta, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Configuration;
using Okta.AuthFoundation;
using Okta.AuthFoundation.Claims;
using Okta.AuthFoundation.OAuth2;
using Okta.AuthFoundation.TokenManagement;
using Okta.OAuth2;
using Okta.OAuth2.Flows;

namespace Okta.Client.Sdk.Samples.ConsoleWebRedirect;

public class Program
{
    private static OAuth2Client _client = null!;
    private static Credential? _currentCredential;
    private static string _redirectUri = null!;

    public static async Task Main(string[] args)
    {
        var configuration = new ConfigurationBuilder()
            .AddJsonFile(FindConfigPath(), optional: false)
            .Build();

        var issuer = new Uri(configuration["IssuerUrl"]!);
        var clientId = configuration["ClientId"]!;
        _redirectUri = configuration["RedirectUri"]
            ?? throw new InvalidOperationException("RedirectUri is required in config/okta-native.json");
        var scopes = configuration.GetSection("Scopes").Get<List<string>>()
                     ?? new List<string> { "openid", "profile", "email", "offline_access" };

        var clientConfig = new OAuth2ClientConfiguration(issuer, clientId, scopes);
        _client = new OAuth2Client(clientConfig);

        _currentCredential = await Credential.GetDefaultAsync();
        if (_currentCredential != null)
        {
            var expired = _currentCredential.Token.ExpiresAt < DateTime.UtcNow;
            if (!expired)
            {
                var name = _currentCredential.Token.IdToken?.Name();
                Console.WriteLine($"Welcome back, {name ?? _currentCredential.Id}!");
            }
        }

        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("=== Okta SDK Console Sample ===");
            Console.WriteLine();
            Console.WriteLine("--- Authentication ---");
            Console.WriteLine(" 1. Login (Authorization Code + PKCE)");
            Console.WriteLine(" 2. Logout (Session Logout)");
            Console.WriteLine(" 3. Import from refresh token");
            Console.WriteLine();
            Console.WriteLine("--- Token Info ---");
            Console.WriteLine(" 4. Show current credential");
            Console.WriteLine(" 5. Show ID token claims");
            Console.WriteLine();
            Console.WriteLine("--- Token Lifecycle ---");
            Console.WriteLine(" 6. Refresh token");
            Console.WriteLine(" 7. Introspect token");
            Console.WriteLine(" 8. Revoke token");
            Console.WriteLine();
            Console.WriteLine("--- User Info ---");
            Console.WriteLine(" 9. Fetch user info");
            Console.WriteLine();
            Console.WriteLine("--- Credential Storage ---");
            Console.WriteLine("10. List all credentials");
            Console.WriteLine("11. Set tags on credential");
            Console.WriteLine("12. Find credential by tag");
            Console.WriteLine("13. Remove current credential");
            Console.WriteLine("14. Clear all credentials");
            Console.WriteLine();
            Console.WriteLine("--- Utilities ---");
            Console.WriteLine("15. Authorize a sample HTTP request");
            Console.WriteLine(" 0. Exit");
            Console.WriteLine();
            Console.Write("Choose an option: ");

            switch (Console.ReadLine()?.Trim())
            {
                case "1": await LoginAsync(); break;
                case "2": await LogoutAsync(); break;
                case "3": await ImportFromRefreshTokenAsync(); break;
                case "4": await ShowCredentialAsync(); break;
                case "5": await ShowIdTokenClaimsAsync(); break;
                case "6": await RefreshTokenAsync(); break;
                case "7": await IntrospectTokenAsync(); break;
                case "8": await RevokeTokenAsync(); break;
                case "9": await FetchUserInfoAsync(); break;
                case "10": await ListAllCredentialsAsync(); break;
                case "11": await SetTagsAsync(); break;
                case "12": await FindByTagAsync(); break;
                case "13": await RemoveCredentialAsync(); break;
                case "14": await ClearAllCredentialsAsync(); break;
                case "15": await AuthorizeRequestAsync(); break;
                case "0": return;
                default: Console.WriteLine("Invalid option."); break;
            }
        }
    }

    // --- Authentication ---
    private static async Task LoginAsync()
    {
        var authFlow = new AuthorizationCodeFlow(_client, _redirectUri);

        try
        {
            Console.WriteLine("Starting authorization flow...");
            var authorizeUrl = await authFlow.StartAsync();

            Console.WriteLine($"Authorization URL:\n{authorizeUrl}\n");

            var redirectUriParsed = new Uri(_redirectUri);
            var listenerPrefix = $"{redirectUriParsed.Scheme}://{redirectUriParsed.Host}:{redirectUriParsed.Port}/";

            using var listener = new HttpListener();
            listener.Prefixes.Add(listenerPrefix);
            listener.Start();
            Console.WriteLine($"Listening on {listenerPrefix}...");

            OpenBrowser(authorizeUrl.ToString());
            Console.WriteLine("Waiting for callback...\n");

            var context = await listener.GetContextAsync();
            var callbackUri = context.Request.Url?.ToString();

            await SendBrowserResponse(context, "Authentication Complete", "You can close this window.");
            listener.Stop();

            if (callbackUri == null)
            {
                Console.WriteLine("No callback received.");
                return;
            }

            Console.WriteLine($"Callback received: {callbackUri}\n");
            Console.WriteLine("Exchanging authorization code for tokens...");

            var response = await authFlow.ResumeAsync(callbackUri);

            if (response.IsSuccess && response.Result != null)
            {
                _currentCredential = await Credential.StoreAsync(response.Result);
                Console.WriteLine($"Authentication successful! Credential stored with ID: {_currentCredential.Id}\n");
                DisplayCredential(_currentCredential);
            }
            else
            {
                Console.WriteLine($"Authentication failed: {response.ErrorMessage}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    private static async Task LogoutAsync()
    {
        if (_currentCredential == null)
        {
            Console.WriteLine("No credential available. Please authenticate first.");
            return;
        }

        if (_currentCredential.Token.IdToken is null)
        {
            Console.WriteLine("No ID token available for session logout.");
            return;
        }

        try
        {
            var logoutRedirectUri = new Uri(_redirectUri);
            var logoutFlow = new SessionLogoutFlow(_client, logoutRedirectUri);
            var state = Crypto.GenerateRandomString();
            var context = new SessionLogoutFlowContext(_currentCredential.Token.IdToken.EncodedToken, state);

            var logoutUrl = await logoutFlow.StartAsync(context);
            Console.WriteLine($"Logout URL:\n{logoutUrl}\n");

            using var listener = new HttpListener();
            var listenerPrefix = $"{logoutRedirectUri.Scheme}://{logoutRedirectUri.Host}:{logoutRedirectUri.Port}/";
            listener.Prefixes.Add(listenerPrefix);
            listener.Start();

            OpenBrowser(logoutUrl.ToString());
            Console.WriteLine("Waiting for logout callback...\n");

            var httpContext = await listener.GetContextAsync();
            await SendBrowserResponse(httpContext, "Logout Complete", "You can close this window.");
            listener.Stop();

            await _currentCredential.RemoveAsync();
            _currentCredential = null;
            Console.WriteLine("Logout successful. Credential removed.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Logout error: {ex.Message}");
        }
    }

    private static async Task ImportFromRefreshTokenAsync()
    {
        Console.Write("Enter a refresh token: ");
        var refreshToken = Console.ReadLine()?.Trim();

        if (string.IsNullOrEmpty(refreshToken))
        {
            Console.WriteLine("No refresh token provided.");
            return;
        }

        try
        {
            Console.WriteLine("Importing credential from refresh token...");
            var token = await Token.FromAsync(refreshToken, _client);
            _currentCredential = await Credential.StoreAsync(token);
            Console.WriteLine($"Import successful! Credential stored with ID: {_currentCredential.Id}\n");
            DisplayCredential(_currentCredential);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Import failed: {ex.Message}");
        }
    }

    // --- Token Info ---
    private static Task ShowCredentialAsync()
    {
        if (_currentCredential == null)
        {
            Console.WriteLine("No credential available. Please authenticate first.");
            return Task.CompletedTask;
        }

        DisplayCredential(_currentCredential);
        return Task.CompletedTask;
    }

    private static Task ShowIdTokenClaimsAsync()
    {
        if (_currentCredential == null)
        {
            Console.WriteLine("No credential available. Please authenticate first.");
            return Task.CompletedTask;
        }

        if (_currentCredential.Token.IdToken is null)
        {
            Console.WriteLine("No ID token present.");
            return Task.CompletedTask;
        }

        Console.WriteLine("=== ID Token Claims ===");
        foreach (var (key, value) in _currentCredential.Token.IdToken.Payload)
        {
            Console.WriteLine($"  {key}: {value}");
        }

        return Task.CompletedTask;
    }

    // --- Token Lifecycle ---
    private static async Task RefreshTokenAsync()
    {
        if (_currentCredential == null)
        {
            Console.WriteLine("No credential available. Please authenticate first.");
            return;
        }

        try
        {
            var oldAccessToken = _currentCredential.Token.AccessToken;
            Console.WriteLine("Refreshing token...");
            await _currentCredential.RefreshAsync();
            Console.WriteLine("Token refreshed.");
            Console.WriteLine($"  Old access token: {oldAccessToken}");
            Console.WriteLine($"  New access token: {_currentCredential.Token.AccessToken}");
            Console.WriteLine($"  Expires at:       {_currentCredential.Token.ExpiresAt}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Refresh failed: {ex.Message}");
        }
    }

    private static async Task IntrospectTokenAsync()
    {
        if (_currentCredential == null)
        {
            Console.WriteLine("No credential available. Please authenticate first.");
            return;
        }

        try
        {
            Console.WriteLine("Introspecting token...");
            var result = await _currentCredential.IntrospectAsync();
            Console.WriteLine("=== Introspection Result ===");
            Console.WriteLine($"  Active:    {result.Active}");
            Console.WriteLine($"  Scope:     {result.Scope}");
            Console.WriteLine($"  Client ID: {result.ClientId}");
            Console.WriteLine($"  Username:  {result.Username}");
            Console.WriteLine($"  Token Type:{result.TokenType}");
            Console.WriteLine($"  Subject:   {result.Sub}");
            if (result.Exp.HasValue)
            {
                Console.WriteLine($"  Expires:   {DateTimeOffset.FromUnixTimeSeconds(result.Exp.Value).LocalDateTime}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Introspect failed: {ex.Message}");
        }
    }

    private static async Task RevokeTokenAsync()
    {
        if (_currentCredential == null)
        {
            Console.WriteLine("No credential available. Please authenticate first.");
            return;
        }

        Console.WriteLine("Revoke type:");
        Console.WriteLine("  1. Access token only");
        Console.WriteLine("  2. Refresh token only");
        Console.WriteLine("  3. All tokens");
        Console.Write("Choose: ");

        var type = Console.ReadLine()?.Trim() switch
        {
            "1" => TokenRevokeType.Access,
            "2" => TokenRevokeType.Refresh,
            "3" => TokenRevokeType.All,
            _ => (TokenRevokeType?)null,
        };

        if (type == null)
        {
            Console.WriteLine("Invalid choice.");
            return;
        }

        try
        {
            Console.WriteLine($"Revoking {type}...");
            await _currentCredential.RevokeAsync(type.Value);
            Console.WriteLine("Revocation successful.");
            if (type == TokenRevokeType.All)
            {
                await _currentCredential.RemoveAsync();
                _currentCredential = null;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Revoke failed: {ex.Message}");
        }
    }

    // --- User Info ---
    private static async Task FetchUserInfoAsync()
    {
        if (_currentCredential == null)
        {
            Console.WriteLine("No credential available. Please authenticate first.");
            return;
        }

        try
        {
            Console.WriteLine("Fetching user info...");
            var userInfo = await _currentCredential.UserInfoAsync();
            Console.WriteLine("=== User Info ===");
            Console.WriteLine($"  Subject:            {userInfo.Subject()}");
            Console.WriteLine($"  Name:               {userInfo.Name()}");
            Console.WriteLine($"  Email:              {userInfo.Email()}");
            Console.WriteLine($"  Email Verified:     {userInfo.EmailVerified()}");
            Console.WriteLine($"  Preferred Username: {userInfo.PreferredUsername()}");
            Console.WriteLine($"  Given Name:         {userInfo.GivenName()}");
            Console.WriteLine($"  Family Name:        {userInfo.FamilyName()}");
            Console.WriteLine($"  Locale:             {userInfo.Locale()}");
            Console.WriteLine($"  Zone Info:          {userInfo.ZoneInfo()}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"User info failed: {ex.Message}");
        }
    }

    // --- Credential Storage ---
    private static async Task ListAllCredentialsAsync()
    {
        try
        {
            var ids = await Credential.AllIDsAsync();
            var defaultCredential = await Credential.GetDefaultAsync();
            Console.WriteLine($"=== All Credentials ({ids.Count}) ===");
            foreach (var id in ids)
            {
                var marker = (defaultCredential?.Id == id) ? " (default)" : string.Empty;
                Console.WriteLine($"  {id}{marker}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    private static async Task SetTagsAsync()
    {
        if (_currentCredential == null)
        {
            Console.WriteLine("No credential available. Please authenticate first.");
            return;
        }

        var tags = new Dictionary<string, string>();
        Console.WriteLine("Enter tags (empty key to finish):");
        while (true)
        {
            Console.Write("  Key: ");
            var key = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(key))
            {
                break;
            }

            Console.Write("  Value: ");
            var value = Console.ReadLine()?.Trim() ?? string.Empty;
            tags[key] = value;
        }

        if (tags.Count == 0)
        {
            Console.WriteLine("No tags provided.");
            return;
        }

        try
        {
            await _currentCredential.SetTagsAsync(tags);
            Console.WriteLine($"Tags set: {string.Join(", ", tags.Select(t => $"{t.Key}={t.Value}"))}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    private static async Task FindByTagAsync()
    {
        Console.Write("Tag key: ");
        var key = Console.ReadLine()?.Trim();
        Console.Write("Tag value: ");
        var value = Console.ReadLine()?.Trim();

        if (string.IsNullOrEmpty(key))
        {
            Console.WriteLine("Key is required.");
            return;
        }

        try
        {
            var results = await Credential.FindAsync(m =>
                m.Tags != null && m.Tags.TryGetValue(key, out var v) && v == value);
            Console.WriteLine($"Found {results.Count} credential(s):");
            foreach (var c in results)
            {
                Console.WriteLine($"  ID: {c.Id}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    private static async Task RemoveCredentialAsync()
    {
        if (_currentCredential == null)
        {
            Console.WriteLine("No credential available. Please authenticate first.");
            return;
        }

        try
        {
            var id = _currentCredential.Id;
            await _currentCredential.RemoveAsync();
            _currentCredential = null;
            Console.WriteLine($"Credential {id} removed from storage.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    private static async Task ClearAllCredentialsAsync()
    {
        Console.Write("Are you sure you want to clear ALL credentials? (y/N): ");
        if (Console.ReadLine()?.Trim().ToLowerInvariant() != "y")
        {
            Console.WriteLine("Cancelled.");
            return;
        }

        try
        {
            await Credential.ClearAsync();
            _currentCredential = null;
            Console.WriteLine("All credentials cleared.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    // --- Utilities ---
    private static async Task AuthorizeRequestAsync()
    {
        if (_currentCredential == null)
        {
            Console.WriteLine("No credential available. Please authenticate first.");
            return;
        }

        try
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/resource");
            await _currentCredential.AuthorizeAsync(request);
            Console.WriteLine("=== Authorized HTTP Request ===");
            Console.WriteLine($"  Method: {request.Method}");
            Console.WriteLine($"  URL:    {request.RequestUri}");
            Console.WriteLine($"  Authorization: {request.Headers.Authorization}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    // --- Helpers ---
    private static void DisplayCredential(Credential credential)
    {
        var token = credential.Token;

        if (token.IdToken is not null)
        {
            var name = token.IdToken.Name();
            var email = token.IdToken.Email();

            Console.WriteLine("=== User Information ===");
            if (!string.IsNullOrEmpty(name))
            {
                Console.WriteLine($"  Name:    {name}");
            }

            if (!string.IsNullOrEmpty(email))
            {
                Console.WriteLine($"  Email:   {email}");
            }

            Console.WriteLine($"  Subject:  {token.IdToken.Subject()}");
            Console.WriteLine($"  ID Token: {token.IdToken.EncodedToken}");
        }

        Console.WriteLine("=== Credential Information ===");
        Console.WriteLine($"  Credential ID: {credential.Id}");
        Console.WriteLine($"  Token Type:    {token.TokenType}");
        Console.WriteLine($"  Access Token:  {token.AccessToken}");
        Console.WriteLine($"  Expires In:    {token.ExpiresIn}s");
        Console.WriteLine($"  Expires At:    {token.ExpiresAt}");
        if (!string.IsNullOrEmpty(token.RefreshToken))
        {
            Console.WriteLine($"  Refresh Token: {token.RefreshToken}");
        }

        if (!string.IsNullOrEmpty(token.DeviceSecret))
        {
            Console.WriteLine($"  Device Secret: {token.DeviceSecret}");
        }

        if (token.Scope != null)
        {
            Console.WriteLine($"  Scopes:        {string.Join(" ", token.Scope)}");
        }

        if (credential.Tags != null && credential.Tags.Count > 0)
        {
            Console.WriteLine($"  Tags:          {string.Join(", ", credential.Tags.Select(t => $"{t.Key}={t.Value}"))}");
        }
    }

    private static void OpenBrowser(string url)
    {
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                Process.Start("open", url);
            }
            else
            {
                Process.Start("xdg-open", url);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Could not open browser automatically: {ex.Message}");
            Console.WriteLine($"Please open the following URL manually:\n{url}");
        }
    }

    private static async Task SendBrowserResponse(HttpListenerContext context, string title, string message)
    {
        var html = $@"
<!DOCTYPE html>
<html>
<head><title>{title}</title>
<style>
    body {{ font-family: sans-serif; display: flex; justify-content: center; align-items: center;
           height: 100vh; margin: 0; background: linear-gradient(135deg, #667eea, #764ba2); }}
    .box {{ background: white; padding: 40px 60px; border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2); text-align: center; }}
    h1 {{ color: #28a745; }}
</style></head>
<body><div class='box'><h1>{title}</h1><p>{message}</p></div></body>
</html>";

        var buffer = Encoding.UTF8.GetBytes(html);
        context.Response.ContentType = "text/html";
        context.Response.ContentLength64 = buffer.Length;
        await context.Response.OutputStream.WriteAsync(buffer);
        context.Response.Close();
    }

    private static string FindConfigPath()
    {
        var dir = new DirectoryInfo(Directory.GetCurrentDirectory());
        while (dir != null)
        {
            var configPath = Path.Combine(dir.FullName, "config", "okta-native.json");
            if (File.Exists(configPath))
            {
                return configPath;
            }

            dir = dir.Parent;
        }

        throw new FileNotFoundException("Could not find config/okta-native.json in any parent directory.");
    }
}
