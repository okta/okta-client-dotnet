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

using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Okta.AuthFoundation;
using Okta.AuthFoundation.Claims;
using Okta.AuthFoundation.OAuth2;
using Okta.AuthFoundation.TokenManagement;
using Okta.OAuth2;
using Okta.OAuth2.Flows;

namespace Okta.Client.Sdk.Samples.DeviceSso;

public class Program
{
    private static OAuth2Client _client = null!;
    private static Credential? _currentCredential;
    private static string? _audience;

    public static async Task Main(string[] args)
    {
        var configuration = new ConfigurationBuilder()
            .AddJsonFile(FindConfigPath(), optional: false)
            .Build();

        var issuer = new Uri(configuration["IssuerUrl"]!);
        var clientId = configuration["ClientId"]!;
        var scopes = configuration.GetSection("Scopes").Get<List<string>>()
                     ?? new List<string> { "openid", "profile", "email", "offline_access" };
        _audience = configuration["Audience"];

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
            Console.WriteLine("=== Okta Token Exchange / Native SSO Sample ===");
            Console.WriteLine();
            Console.WriteLine("--- Token Exchange ---");
            Console.WriteLine(" 1. Sign in with Native SSO (device secret)");
            Console.WriteLine();
            Console.WriteLine("--- Token Info ---");
            Console.WriteLine(" 2. Show current credential");
            Console.WriteLine(" 3. Show ID token claims");
            Console.WriteLine();
            Console.WriteLine("--- Token Lifecycle ---");
            Console.WriteLine(" 4. Refresh token");
            Console.WriteLine(" 5. Introspect token");
            Console.WriteLine(" 6. Revoke token");
            Console.WriteLine();
            Console.WriteLine("--- User Info ---");
            Console.WriteLine(" 7. Fetch user info");
            Console.WriteLine();
            Console.WriteLine("--- Exit ---");
            Console.WriteLine(" 0. Exit");
            Console.WriteLine();
            Console.Write("Choose an option: ");

            switch (Console.ReadLine()?.Trim())
            {
                case "1": await TokenExchangeAsync(); break;
                case "2": await ShowCredentialAsync(); break;
                case "3": await ShowIdTokenClaimsAsync(); break;
                case "4": await RefreshTokenAsync(); break;
                case "5": await IntrospectTokenAsync(); break;
                case "6": await RevokeTokenAsync(); break;
                case "7": await FetchUserInfoAsync(); break;
                case "0": return;
                default: Console.WriteLine("Invalid option."); break;
            }
        }
    }

    private static async Task TokenExchangeAsync()
    {
        string idToken;
        string deviceSecret;

        var sharedFilePath = Path.Combine(Path.GetTempPath(), "okta-native-sso.json");

        Console.WriteLine("Token Exchange Options:");
        Console.WriteLine("  1. Read from shared file (" + sharedFilePath + ")");
        Console.WriteLine("  2. Enter manually");
        Console.Write("Choose: ");

        if (Console.ReadLine()?.Trim() == "1")
        {
            if (!File.Exists(sharedFilePath))
            {
                Console.WriteLine($"Shared file not found at {sharedFilePath}");
                Console.WriteLine("Use option 2 to enter the ID token and device secret manually.");
                Console.WriteLine("(Run ConsoleWebRedirectSample, authenticate, then use 'Show current credential' to view them.)");
                return;
            }

            try
            {
                var json = File.ReadAllText(sharedFilePath);
                var doc = JsonDocument.Parse(json);
                idToken = doc.RootElement.GetProperty("IdToken").GetString() ?? string.Empty;
                deviceSecret = doc.RootElement.GetProperty("DeviceSecret").GetString() ?? string.Empty;

                if (string.IsNullOrEmpty(idToken) || string.IsNullOrEmpty(deviceSecret))
                {
                    Console.WriteLine("Invalid shared file: missing IdToken or DeviceSecret.");
                    return;
                }

                Console.WriteLine("Successfully read tokens from shared file.\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to read shared file: {ex.Message}");
                return;
            }
        }
        else
        {
            Console.Write("ID token: ");
            idToken = Console.ReadLine()?.Trim() ?? string.Empty;
            Console.Write("Device secret: ");
            deviceSecret = Console.ReadLine()?.Trim() ?? string.Empty;

            if (string.IsNullOrEmpty(idToken) || string.IsNullOrEmpty(deviceSecret))
            {
                Console.WriteLine("ID token and device secret are required.");
                return;
            }
        }

        try
        {
            Console.WriteLine("Performing token exchange...");
            var flow = new TokenExchangeFlow(_client);
            var response = await flow.StartAsync(
                TokenExchangeToken.Subject(TokenKind.IdToken, idToken),
                TokenExchangeToken.Actor(TokenKind.DeviceSecret, deviceSecret),
                audience: _audience);

            if (response.IsSuccess && response.Result != null)
            {
                _currentCredential = await Credential.StoreAsync(response.Result);
                Console.WriteLine("Token exchange successful! Credential stored.\n");
                DisplayCredential(_currentCredential);
            }
            else
            {
                Console.WriteLine($"Token exchange failed: {response.ErrorMessage}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    private static Task ShowCredentialAsync()
    {
        if (_currentCredential == null)
        {
            Console.WriteLine("No credential available. Please perform token exchange first.");
            return Task.CompletedTask;
        }

        DisplayCredential(_currentCredential);
        return Task.CompletedTask;
    }

    private static Task ShowIdTokenClaimsAsync()
    {
        if (_currentCredential == null)
        {
            Console.WriteLine("No credential available. Please perform token exchange first.");
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

    private static async Task RefreshTokenAsync()
    {
        if (_currentCredential == null)
        {
            Console.WriteLine("No credential available. Please perform token exchange first.");
            return;
        }

        try
        {
            var oldAccessToken = _currentCredential.Token.AccessToken;
            Console.WriteLine("Refreshing token...");
            await _currentCredential.RefreshAsync();
            Console.WriteLine("Token refreshed.");
            Console.WriteLine($"  Old access token: {TruncateToken(oldAccessToken)}");
            Console.WriteLine($"  New access token: {TruncateToken(_currentCredential.Token.AccessToken)}");
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
            Console.WriteLine("No credential available. Please perform token exchange first.");
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
            Console.WriteLine("No credential available. Please perform token exchange first.");
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

    private static async Task FetchUserInfoAsync()
    {
        if (_currentCredential == null)
        {
            Console.WriteLine("No credential available. Please perform token exchange first.");
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

            Console.WriteLine($"  Subject: {token.IdToken.Subject()}");
        }

        Console.WriteLine("=== Credential Information ===");
        Console.WriteLine($"  Credential ID: {credential.Id}");
        Console.WriteLine($"  Token Type:    {token.TokenType}");
        Console.WriteLine($"  Access Token:  {TruncateToken(token.AccessToken)}");
        Console.WriteLine($"  Expires In:    {token.ExpiresIn}s");
        Console.WriteLine($"  Expires At:    {token.ExpiresAt}");
        if (!string.IsNullOrEmpty(token.RefreshToken))
        {
            Console.WriteLine($"  Refresh Token: {TruncateToken(token.RefreshToken)}");
        }

        if (!string.IsNullOrEmpty(token.DeviceSecret))
        {
            Console.WriteLine($"  Device Secret: {TruncateToken(token.DeviceSecret)}");
        }

        if (token.Scope != null)
        {
            Console.WriteLine($"  Scopes:        {string.Join(" ", token.Scope)}");
        }
    }

    private static string TruncateToken(string token)
    {
        if (string.IsNullOrEmpty(token) || token.Length <= 20)
        {
            return token;
        }

        return $"{token[..10]}...{token[^10..]}";
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
