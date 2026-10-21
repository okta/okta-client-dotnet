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

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.JsonWebTokens;
using Okta.AuthFoundation;
using Okta.AuthFoundation.JwtSecurity;
using Okta.AuthFoundation.OAuth2;
using Okta.AuthFoundation.TokenManagement;

namespace Okta.Client.Sdk.Tests
{
    /// <summary>
    /// Helper class for creating common test objects with sensible defaults
    /// </summary>
    public static class TestHelpers
    {
        // Default values
        public const string DefaultId = "id1";
        public const string DefaultScope = "scope";
        public const string DefaultClientId = "clientId";
        public const string DefaultAccessToken = "abc123";
        public const string DefaultTokenType = "Bearer";
        public const int DefaultExpiresIn = 3600;

        // Common URIs used in tests
        public static readonly Uri ExampleUri = new Uri("https://example.com");
        public static readonly Uri ExampleOpenIdConfigUri = new Uri("https://example.com/.well-known/openid-configuration");
        public static readonly Uri ExampleTokenEndpoint = new Uri("https://example.com/token");
        public static readonly Uri ExampleJwksEndpoint = new Uri("https://example.com/v1/keys");
        public static readonly Uri ExampleAuthorizationEndpoint = new Uri("https://example.com/authorize");
        public static readonly Uri ExampleEndSessionEndpoint = new Uri("https://example.com/logout");
        public static readonly Uri ExampleDeviceAuthorizationEndpoint = new Uri("https://example.com/device/authorize");

        /// <summary>
        /// Creates a test TokenContext with example values
        /// Default: issuer="https://example.com", scope=["scope"], clientId="clientId"
        /// </summary>
        public static TokenContext CreateTokenContext(Uri? issuer = null, List<string>? scope = null, string? clientId = null)
        {
            return new TokenContext(issuer ?? ExampleUri, scope ?? new List<string> { DefaultScope }, clientId ?? DefaultClientId);
        }

        /// <summary>
        /// Creates a test Token with example context and default values
        /// Default: id="test-token-id", accessToken="abc123", tokenType="Bearer", expiresIn=3600
        /// </summary>
        public static Token CreateToken(
            string? id = null,
            string? accessToken = null,
            string? refreshToken = null,
            string? tokenType = null,
            int? expiresIn = null,
            Jwt? idToken = null,
            TokenContext? context = null,
            string? deviceSecret = null)
        {
            var ctx = context ?? CreateTokenContext();
            return new Token(ctx)
            {
                Id = id ?? DefaultId,
                AccessToken = accessToken ?? DefaultAccessToken,
                RefreshToken = refreshToken,
                TokenType = tokenType ?? DefaultTokenType,
                ExpiresIn = expiresIn ?? DefaultExpiresIn,
                IdToken = idToken,
                DeviceSecret = deviceSecret,
            };
        }

        /// <summary>
        /// Creates a test TokenMetadata with a default tag entry.
        /// </summary>
        public static TokenMetadata CreateTokenMetadata(Token? token = null, Dictionary<string, string>? tags = null)
        {
            var tkn = token ?? CreateToken();
            return new TokenMetadata(tkn, tags ?? new Dictionary<string, string> { ["tag"] = "tag1" });
        }

        /// <summary>
        /// Creates a simple example Jwt for testing (not cryptographically valid)
        /// Default: subject="1234567890", name="John Doe", iat=1516239022
        /// </summary>
        public static Jwt CreateIdToken(string? subject = null, string? name = null, long? issuedAt = null)
        {
            return new Jwt(new JsonWebToken(
                header: "{\"alg\":\"RS256\"}",
                payload: $"{{\"sub\":\"{subject ?? "1234567890"}\",\"name\":\"{name ?? "John Doe"}\",\"iat\":{issuedAt ?? 1516239022}}}"));
        }

        /// <summary>
        /// Creates a Jwt with full claims for validation testing
        /// Default: issuer="https://example.com", audience="clientId", subject="user123", valid for 5 minutes
        /// </summary>
        public static Jwt CreateIdTokenWithClaims(
            string? issuer = null,
            string? audience = null,
            string? subject = null,
            DateTime? issuedAt = null,
            DateTime? expiresAt = null,
            string? nonce = null,
            string algorithm = "RS256",
            DateTime? authTime = null)
        {
            var now = issuedAt ?? DateTime.UtcNow;
            var exp = expiresAt ?? now.AddMinutes(5);
            var iss = issuer ?? ExampleUri.ToString();
            var aud = audience ?? DefaultClientId;
            var sub = subject ?? "user123";

            var header = $"{{\"alg\":\"{algorithm}\"}}";
            var payload = $"{{\"iss\":\"{iss}\",\"aud\":\"{aud}\",\"iat\":{new DateTimeOffset(now).ToUnixTimeSeconds()},\"exp\":{new DateTimeOffset(exp).ToUnixTimeSeconds()},\"sub\":\"{sub}\"";

            if (!string.IsNullOrEmpty(nonce))
            {
                payload += $",\"nonce\":\"{nonce}\"";
            }

            if (authTime.HasValue)
            {
                payload += $",\"auth_time\":{new DateTimeOffset(authTime.Value).ToUnixTimeSeconds()}";
            }

            payload += "}";

            return new Jwt(new JsonWebToken(header, payload));
        }

        /// <summary>
        /// Creates a test OAuth2ClientConfiguration with example values
        /// Default: baseUrl="https://example.com", clientId="clientId", scope=["scope"]
        /// </summary>
        public static OAuth2ClientConfiguration CreateOAuth2ClientConfiguration(Uri? baseUrl = null, Uri? discoveryUrl = null, string? clientId = null, List<string>? scope = null)
        {
            var baseUri = baseUrl ?? ExampleUri;
            return new OAuth2ClientConfiguration(
                baseUri,
                discoveryUrl ?? ExampleOpenIdConfigUri,
                clientId ?? DefaultClientId,
                scope ?? new List<string> { DefaultScope });
        }

        /// <summary>
        /// Creates a test OpenIdConfiguration with example endpoints
        /// Default: issuer="https://example.com", tokenEndpoint="/token", jwksUri="/v1/keys"
        /// </summary>
        public static OpenIdConfiguration CreateOpenIdConfiguration(Uri? issuer = null, Uri? tokenEndpoint = null, Uri? jwksUri = null, Uri? authorizationEndpoint = null, Uri? endSessionEndpoint = null, Uri? deviceAuthorizationEndpoint = null)
        {
            var config = new OpenIdConfiguration(
                issuer ?? ExampleUri,
                tokenEndpoint ?? ExampleTokenEndpoint,
                jwksUri ?? ExampleJwksEndpoint);
            config.AuthorizationEndpoint = authorizationEndpoint ?? ExampleAuthorizationEndpoint;
            config.EndSessionEndpoint = endSessionEndpoint ?? ExampleEndSessionEndpoint;
            config.DeviceAuthorizationEndpoint = deviceAuthorizationEndpoint ?? ExampleDeviceAuthorizationEndpoint;
            return config;
        }
    }

    /// <summary>
    /// Test helper class that returns a pre-configured credential
    /// </summary>
    public class TestCredentialDataSource : ICredentialDataSource
    {
        private readonly Credential _credential;
        private readonly Dictionary<string, Credential> _credentials = new();

        public event EventHandler<CredentialAddedEventArgs>? CredentialAdded;

        public TestCredentialDataSource(Credential credential)
        {
            _credential = credential;
        }

        public bool Has(Token token) => _credentials.ContainsKey(token.Id);

        public Credential For(Token token, TokenMetadata? metadata)
        {
            if (!_credentials.ContainsKey(token.Id))
            {
                _credentials[token.Id] = _credential;
                CredentialAdded?.Invoke(this, new CredentialAddedEventArgs(_credential));
            }

            return _credential;
        }

        public void Remove(Credential credential) => _credentials.Remove(credential.Id);

        public void Remove(string id) => _credentials.Remove(id);

        public void Clear() => _credentials.Clear();

        public int Size() => _credentials.Count;
    }
}
