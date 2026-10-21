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

using Okta.AuthFoundation;
using Okta.AuthFoundation.JwtSecurity;
using Okta.AuthFoundation.TokenManagement;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    public class TokenTests
    {
        [Fact]
        public void Constructor_WithContext_InitializesWithContext()
        {
            var context = TestHelpers.CreateTokenContext();
            var token = new Token(context);

            Assert.Equal(context, token.Context);
            Assert.NotEqual(default, token.IssuedAt);
        }

        [Fact]
        public void Scope_WithListValue_StoresCorrectly()
        {
            var token = TestHelpers.CreateToken();
            token.Scope = new List<string> { "openid", "profile", "email" };

            Assert.NotNull(token.Scope);
            Assert.Equal(3, token.Scope.Count);
            Assert.Contains("openid", token.Scope);
            Assert.Contains("profile", token.Scope);
            Assert.Contains("email", token.Scope);
        }

        [Fact]
        public void Scope_WhenNull_ReturnsNull()
        {
            var token = TestHelpers.CreateToken();
            token.Scope = null;

            Assert.Null(token.Scope);
        }

        [Fact]
        public void Scope_WhenEmpty_ReturnsEmptyList()
        {
            var token = TestHelpers.CreateToken();
            token.Scope = new List<string>();

            // Empty list is treated as not null, but represents no scope
            Assert.Empty(token.Scope);
        }

        [Fact]
        public void IdToken_WithValidToken_CreatesJwtProperty()
        {
            var idTokenJwt = TestHelpers.CreateIdToken(subject: "user123");
            var token = TestHelpers.CreateToken(idToken: idTokenJwt);

            Assert.NotNull(token.IdToken);
            Assert.IsType<Jwt>(token.IdToken);
        }

        [Fact]
        public void IdToken_WhenNull_ReturnsNull()
        {
            var token = TestHelpers.CreateToken(idToken: null);

            Assert.Null(token.IdToken);
        }

        [Fact]
        public void DeviceSecret_WhenSet_IsPreserved()
        {
            var token = TestHelpers.CreateToken(deviceSecret: "device-secret-123");

            Assert.Equal("device-secret-123", token.DeviceSecret);
        }

        [Fact]
        public void DeviceSecret_WhenNull_IsNull()
        {
            var token = TestHelpers.CreateToken();

            Assert.Null(token.DeviceSecret);
        }

        [Fact]
        public void ExpiresAt_CalculatesCorrectly()
        {
            var now = DateTime.UtcNow;
            var token = new Token(TestHelpers.CreateTokenContext()) { AccessToken = "x", TokenType = "Bearer", ExpiresIn = 3600, IssuedAt = now };

            var expectedExpiry = now.AddSeconds(3600);
            Assert.NotNull(token.ExpiresAt);
            Assert.InRange(token.ExpiresAt.Value, expectedExpiry.AddSeconds(-1), expectedExpiry.AddSeconds(1));
        }

        [Fact]
        public void ExpiresAt_WithoutIssuedAt_ReturnsNull()
        {
            var token = new Token(TestHelpers.CreateTokenContext()) { AccessToken = "x", TokenType = "Bearer", ExpiresIn = 3600, IssuedAt = null };

            Assert.Null(token.ExpiresAt);
        }

        [Fact]
        public void ExpiresAt_WithFreshToken()
        {
            var token = TestHelpers.CreateToken(expiresIn: 3600);

            // IssuedAt is set to now by constructor
            Assert.NotNull(token.ExpiresAt);
            Assert.True(token.ExpiresAt > DateTime.UtcNow);
        }

        [Fact]
        public void ExpiresAt_WithExpiredToken()
        {
            var token = new Token(TestHelpers.CreateTokenContext()) { AccessToken = "x", TokenType = "Bearer", ExpiresIn = 1, IssuedAt = DateTime.UtcNow.AddHours(-1) };

            Assert.NotNull(token.ExpiresAt);
            Assert.True(token.ExpiresAt < DateTime.UtcNow);
        }

        [Fact]
        public void Merge_WithNewRefreshResponse_UpdatesAccessToken()
        {
            var existingToken = TestHelpers.CreateToken(
                accessToken: "old-access-token",
                refreshToken: "refresh-token-123");

            var newResponse = TestHelpers.CreateToken(
                accessToken: "new-access-token",
                expiresIn: 7200);

            var merged = newResponse.Merge(existingToken);

            Assert.Equal("new-access-token", merged.AccessToken);
            Assert.Equal(7200, merged.ExpiresIn);
            Assert.Equal(existingToken.Id, merged.Id);
        }

        [Fact]
        public void Merge_PreservesRefreshTokenWhenNotInResponse()
        {
            var existingToken = TestHelpers.CreateToken(
                refreshToken: "existing-refresh-token");

            var newResponse = TestHelpers.CreateToken(
                accessToken: "new-access-token",
                refreshToken: null);

            var merged = newResponse.Merge(existingToken);

            Assert.Equal("existing-refresh-token", merged.RefreshToken);
        }

        [Fact]
        public void Merge_UpdatesRefreshTokenWhenProvided()
        {
            var existingToken = TestHelpers.CreateToken(
                refreshToken: "old-refresh-token");

            var newResponse = TestHelpers.CreateToken(
                accessToken: "new-access-token",
                refreshToken: "new-refresh-token");

            var merged = newResponse.Merge(existingToken);

            Assert.Equal("new-refresh-token", merged.RefreshToken);
        }

        [Fact]
        public void Merge_UpdatesScope()
        {
            var existingToken = TestHelpers.CreateToken();
            existingToken.Scope = new List<string> { "openid" };

            var newResponse = TestHelpers.CreateToken();
            newResponse.Scope = new List<string> { "openid", "profile" };

            var merged = newResponse.Merge(existingToken);

            Assert.NotNull(merged.Scope);
            Assert.Equal(2, merged.Scope.Count);
            Assert.Contains("profile", merged.Scope);
        }

        [Fact]
        public void Merge_UpdatesIdToken()
        {
            var oldIdToken = TestHelpers.CreateIdToken(subject: "old-user");
            var existingToken = TestHelpers.CreateToken(idToken: oldIdToken);

            var newIdToken = TestHelpers.CreateIdToken(subject: "new-user");
            var newResponse = TestHelpers.CreateToken(idToken: newIdToken);

            var merged = newResponse.Merge(existingToken);

            Assert.NotNull(merged.IdToken);
            Assert.NotEqual(oldIdToken.EncodedToken, merged.IdToken.EncodedToken);
        }

        [Fact]
        public void Merge_PreservesDeviceSecret()
        {
            var existingToken = TestHelpers.CreateToken(deviceSecret: "device-secret-123");

            var newResponse = TestHelpers.CreateToken();

            var merged = newResponse.Merge(existingToken);

            Assert.Equal("device-secret-123", merged.DeviceSecret);
        }

        [Fact]
        public void Merge_PreservesExistingId()
        {
            var existingToken = TestHelpers.CreateToken(id: "existing-id-123");
            var existingId = existingToken.Id;

            var newResponse = TestHelpers.CreateToken(id: "new-id-456");
            var newId = newResponse.Id;

            Assert.NotEqual(existingId, newId);

            var merged = newResponse.Merge(existingToken);

            Assert.Equal(existingId, merged.Id);
        }

        [Fact]
        public void Merge_PreservesResponseIssuedAt()
        {
            // The merged token's IssuedAt should reflect when the response was received
            // (i.e. this.IssuedAt), not when Merge was invoked.
            var responseReceivedAt = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
            var newResponse = new Token(TestHelpers.CreateTokenContext())
            {
                AccessToken = "new-access-token",
                TokenType = "Bearer",
                ExpiresIn = 3600,
                IssuedAt = responseReceivedAt,
            };
            var existingToken = TestHelpers.CreateToken(refreshToken: "existing-refresh");

            var merged = newResponse.Merge(existingToken);

            Assert.Equal(responseReceivedAt, merged.IssuedAt);
        }

        [Fact]
        public void Merge_CarriesForwardContextWhenResponseHasNone()
        {
            // Refresh responses never include token_context. Merge must carry the
            // existing credential's context forward so subsequent metadata derivation
            // retains issuer/scope/clientId.
            var existingContext = new TokenContext(
                new Uri("https://existing-issuer.example.com"),
                new List<string> { "openid", "profile" },
                "existing-client-id");
            var existingToken = TestHelpers.CreateToken(context: existingContext);

            var responseWithNoContext = new Token() // parameterless ctor — no context
            {
                AccessToken = "new-access-token",
                TokenType = "Bearer",
                ExpiresIn = 3600,
            };
            Assert.Null(responseWithNoContext.Context);

            var merged = responseWithNoContext.Merge(existingToken);

            Assert.NotNull(merged.Context);
            Assert.Equal(existingContext.Issuer, merged.Context!.Issuer);
            Assert.Equal(existingContext.ClientId, merged.Context.ClientId);
            Assert.Equal(existingContext.Scope, merged.Context.Scope);
        }

        [Fact]
        public async Task AuthorizeAsync_SetsAuthorizationHeader_WithBearerToken()
        {
            var token = TestHelpers.CreateToken(tokenType: "Bearer", accessToken: "test-access-token");
            var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/api");

            await token.AuthorizeAsync(request);

            Assert.NotNull(request.Headers.Authorization);
            Assert.Equal("Bearer", request.Headers.Authorization.Scheme);
            Assert.Equal("test-access-token", request.Headers.Authorization.Parameter);
        }

        [Fact]
        public async Task AuthorizeAsync_WithDPopTokenType_ThrowsNotSupportedException()
        {
            var token = TestHelpers.CreateToken(tokenType: "DPoP", accessToken: "test-token");
            var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/api");

            await Assert.ThrowsAsync<NotSupportedException>(() => token.AuthorizeAsync(request));
        }

        [Fact]
        public async Task AuthorizeAsync_WithCustomTokenType_SetsCorrectScheme()
        {
            var token = TestHelpers.CreateToken(tokenType: "CustomScheme", accessToken: "custom-token-value");
            var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/api");

            await token.AuthorizeAsync(request);

            Assert.Equal("CustomScheme", request.Headers.Authorization?.Scheme);
            Assert.Equal("custom-token-value", request.Headers.Authorization?.Parameter);
        }

        [Fact]
        public void RetrieveToken_AccessToken_ReturnsAccessToken()
        {
            var token = TestHelpers.CreateToken(accessToken: "my-access-token");

            var result = token.RetrieveToken(TokenKind.AccessToken);

            Assert.Equal("my-access-token", result);
        }

        [Fact]
        public void RetrieveToken_RefreshToken_ReturnsRefreshToken()
        {
            var token = TestHelpers.CreateToken(refreshToken: "my-refresh-token");

            var result = token.RetrieveToken(TokenKind.RefreshToken);

            Assert.Equal("my-refresh-token", result);
        }

        [Fact]
        public void RetrieveToken_RefreshToken_ThrowsWhenMissing()
        {
            var token = TestHelpers.CreateToken(refreshToken: null);

            Assert.Throws<InvalidOperationException>(() => token.RetrieveToken(TokenKind.RefreshToken));
        }

        [Fact]
        public void RetrieveToken_IdToken_ReturnsEncodedToken()
        {
            var idToken = TestHelpers.CreateIdToken();
            var token = TestHelpers.CreateToken(idToken: idToken);

            var result = token.RetrieveToken(TokenKind.IdToken);

            Assert.Equal(idToken.EncodedToken, result);
        }

        [Fact]
        public void RetrieveToken_IdToken_ThrowsWhenMissing()
        {
            var token = TestHelpers.CreateToken(idToken: null);

            Assert.Throws<InvalidOperationException>(() => token.RetrieveToken(TokenKind.IdToken));
        }

        [Fact]
        public void RetrieveToken_DeviceSecret_ReturnsDeviceSecret()
        {
            var token = TestHelpers.CreateToken(deviceSecret: "device-secret-abc");

            var result = token.RetrieveToken(TokenKind.DeviceSecret);

            Assert.Equal("device-secret-abc", result);
        }

        [Fact]
        public void RetrieveToken_DeviceSecret_ThrowsWhenMissing()
        {
            var token = TestHelpers.CreateToken();

            Assert.Throws<InvalidOperationException>(() => token.RetrieveToken(TokenKind.DeviceSecret));
        }
    }
}
