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
using Okta.AuthFoundation.Claims;
using Okta.AuthFoundation.TokenManagement;
using Xunit;

namespace Okta.Client.Sdk.Tests.Integration
{
    [Trait("Category", "Integration")]
    public class TokenLifecycleIntegrationTests : IntegrationTestBase
    {
        [IntegrationFact]
        public async Task ObtainToken_ViaResourceOwnerFlow()
        {
            var token = await ObtainTokenAsync();

            Assert.NotNull(token);
            Assert.False(string.IsNullOrEmpty(token.AccessToken));
            Assert.Equal("Bearer", token.TokenType);
            Assert.True(token.ExpiresIn > 0);
            Assert.NotNull(token.IdToken);
        }

        [IntegrationFact]
        public async Task RefreshAsync_ReturnsNewToken()
        {
            var token = await ObtainTokenAsync();
            Assert.False(string.IsNullOrEmpty(token.RefreshToken), "Token must include a refresh token (ensure offline_access scope).");

            var originalId = token.Id;
            var originalAccessToken = token.AccessToken;

            var response = await Client.RefreshAsync(token, Scopes);

            Assert.True(response.IsSuccess);
            Assert.NotNull(response.Result);
            Assert.Equal(originalId, response.Result.Id);
            Assert.NotEqual(originalAccessToken, response.Result.AccessToken);
        }

        [IntegrationFact]
        public async Task IntrospectAsync_ActiveToken()
        {
            var token = await ObtainTokenAsync();

            var response = await Client.IntrospectAsync(token, TokenKind.AccessToken);

            Assert.True(response.IsSuccess);
            Assert.NotNull(response.Result);
            Assert.True(response.Result.Active);
            Assert.False(string.IsNullOrEmpty(response.Result.Sub));
        }

        [IntegrationFact]
        public async Task UserInfoAsync_ReturnsProfile()
        {
            var token = await ObtainTokenAsync();

            var response = await Client.UserInfoAsync(token);

            Assert.True(response.IsSuccess);
            Assert.NotNull(response.Result);
            Assert.False(string.IsNullOrEmpty(response.Result.Subject()));
        }

        [IntegrationFact]
        public async Task RevokeAsync_AccessToken_ThenIntrospectShowsInactive()
        {
            var token = await ObtainTokenAsync();

            await Client.RevokeAsync(token, TokenRevokeType.Access);

            var introspectResponse = await Client.IntrospectAsync(token, TokenKind.AccessToken);
            Assert.True(introspectResponse.IsSuccess);
            Assert.NotNull(introspectResponse.Result);
            Assert.False(introspectResponse.Result.Active);
        }

        [IntegrationFact]
        public async Task RevokeAsync_RefreshToken_ThenRefreshFails()
        {
            var token = await ObtainTokenAsync();
            Assert.False(string.IsNullOrEmpty(token.RefreshToken), "Token must include a refresh token.");

            await Client.RevokeAsync(token, TokenRevokeType.Refresh);

            var refreshResponse = await Client.RefreshAsync(token, Scopes);
            Assert.False(refreshResponse.IsSuccess);
        }

        [IntegrationFact]
        public async Task TokenFromAsync_ImportsFromRefreshToken()
        {
            var token = await ObtainTokenAsync();
            Assert.False(string.IsNullOrEmpty(token.RefreshToken), "Token must include a refresh token.");

            var imported = await Token.FromAsync(token.RefreshToken, Client);

            Assert.NotNull(imported);
            Assert.False(string.IsNullOrEmpty(imported.AccessToken));
            Assert.NotEqual(token.AccessToken, imported.AccessToken);
        }

        [IntegrationFact]
        public async Task RefreshIfNeededAsync_SkipsWhenFresh()
        {
            var token = await ObtainTokenAsync();
            var credential = new Credential(token, Client, new TokenMetadata(token));
            var originalAccessToken = credential.Token.AccessToken;

            await credential.RefreshIfNeededAsync(gracePeriod: 30);

            Assert.Equal(originalAccessToken, credential.Token.AccessToken);
        }
    }
}
