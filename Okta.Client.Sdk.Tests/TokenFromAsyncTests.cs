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

using System.Net;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Okta.AuthFoundation.Exceptions;
using Okta.AuthFoundation.OAuth2;
using Okta.AuthFoundation.TokenManagement;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    public class TokenFromAsyncTests : IDisposable
    {
        private readonly OAuth2ClientConfiguration _config;
        private readonly TestHttpMessageHandler _mockHandler;
        private readonly HttpClient _httpClient;

        public TokenFromAsyncTests()
        {
            _config = TestHelpers.CreateOAuth2ClientConfiguration();
            _mockHandler = new TestHttpMessageHandler((request, cancellationToken) =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{}"),
                }));
            _httpClient = new HttpClient(_mockHandler);
        }

        public void Dispose()
        {
            _httpClient.Dispose();
            _mockHandler.Dispose();
            GC.SuppressFinalize(this);
        }

        private OAuth2Client CreateClient()
        {
            var client = Substitute.ForPartsOf<OAuth2Client>(_config, _httpClient, null, null, null);

            client.When(x => x.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>())).DoNotCallBase();
            client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(TestHelpers.CreateOpenIdConfiguration()));

            client.When(x => x.JwksAsync(Arg.Any<bool>())).DoNotCallBase();
            client.JwksAsync(Arg.Any<bool>()).Returns(Task.FromResult(new JsonWebKeySet()));

            client.When(x => x.ValidateTokenAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<JsonWebKeySet>(), Arg.Any<Token>())).DoNotCallBase();
            client.ValidateTokenAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<JsonWebKeySet>(), Arg.Any<Token>())
                .Returns(callInfo => Task.FromResult(callInfo.ArgAt<Token>(2)));

            return client;
        }

        [Fact]
        public async Task FromAsync_ReturnsToken_OnSuccess()
        {
            var tokenJson = @"{
                ""access_token"": ""new-access-token"",
                ""token_type"": ""Bearer"",
                ""expires_in"": 3600,
                ""refresh_token"": ""new-refresh-token""
            }";

            _mockHandler.HandlerFunc = (request, cancellationToken) =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(tokenJson),
                });

            var client = CreateClient();

            var token = await Token.FromAsync("the_refresh_token", client);

            Assert.NotNull(token);
            Assert.Equal("new-access-token", token.AccessToken);
            Assert.Equal("Bearer", token.TokenType);
            Assert.Equal("new-refresh-token", token.RefreshToken);
        }

        [Fact]
        public async Task FromAsync_SendsRefreshTokenInRequest()
        {
            HttpRequestMessage? capturedRequest = null;
            string? capturedBody = null;

            _mockHandler.HandlerFunc = async (request, cancellationToken) =>
            {
                capturedRequest = request;
                capturedBody = await request.Content!.ReadAsStringAsync(cancellationToken);
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(@"{""access_token"":""tok"",""token_type"":""Bearer"",""expires_in"":3600}"),
                };
            };

            var client = CreateClient();

            await Token.FromAsync("my_refresh_token", client);

            Assert.NotNull(capturedRequest);
            Assert.Equal(HttpMethod.Post, capturedRequest.Method);
            Assert.Equal(TestHelpers.ExampleTokenEndpoint, capturedRequest.RequestUri);
            Assert.NotNull(capturedBody);
            Assert.Contains("grant_type=refresh_token", capturedBody);
            Assert.Contains("my_refresh_token", capturedBody);
        }

        [Fact]
        public async Task FromAsync_ThrowsOAuth2Exception_OnFailedResponse()
        {
            _mockHandler.HandlerFunc = (request, cancellationToken) =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent(@"{""error"":""invalid_grant"",""error_description"":""refresh token is invalid""}"),
                });

            var client = CreateClient();

            var ex = await Assert.ThrowsAsync<OAuth2Exception>(() => Token.FromAsync("expired_refresh_token", client));
            Assert.Contains("invalid_grant", ex.Message);
        }
    }
}
