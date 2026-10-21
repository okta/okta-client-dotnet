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
using System.Web;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Okta.AuthFoundation.Exceptions;
using Okta.AuthFoundation.Http;
using Okta.AuthFoundation.OAuth2;
using Okta.AuthFoundation.TokenManagement;
using Okta.OAuth2;
using Okta.OAuth2.Flows;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    public class AuthorizationCodeFlowTests : IDisposable
    {
        private TestHttpMessageHandler _mockHandler;
        private HttpClient _httpClient;

        public AuthorizationCodeFlowTests()
        {
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

        [Fact]
        public void Constructor_SetsClientAndRedirectUri()
        {
            var config = TestHelpers.CreateOAuth2ClientConfiguration();
            var client = new OAuth2Client(config, _httpClient);
            var redirectUri = "http://localhost:8080/callback";

            var flow = new AuthorizationCodeFlow(client, redirectUri);

            Assert.Equal(client, flow.Client);
            Assert.Equal(redirectUri, flow.RedirectUri);
        }

        [Fact]
        public async Task StartAsync_ReturnsAuthorizationUrlWithRequiredParameters()
        {
            var config = TestHelpers.CreateOAuth2ClientConfiguration(
                clientId: "test-client-id",
                scope: new List<string> { "openid", "profile", "email" });
            var openIdConfig = TestHelpers.CreateOpenIdConfiguration();
            var oauth2Client = Substitute.For<OAuth2Client>(config, _httpClient, null, null, null);
            oauth2Client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(openIdConfig));

            var flow = new AuthorizationCodeFlow(oauth2Client, "http://localhost:8080/callback");

            var authorizeUrl = await flow.StartAsync();
            var query = HttpUtility.ParseQueryString(authorizeUrl.Query);

            Assert.StartsWith("https://example.com/authorize", authorizeUrl.ToString());
            Assert.Equal("test-client-id", query["client_id"]);
            Assert.Equal("code", query["response_type"]);
            Assert.Equal("http://localhost:8080/callback", query["redirect_uri"]);
            Assert.Contains("openid", query["scope"]);
            Assert.NotNull(query["state"]);
            Assert.NotNull(query["nonce"]);
            Assert.NotNull(query["code_challenge"]);
            Assert.Equal("S256", query["code_challenge_method"]);
            Assert.True(flow.IsAuthenticating);
        }

        [Fact]
        public async Task StartAsync_MissingAuthorizationEndpoint_ThrowsInvalidOperationException()
        {
            var openIdConfig = new OpenIdConfiguration(
                TestHelpers.ExampleUri,
                TestHelpers.ExampleTokenEndpoint,
                TestHelpers.ExampleJwksEndpoint);
            openIdConfig.AuthorizationEndpoint = null;

            var oauth2Client = Substitute.For<OAuth2Client>(
                TestHelpers.CreateOAuth2ClientConfiguration(),
                _httpClient,
                null,
                null,
                null);
            oauth2Client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(openIdConfig));

            var flow = new AuthorizationCodeFlow(oauth2Client, "http://localhost:8080/callback");

            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => flow.StartAsync());
            Assert.IsType<InvalidOperationException>(ex);
            Assert.False(flow.IsAuthenticating);
        }

        [Fact]
        public async Task StartAsync_NetworkError_ThrowsExceptionAndResetsState()
        {
            var oauth2Client = Substitute.For<OAuth2Client>(
                TestHelpers.CreateOAuth2ClientConfiguration(),
                _httpClient,
                null,
                null,
                null);
            oauth2Client.FetchOpenIdConfigurationAsync()
                .Returns(Task.FromException<OpenIdConfiguration>(new HttpRequestException("Network error")));

            var flow = new AuthorizationCodeFlow(oauth2Client, "http://localhost:8080/callback");

            var ex = await Assert.ThrowsAsync<HttpRequestException>(() => flow.StartAsync());
            Assert.False(flow.IsAuthenticating);
        }

        [Fact]
        public async Task ResumeAsync_ValidCallback_ReturnsToken()
        {
            var openIdConfig = TestHelpers.CreateOpenIdConfiguration();
            var token = TestHelpers.CreateToken(accessToken: "access-token-123");
            var apiResponse = ApiResponse<Token>.Success(token);

            var mockAuth = Substitute.For<IClientAuthentication>();
            mockAuth.Method.Returns(ClientAuthentication.None);
            var oauth2Client = Substitute.For<OAuth2Client>(
                new OAuth2ClientConfiguration(TestHelpers.ExampleUri, TestHelpers.ExampleOpenIdConfigUri, TestHelpers.DefaultClientId, authentication: mockAuth),
                _httpClient,
                null,
                null,
                null);
            oauth2Client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(openIdConfig));
            oauth2Client.ExchangeAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<CancellationToken>()).Returns(ci =>
            {
                ci.Arg<OAuth2TokenRequest>().Prepare();
                return Task.FromResult(apiResponse);
            });

            var flow = new AuthorizationCodeFlow(oauth2Client, "http://localhost:8080/callback");
            var authorizeUrl = await flow.StartAsync();
            var state = HttpUtility.ParseQueryString(authorizeUrl.Query)["state"];

            var callbackUri = $"http://localhost:8080/callback?code=auth-code-xyz&state={state}";
            var response = await flow.ResumeAsync(callbackUri);

            Assert.True(response.IsSuccess);
            Assert.Equal("access-token-123", response.Result.AccessToken);
            mockAuth.Received(1).AddAuthentication(Arg.Any<HttpRequestMessage>(), TestHelpers.DefaultClientId, Arg.Any<Dictionary<string, string>>());
        }

        [Fact]
        public async Task ResumeAsync_InvalidState_ThrowsOAuth2Exception()
        {
            var openIdConfig = TestHelpers.CreateOpenIdConfiguration();
            var oauth2Client = Substitute.For<OAuth2Client>(
                TestHelpers.CreateOAuth2ClientConfiguration(),
                _httpClient,
                null,
                null,
                null);
            oauth2Client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(openIdConfig));

            var flow = new AuthorizationCodeFlow(oauth2Client, "http://localhost:8080/callback");
            await flow.StartAsync();

            var callbackUri = "http://localhost:8080/callback?code=auth-code-xyz&state=wrong-state";

            var ex = await Assert.ThrowsAsync<OAuth2Exception>(() => flow.ResumeAsync(callbackUri));
            Assert.IsType<OAuth2Exception>(ex);
            Assert.Contains("State value parameters do not match.", ex.Message);
        }

        [Fact]
        public async Task ResumeAsync_ErrorResponse_ThrowsOAuth2Exception()
        {
            var openIdConfig = TestHelpers.CreateOpenIdConfiguration();
            var oauth2Client = Substitute.For<OAuth2Client>(
                TestHelpers.CreateOAuth2ClientConfiguration(),
                _httpClient,
                null,
                null,
                null);
            oauth2Client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(openIdConfig));

            var flow = new AuthorizationCodeFlow(oauth2Client, "http://localhost:8080/callback");
            await flow.StartAsync();

            var callbackUri = "http://localhost:8080/callback?error=access_denied&error_description=User%20denied%20access";

            var ex = await Assert.ThrowsAsync<OAuth2Exception>(() => flow.ResumeAsync(callbackUri));
            Assert.IsType<OAuth2Exception>(ex);
            Assert.Contains("access_denied", ex.Message);
        }

        [Fact]
        public async Task ResumeAsync_TokenExchangeFailure_ReturnsFailureResponse()
        {
            var openIdConfig = TestHelpers.CreateOpenIdConfiguration();
            var oauth2Client = Substitute.For<OAuth2Client>(
                TestHelpers.CreateOAuth2ClientConfiguration(),
                _httpClient,
                null,
                null,
                null);
            oauth2Client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(openIdConfig));
            oauth2Client.ExchangeAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<CancellationToken>())
                .Returns(Task.FromResult(ApiResponse<Token>.Failure("Token exchange failed", HttpStatusCode.BadRequest)));

            var flow = new AuthorizationCodeFlow(oauth2Client, "http://localhost:8080/callback");
            var authorizeUrl = await flow.StartAsync();
            var state = HttpUtility.ParseQueryString(authorizeUrl.Query)["state"];

            var callbackUri = $"http://localhost:8080/callback?code=auth-code-xyz&state={state}";
            var response = await flow.ResumeAsync(callbackUri);

            Assert.False(response.IsSuccess);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        [Fact]
        public async Task Reset_SetsIsAuthenticatingToFalse()
        {
            var openIdConfig = TestHelpers.CreateOpenIdConfiguration();
            var oauth2Client = Substitute.For<OAuth2Client>(
                TestHelpers.CreateOAuth2ClientConfiguration(),
                _httpClient,
                null,
                null,
                null);
            oauth2Client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(openIdConfig));

            var flow = new AuthorizationCodeFlow(oauth2Client, "http://localhost:8080/callback");
            await flow.StartAsync();
            Assert.True(flow.IsAuthenticating);

            flow.Reset();

            Assert.False(flow.IsAuthenticating);
        }

        [Fact]
        public async Task StartAsync_GeneratesUniqueStateAndPkcePerFlow()
        {
            var openIdConfig = TestHelpers.CreateOpenIdConfiguration();
            var oauth2Client = Substitute.For<OAuth2Client>(
                TestHelpers.CreateOAuth2ClientConfiguration(),
                _httpClient,
                null,
                null,
                null);
            oauth2Client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(openIdConfig));

            var flow1 = new AuthorizationCodeFlow(oauth2Client, "http://localhost:8080/callback");
            var flow2 = new AuthorizationCodeFlow(oauth2Client, "http://localhost:8080/callback");

            var url1 = await flow1.StartAsync();
            var url2 = await flow2.StartAsync();

            var query1 = HttpUtility.ParseQueryString(url1.Query);
            var query2 = HttpUtility.ParseQueryString(url2.Query);

            Assert.NotEqual(query1["state"], query2["state"]);
            Assert.NotEqual(query1["code_challenge"], query2["code_challenge"]);
        }

        [Fact]
        public async Task ResumeAsync_CalledBeforeStartAsync_ThrowsInvalidOperationException()
        {
            var config = TestHelpers.CreateOAuth2ClientConfiguration();
            var client = new OAuth2Client(config, _httpClient);
            var flow = new AuthorizationCodeFlow(client, "http://localhost:8080/callback");

            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                flow.ResumeAsync("http://localhost:8080/callback?code=abc&state=xyz"));
            Assert.Equal("StartAsync must be called before ResumeAsync.", ex.Message);
        }

        [Fact]
        public async Task ResumeAsync_DoesNotSendNonceToTokenEndpoint()
        {
            string? capturedBody = null;
            var capturingHandler = new TestHttpMessageHandler(async (request, ct) =>
            {
                capturedBody = await request.Content!.ReadAsStringAsync(ct);
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(@"{""access_token"":""tok"",""token_type"":""Bearer"",""expires_in"":3600}"),
                };
            });
            var capturingHttpClient = new HttpClient(capturingHandler);

            var mockAuth = Substitute.For<IClientAuthentication>();
            mockAuth.Method.Returns(ClientAuthentication.None);
            var config = new OAuth2ClientConfiguration(
                TestHelpers.ExampleUri,
                TestHelpers.ExampleOpenIdConfigUri,
                TestHelpers.DefaultClientId,
                authentication: mockAuth);
            var openIdConfig = TestHelpers.CreateOpenIdConfiguration();

            var oauth2Client = Substitute.ForPartsOf<OAuth2Client>(config, capturingHttpClient, null, null, null);
            oauth2Client.When(x => x.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>())).DoNotCallBase();
            oauth2Client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(openIdConfig));
            oauth2Client.When(x => x.JwksAsync(Arg.Any<bool>())).DoNotCallBase();
            oauth2Client.JwksAsync(Arg.Any<bool>()).Returns(Task.FromResult(new JsonWebKeySet()));
            oauth2Client.When(x => x.ValidateTokenAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<JsonWebKeySet>(), Arg.Any<Token>())).DoNotCallBase();
            oauth2Client.ValidateTokenAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<JsonWebKeySet>(), Arg.Any<Token>())
                .Returns(ci => Task.FromResult(ci.ArgAt<Token>(2)));

            var flow = new AuthorizationCodeFlow(oauth2Client, "http://localhost:8080/callback");
            var authorizeUrl = await flow.StartAsync();
            var state = HttpUtility.ParseQueryString(authorizeUrl.Query)["state"];

            await flow.ResumeAsync($"http://localhost:8080/callback?code=auth-code-xyz&state={state}");

            Assert.NotNull(capturedBody);
            Assert.DoesNotContain("nonce", capturedBody);
        }

        [Fact]
        public async Task StartAsync_IncludesAdditionalParametersInAuthorizeUrl()
        {
            var openIdConfig = TestHelpers.CreateOpenIdConfiguration();
            var oauth2Client = Substitute.For<OAuth2Client>(
                TestHelpers.CreateOAuth2ClientConfiguration(),
                _httpClient,
                null,
                null,
                null);
            oauth2Client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(openIdConfig));

            var additionalParams = new Dictionary<string, string>
            {
                ["prompt"] = "login",
                ["idp"] = "0oa1234567890abcdef",
            };
            var flow = new AuthorizationCodeFlow(oauth2Client, "http://localhost:8080/callback", additionalParams);

            var authorizeUrl = await flow.StartAsync();
            var query = HttpUtility.ParseQueryString(authorizeUrl.Query);

            Assert.Equal("login", query["prompt"]);
            Assert.Equal("0oa1234567890abcdef", query["idp"]);
        }
    }
}
