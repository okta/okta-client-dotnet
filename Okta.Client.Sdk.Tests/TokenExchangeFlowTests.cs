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
    public class TokenExchangeFlowTests : IDisposable
    {
        private readonly TestHttpMessageHandler _mockHandler;
        private readonly HttpClient _httpClient;

        public TokenExchangeFlowTests()
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

        private OAuth2Client CreateMockClient(OpenIdConfiguration? openIdConfig = null)
        {
            var client = Substitute.For<OAuth2Client>(
                TestHelpers.CreateOAuth2ClientConfiguration(),
                _httpClient,
                null,
                null,
                null);
            client.FetchOpenIdConfigurationAsync()
                .Returns(Task.FromResult(openIdConfig ?? TestHelpers.CreateOpenIdConfiguration()));
            return client;
        }

        [Fact]
        public async Task StartAsync_WithSubjectAndActor_ReturnsToken()
        {
            var token = TestHelpers.CreateToken(accessToken: "exchanged-token");
            var client = CreateMockClient();
            client.ExchangeAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<CancellationToken>())
                .Returns(Task.FromResult(ApiResponse<Token>.Success(token)));

            var flow = new TokenExchangeFlow(client);
            var result = await flow.StartAsync(
                TokenExchangeToken.Subject(TokenKind.IdToken, "id-token-value"),
                TokenExchangeToken.Actor(TokenKind.DeviceSecret, "device-secret-value"));

            Assert.True(result.IsSuccess);
            Assert.Equal("exchanged-token", result.Result!.AccessToken);
            Assert.False(flow.IsAuthenticating);
        }

        [Fact]
        public async Task StartAsync_SubjectOnly_ReturnsToken()
        {
            var token = TestHelpers.CreateToken(accessToken: "exchanged-token");
            var client = CreateMockClient();
            client.ExchangeAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<CancellationToken>())
                .Returns(Task.FromResult(ApiResponse<Token>.Success(token)));

            var flow = new TokenExchangeFlow(client);
            var result = await flow.StartAsync(TokenExchangeToken.Subject(TokenKind.AccessToken, "access-token-value"));

            Assert.True(result.IsSuccess);
        }

        [Fact]
        public async Task StartAsync_NullSubjectToken_ThrowsArgumentNullException()
        {
            var client = CreateMockClient();
            var flow = new TokenExchangeFlow(client);

            await Assert.ThrowsAsync<ArgumentNullException>(() => flow.StartAsync(null!));
            Assert.False(flow.IsAuthenticating);
        }

        [Fact]
        public async Task StartAsync_ServerError_ReturnsFailureResponse()
        {
            var client = CreateMockClient();
            client.ExchangeAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<CancellationToken>())
                .Returns(Task.FromResult(ApiResponse<Token>.Failure("invalid_grant", HttpStatusCode.BadRequest)));

            var flow = new TokenExchangeFlow(client);
            var result = await flow.StartAsync(TokenExchangeToken.Subject(TokenKind.IdToken, "id-token-value"));

            Assert.False(result.IsSuccess);
            Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
            Assert.False(flow.IsAuthenticating);
        }

        [Fact]
        public async Task StartAsync_NetworkError_ThrowsAndResetsState()
        {
            var client = CreateMockClient();
            client.ExchangeAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<CancellationToken>())
                .Returns(Task.FromException<ApiResponse<Token>>(new HttpRequestException("Network error")));

            var flow = new TokenExchangeFlow(client);

            await Assert.ThrowsAsync<HttpRequestException>(() =>
                flow.StartAsync(TokenExchangeToken.Subject(TokenKind.IdToken, "id-token-value")));
            Assert.False(flow.IsAuthenticating);
        }

        [Fact]
        public async Task StartAsync_ThrowsFlowException_WhenAlreadyInProgress()
        {
            var requestStarted = new TaskCompletionSource<bool>();
            var requestComplete = new TaskCompletionSource<bool>();

            var client = CreateMockClient();
            client.ExchangeAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<CancellationToken>())
                .Returns(async _ =>
                {
                    requestStarted.SetResult(true);
                    await requestComplete.Task;
                    return ApiResponse<Token>.Success(TestHelpers.CreateToken());
                });

            var flow = new TokenExchangeFlow(client);
            var task1 = flow.StartAsync(TokenExchangeToken.Subject(TokenKind.IdToken, "id-token-value"));
            await requestStarted.Task;

            var ex = await Assert.ThrowsAsync<FlowException>(() =>
                flow.StartAsync(TokenExchangeToken.Subject(TokenKind.IdToken, "id-token-value")));
            Assert.Equal("Flow already in progress.", ex.Message);

            requestComplete.SetResult(true);
            await task1;
        }

        [Fact]
        public async Task StartAsync_SetsCorrectGrantTypeInBody()
        {
            var client = CreateMockClient();
            HttpRequestMessage? capturedRequest = null;
            client.ExchangeAsync(Arg.Do<OAuth2TokenRequest>(r =>
            {
                var msg = new HttpRequestMessage(HttpMethod.Post, r.Url);
                msg.Content = r.Body();
                capturedRequest = msg;
            })).Returns(Task.FromResult(ApiResponse<Token>.Success(TestHelpers.CreateToken())));

            var flow = new TokenExchangeFlow(client);
            await flow.StartAsync(TokenExchangeToken.Subject(TokenKind.IdToken, "id-token-value"));

            Assert.NotNull(capturedRequest);
            var body = await capturedRequest!.Content!.ReadAsStringAsync();
            Assert.Contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange", body);
        }

        [Fact]
        public async Task StartAsync_SetsCorrectSubjectTokenParameters()
        {
            var client = CreateMockClient();
            HttpRequestMessage? capturedRequest = null;
            client.ExchangeAsync(Arg.Do<OAuth2TokenRequest>(r =>
            {
                var msg = new HttpRequestMessage(HttpMethod.Post, r.Url);
                msg.Content = r.Body();
                capturedRequest = msg;
            })).Returns(Task.FromResult(ApiResponse<Token>.Success(TestHelpers.CreateToken())));

            var flow = new TokenExchangeFlow(client);
            await flow.StartAsync(TokenExchangeToken.Subject(TokenKind.IdToken, "my-id-token"));

            Assert.NotNull(capturedRequest);
            var body = await capturedRequest!.Content!.ReadAsStringAsync();
            Assert.Contains("subject_token=my-id-token", body);
            Assert.Contains("subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid_token", body);
        }

        [Fact]
        public async Task StartAsync_SetsCorrectActorTokenParameters()
        {
            var client = CreateMockClient();
            HttpRequestMessage? capturedRequest = null;
            client.ExchangeAsync(Arg.Do<OAuth2TokenRequest>(r =>
            {
                var msg = new HttpRequestMessage(HttpMethod.Post, r.Url);
                msg.Content = r.Body();
                capturedRequest = msg;
            })).Returns(Task.FromResult(ApiResponse<Token>.Success(TestHelpers.CreateToken())));

            var flow = new TokenExchangeFlow(client);
            await flow.StartAsync(
                TokenExchangeToken.Subject(TokenKind.IdToken, "my-id-token"),
                TokenExchangeToken.Actor(TokenKind.DeviceSecret, "my-device-secret"));

            Assert.NotNull(capturedRequest);
            var body = await capturedRequest!.Content!.ReadAsStringAsync();
            Assert.Contains("actor_token=my-device-secret", body);
            Assert.Contains("actor_token_type=urn%3Ax-oath%3Aparams%3Aoauth%3Atoken-type%3Adevice-secret", body);
        }

        [Fact]
        public async Task StartAsync_IncludesClientAuthentication()
        {
            var mockAuth = Substitute.For<IClientAuthentication>();
            mockAuth.Method.Returns(ClientAuthentication.None);
            var client = Substitute.For<OAuth2Client>(
                new OAuth2ClientConfiguration(TestHelpers.ExampleUri, TestHelpers.ExampleOpenIdConfigUri, TestHelpers.DefaultClientId, authentication: mockAuth),
                _httpClient,
                null,
                null,
                null);
            client.FetchOpenIdConfigurationAsync()
                .Returns(Task.FromResult(TestHelpers.CreateOpenIdConfiguration()));
            client.ExchangeAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<CancellationToken>()).Returns(ci =>
            {
                ci.Arg<OAuth2TokenRequest>().Prepare();
                return Task.FromResult(ApiResponse<Token>.Success(TestHelpers.CreateToken()));
            });

            var flow = new TokenExchangeFlow(client);
            await flow.StartAsync(TokenExchangeToken.Subject(TokenKind.IdToken, "id-token-value"));

            mockAuth.Received(1).AddAuthentication(
                Arg.Any<HttpRequestMessage>(),
                TestHelpers.DefaultClientId,
                Arg.Any<Dictionary<string, string>>());
        }

        [Fact]
        public async Task StartAsync_IncludesAudience()
        {
            var client = CreateMockClient();
            HttpRequestMessage? capturedRequest = null;
            client.ExchangeAsync(Arg.Do<OAuth2TokenRequest>(r =>
            {
                var msg = new HttpRequestMessage(HttpMethod.Post, r.Url);
                msg.Content = r.Body();
                capturedRequest = msg;
            })).Returns(Task.FromResult(ApiResponse<Token>.Success(TestHelpers.CreateToken())));

            var flow = new TokenExchangeFlow(client);
            await flow.StartAsync(
                TokenExchangeToken.Subject(TokenKind.IdToken, "id-token-value"),
                audience: "api://default");

            Assert.NotNull(capturedRequest);
            var body = await capturedRequest!.Content!.ReadAsStringAsync();
            Assert.Contains("audience=api%3A%2F%2Fdefault", body);
        }

        [Fact]
        public void Subject_WithDeviceSecretKind_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => TokenExchangeToken.Subject(TokenKind.DeviceSecret, "value"));
        }

        [Fact]
        public async Task StartAsync_WithoutAudience_DoesNotIncludeAudience()
        {
            var client = CreateMockClient();
            HttpRequestMessage? capturedRequest = null;
            client.ExchangeAsync(Arg.Do<OAuth2TokenRequest>(r =>
            {
                var msg = new HttpRequestMessage(HttpMethod.Post, r.Url);
                msg.Content = r.Body();
                capturedRequest = msg;
            })).Returns(Task.FromResult(ApiResponse<Token>.Success(TestHelpers.CreateToken())));

            var flow = new TokenExchangeFlow(client);
            await flow.StartAsync(TokenExchangeToken.Subject(TokenKind.IdToken, "id-token-value"));

            Assert.NotNull(capturedRequest);
            var body = await capturedRequest!.Content!.ReadAsStringAsync();
            Assert.DoesNotContain("audience=", body);
        }

        [Fact]
        public async Task StartAsync_ReservedAdditionalParameter_ThrowsArgumentException()
        {
            var client = CreateMockClient();
            client.ExchangeAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<CancellationToken>())
                .Returns(ci =>
                {
                    ci.Arg<OAuth2TokenRequest>().Body();
                    return Task.FromResult(ApiResponse<Token>.Success(TestHelpers.CreateToken()));
                });

            var flow = new TokenExchangeFlow(client);

            await Assert.ThrowsAsync<ArgumentException>(() =>
                flow.StartAsync(
                    TokenExchangeToken.Subject(TokenKind.IdToken, "id-token-value"),
                    additionalParameters: new Dictionary<string, string> { ["grant_type"] = "malicious" }));
        }

        [Fact]
        public async Task StartAsync_IncludesAdditionalParameters()
        {
            var client = CreateMockClient();
            HttpRequestMessage? capturedRequest = null;
            client.ExchangeAsync(Arg.Do<OAuth2TokenRequest>(r =>
            {
                var msg = new HttpRequestMessage(HttpMethod.Post, r.Url);
                msg.Content = r.Body();
                capturedRequest = msg;
            })).Returns(Task.FromResult(ApiResponse<Token>.Success(TestHelpers.CreateToken())));

            var flow = new TokenExchangeFlow(client);
            await flow.StartAsync(
                TokenExchangeToken.Subject(TokenKind.IdToken, "id-token-value"),
                additionalParameters: new Dictionary<string, string> { ["custom_param"] = "custom_value" });

            Assert.NotNull(capturedRequest);
            var body = await capturedRequest!.Content!.ReadAsStringAsync();
            Assert.Contains("custom_param=custom_value", body);
        }

        [Fact]
        public async Task StartAsync_NativeSso_ExchangesIdTokenAndDeviceSecret()
        {
            var newToken = TestHelpers.CreateToken(accessToken: "new-access-token");
            var client = CreateMockClient();
            HttpRequestMessage? capturedRequest = null;
            client.ExchangeAsync(Arg.Do<OAuth2TokenRequest>(r =>
            {
                var msg = new HttpRequestMessage(HttpMethod.Post, r.Url);
                msg.Content = r.Body();
                capturedRequest = msg;
            })).Returns(Task.FromResult(ApiResponse<Token>.Success(newToken)));

            var idTokenString = "existing-id-token";
            var deviceSecret = "existing-device-secret";

            var flow = new TokenExchangeFlow(client);
            var result = await flow.StartAsync(
                TokenExchangeToken.Subject(TokenKind.IdToken, idTokenString),
                TokenExchangeToken.Actor(TokenKind.DeviceSecret, deviceSecret));

            Assert.True(result.IsSuccess);
            Assert.Equal("new-access-token", result.Result!.AccessToken);

            var body = await capturedRequest!.Content!.ReadAsStringAsync();
            Assert.Contains("subject_token=existing-id-token", body);
            Assert.Contains("subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid_token", body);
            Assert.Contains("actor_token=existing-device-secret", body);
            Assert.Contains("actor_token_type=urn%3Ax-oath%3Aparams%3Aoauth%3Atoken-type%3Adevice-secret", body);
            Assert.Contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange", body);
        }
    }
}
