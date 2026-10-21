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
    public class DeviceAuthorizationCodeFlowTests : IDisposable
    {
        private readonly TestHttpMessageHandler _mockHandler;
        private readonly HttpClient _httpClient;

        public DeviceAuthorizationCodeFlowTests()
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

        private static DeviceAuthorizationResponse CreateDeviceAuthResponse(int interval = 0) =>
            new DeviceAuthorizationResponse
            {
                DeviceCode = "device-code-123",
                UserCode = "ABCD-1234",
                VerificationUri = new Uri("https://example.com/activate"),
                VerificationUriComplete = new Uri("https://example.com/activate?user_code=ABCD-1234"),
                ExpiresIn = 600,
                Interval = interval,
            };

        private static void SetupDeviceAuthResponse(OAuth2Client client, DeviceAuthorizationResponse response) =>
            client.SendAsync<DeviceAuthorizationResponse>(Arg.Any<HttpRequestMessage>())
                .Returns(Task.FromResult(ApiResponse<DeviceAuthorizationResponse>.Success(response)));

        private OAuth2Client CreateMockClient(OpenIdConfiguration? openIdConfig = null)
        {
            var client = Substitute.For<OAuth2Client>(
                TestHelpers.CreateOAuth2ClientConfiguration(),
                _httpClient,
                null,
                null,
                null);
            client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>())
                .Returns(Task.FromResult(openIdConfig ?? TestHelpers.CreateOpenIdConfiguration()));
            return client;
        }

        [Fact]
        public async Task StartAsync_ReturnsDeviceAuthorizationResponse()
        {
            var mockAuth = Substitute.For<IClientAuthentication>();
            mockAuth.Method.Returns(ClientAuthentication.None);
            var client = Substitute.For<OAuth2Client>(
                new OAuth2ClientConfiguration(TestHelpers.ExampleUri, TestHelpers.ExampleOpenIdConfigUri, TestHelpers.DefaultClientId, authentication: mockAuth),
                _httpClient,
                null,
                null,
                null);
            client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>())
                .Returns(Task.FromResult(TestHelpers.CreateOpenIdConfiguration()));

            var deviceAuthResponse = CreateDeviceAuthResponse();
            SetupDeviceAuthResponse(client, deviceAuthResponse);

            var flow = new DeviceAuthorizationCodeFlow(client);
            var result = await flow.StartAsync();

            Assert.Equal("device-code-123", result.DeviceCode);
            Assert.Equal("ABCD-1234", result.UserCode);
            Assert.Equal(new Uri("https://example.com/activate"), result.VerificationUri);
            Assert.Equal(new Uri("https://example.com/activate?user_code=ABCD-1234"), result.VerificationUriComplete);
            Assert.Equal(600, result.ExpiresIn);
            Assert.True(flow.IsAuthenticating);
            mockAuth.Received(1).AddAuthentication(Arg.Any<HttpRequestMessage>(), TestHelpers.DefaultClientId, Arg.Any<Dictionary<string, string>>());
        }

        [Fact]
        public async Task StartAsync_MissingDeviceAuthorizationEndpoint_ThrowsInvalidOperationException()
        {
            var openIdConfig = new OpenIdConfiguration(
                TestHelpers.ExampleUri,
                TestHelpers.ExampleTokenEndpoint,
                TestHelpers.ExampleJwksEndpoint);
            openIdConfig.DeviceAuthorizationEndpoint = null;

            var client = CreateMockClient(openIdConfig);
            var flow = new DeviceAuthorizationCodeFlow(client);

            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => flow.StartAsync());
            Assert.Contains("device_authorization_endpoint", ex.Message);
            Assert.False(flow.IsAuthenticating);
        }

        [Fact]
        public async Task StartAsync_ServerError_ThrowsOAuth2Exception()
        {
            var client = CreateMockClient();
            client.SendAsync<DeviceAuthorizationResponse>(Arg.Any<HttpRequestMessage>())
                .Returns(Task.FromResult(ApiResponse<DeviceAuthorizationResponse>.Failure(
                    "invalid_client", HttpStatusCode.Unauthorized)));

            var flow = new DeviceAuthorizationCodeFlow(client);

            var ex = await Assert.ThrowsAsync<OAuth2Exception>(() => flow.StartAsync());
            Assert.Contains("invalid_client", ex.Message);
            Assert.False(flow.IsAuthenticating);
        }

        [Fact]
        public async Task StartAsync_NetworkError_ThrowsAndResetsState()
        {
            var client = CreateMockClient();
            client.SendAsync<DeviceAuthorizationResponse>(Arg.Any<HttpRequestMessage>())
                .Returns(Task.FromException<ApiResponse<DeviceAuthorizationResponse>>(
                    new HttpRequestException("Network error")));

            var flow = new DeviceAuthorizationCodeFlow(client);

            await Assert.ThrowsAsync<HttpRequestException>(() => flow.StartAsync());
            Assert.False(flow.IsAuthenticating);
        }

        [Fact]
        public async Task StartAsync_ThrowsFlowException_WhenAlreadyInProgress()
        {
            var requestStarted = new TaskCompletionSource<bool>();
            var requestComplete = new TaskCompletionSource<bool>();

            var client = Substitute.For<OAuth2Client>(
                TestHelpers.CreateOAuth2ClientConfiguration(),
                _httpClient,
                null,
                null,
                null);
            client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>())
                .Returns(Task.FromResult(TestHelpers.CreateOpenIdConfiguration()));
            client.SendAsync<DeviceAuthorizationResponse>(Arg.Any<HttpRequestMessage>())
                .Returns(async _ =>
                {
                    requestStarted.SetResult(true);
                    await requestComplete.Task;
                    return ApiResponse<DeviceAuthorizationResponse>.Success(CreateDeviceAuthResponse());
                });

            var flow = new DeviceAuthorizationCodeFlow(client);

            var task1 = flow.StartAsync();
            await requestStarted.Task;

            var ex = await Assert.ThrowsAsync<FlowException>(() => flow.StartAsync());
            Assert.Equal("Flow already in progress.", ex.Message);

            requestComplete.SetResult(true);
            await task1;
        }

        [Fact]
        public async Task StartAsync_IncludesAdditionalParameters()
        {
            var client = CreateMockClient();
            HttpRequestMessage? capturedRequest = null;
            client.SendAsync<DeviceAuthorizationResponse>(Arg.Do<HttpRequestMessage>(r => capturedRequest = r))
                .Returns(Task.FromResult(ApiResponse<DeviceAuthorizationResponse>.Success(CreateDeviceAuthResponse())));

            var additionalParams = new Dictionary<string, string> { ["acr_values"] = "urn:okta:loa:2fa:any" };
            var flow = new DeviceAuthorizationCodeFlow(client, additionalParams);

            await flow.StartAsync();

            Assert.NotNull(capturedRequest);
            var body = await capturedRequest!.Content!.ReadAsStringAsync();
            Assert.Contains("acr_values", body);
        }

        [Fact]
        public async Task ResumeAsync_WithoutStart_ThrowsInvalidOperationException()
        {
            var client = CreateMockClient();
            var flow = new DeviceAuthorizationCodeFlow(client);

            await Assert.ThrowsAsync<InvalidOperationException>(() => flow.ResumeAsync());
        }

        [Fact]
        public async Task StartAsync_ReservedAdditionalParameter_ThrowsArgumentException()
        {
            var client = CreateMockClient();
            client.SendAsync<DeviceAuthorizationResponse>(Arg.Any<HttpRequestMessage>())
                .Returns(Task.FromResult(ApiResponse<DeviceAuthorizationResponse>.Success(CreateDeviceAuthResponse())));

            var flow = new DeviceAuthorizationCodeFlow(client, new Dictionary<string, string> { ["client_id"] = "evil" });

            await Assert.ThrowsAsync<ArgumentException>(() => flow.StartAsync());
        }

        [Fact]
        public async Task ResumeAsync_ImmediateSuccess_ReturnsToken()
        {
            var mockAuth = Substitute.For<IClientAuthentication>();
            mockAuth.Method.Returns(ClientAuthentication.None);
            var client = Substitute.For<OAuth2Client>(
                new OAuth2ClientConfiguration(TestHelpers.ExampleUri, TestHelpers.ExampleOpenIdConfigUri, TestHelpers.DefaultClientId, authentication: mockAuth),
                _httpClient,
                null,
                null,
                null);
            client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>())
                .Returns(Task.FromResult(TestHelpers.CreateOpenIdConfiguration()));

            var deviceAuthResponse = CreateDeviceAuthResponse(interval: 0);
            var token = TestHelpers.CreateToken(accessToken: "access-token-123");
            SetupDeviceAuthResponse(client, deviceAuthResponse);
            client.ExchangeAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<CancellationToken>()).Returns(ci =>
            {
                ci.Arg<OAuth2TokenRequest>().Prepare();
                return Task.FromResult(ApiResponse<Token>.Success(token));
            });

            var flow = new DeviceAuthorizationCodeFlow(client, minimumInterval: 0);
            await flow.StartAsync();
            var result = await flow.ResumeAsync();

            Assert.True(result.IsSuccess);
            Assert.Equal("access-token-123", result.Result!.AccessToken);
            Assert.False(flow.IsAuthenticating);
            mockAuth.Received(2).AddAuthentication(Arg.Any<HttpRequestMessage>(), TestHelpers.DefaultClientId, Arg.Any<Dictionary<string, string>>());
        }

        [Fact]
        public async Task ResumeAsync_AuthorizationPending_ThenSuccess_ReturnsToken()
        {
            var deviceAuthResponse = CreateDeviceAuthResponse(interval: 0);
            var token = TestHelpers.CreateToken(accessToken: "access-token-123");
            var pendingResponse = ApiResponse<Token>.Failure(
                "{\"error\":\"authorization_pending\",\"error_description\":\"Not yet\"}",
                HttpStatusCode.BadRequest);
            var successResponse = ApiResponse<Token>.Success(token);

            var client = CreateMockClient();
            SetupDeviceAuthResponse(client, deviceAuthResponse);
            client.ExchangeAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<CancellationToken>())
                .Returns(Task.FromResult(pendingResponse), Task.FromResult(successResponse));

            var flow = new DeviceAuthorizationCodeFlow(client, minimumInterval: 0);
            await flow.StartAsync();
            var result = await flow.ResumeAsync();

            Assert.True(result.IsSuccess);
            Assert.Equal("access-token-123", result.Result!.AccessToken);
            Assert.False(flow.IsAuthenticating);
        }

        [Fact]
        public async Task ResumeAsync_SlowDown_ThenSuccess_ReturnsToken()
        {
            var deviceAuthResponse = CreateDeviceAuthResponse(interval: 0);
            var token = TestHelpers.CreateToken(accessToken: "access-token-123");
            var slowDownResponse = ApiResponse<Token>.Failure(
                "{\"error\":\"slow_down\",\"error_description\":\"Slow down\"}",
                HttpStatusCode.BadRequest);
            var successResponse = ApiResponse<Token>.Success(token);

            var client = CreateMockClient();
            SetupDeviceAuthResponse(client, deviceAuthResponse);
            client.ExchangeAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<CancellationToken>())
                .Returns(Task.FromResult(slowDownResponse), Task.FromResult(successResponse));

            var flow = new DeviceAuthorizationCodeFlow(client, minimumInterval: 0);
            await flow.StartAsync();
            var result = await flow.ResumeAsync();

            Assert.True(result.IsSuccess);
            Assert.Equal("access-token-123", result.Result!.AccessToken);
        }

        [Fact]
        public async Task ResumeAsync_ExpiredToken_ThrowsOAuth2Exception()
        {
            var deviceAuthResponse = CreateDeviceAuthResponse(interval: 0);
            var expiredResponse = ApiResponse<Token>.Failure(
                "{\"error\":\"expired_token\",\"error_description\":\"Token expired\"}",
                HttpStatusCode.BadRequest);

            var client = CreateMockClient();
            SetupDeviceAuthResponse(client, deviceAuthResponse);
            client.ExchangeAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<CancellationToken>())
                .Returns(Task.FromResult(expiredResponse));

            var flow = new DeviceAuthorizationCodeFlow(client, minimumInterval: 0);
            await flow.StartAsync();

            var ex = await Assert.ThrowsAsync<OAuth2Exception>(() => flow.ResumeAsync());
            Assert.Contains("expired", ex.Message);
            Assert.False(flow.IsAuthenticating);
        }

        [Fact]
        public async Task ResumeAsync_AccessDenied_ThrowsOAuth2Exception()
        {
            var deviceAuthResponse = CreateDeviceAuthResponse(interval: 0);
            var deniedResponse = ApiResponse<Token>.Failure(
                "{\"error\":\"access_denied\",\"error_description\":\"User denied\"}",
                HttpStatusCode.BadRequest);

            var client = CreateMockClient();
            SetupDeviceAuthResponse(client, deviceAuthResponse);
            client.ExchangeAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<CancellationToken>())
                .Returns(Task.FromResult(deniedResponse));

            var flow = new DeviceAuthorizationCodeFlow(client, minimumInterval: 0);
            await flow.StartAsync();

            var ex = await Assert.ThrowsAsync<OAuth2Exception>(() => flow.ResumeAsync());
            Assert.Contains("User denied", ex.Message);
            Assert.False(flow.IsAuthenticating);
        }

        [Fact]
        public async Task ResumeAsync_UnknownError_ReturnsFailureResponse()
        {
            var deviceAuthResponse = CreateDeviceAuthResponse(interval: 0);
            var errorResponse = ApiResponse<Token>.Failure(
                "{\"error\":\"server_error\",\"error_description\":\"Unexpected\"}",
                HttpStatusCode.InternalServerError);

            var client = CreateMockClient();
            SetupDeviceAuthResponse(client, deviceAuthResponse);
            client.ExchangeAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<CancellationToken>())
                .Returns(Task.FromResult(errorResponse));

            var flow = new DeviceAuthorizationCodeFlow(client, minimumInterval: 0);
            await flow.StartAsync();
            var result = await flow.ResumeAsync();

            Assert.False(result.IsSuccess);
            Assert.Equal(HttpStatusCode.InternalServerError, result.StatusCode);
            Assert.False(flow.IsAuthenticating);
        }

        [Fact]
        public async Task ResumeAsync_Cancelled_ThrowsOperationCanceledException()
        {
            var deviceAuthResponse = CreateDeviceAuthResponse(interval: 0);

            var client = CreateMockClient();
            SetupDeviceAuthResponse(client, deviceAuthResponse);

            using var cts = new CancellationTokenSource();
            client.ExchangeAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<CancellationToken>())
                .Returns(async _ =>
                {
                    cts.Cancel();
                    return ApiResponse<Token>.Failure(
                        "{\"error\":\"authorization_pending\"}", HttpStatusCode.BadRequest);
                });

            var flow = new DeviceAuthorizationCodeFlow(client, minimumInterval: 0);
            await flow.StartAsync();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => flow.ResumeAsync(cts.Token));
            Assert.False(flow.IsAuthenticating);
        }

        [Fact]
        public async Task Reset_AfterStart_ClearsState()
        {
            var deviceAuthResponse = CreateDeviceAuthResponse();
            var client = CreateMockClient();
            SetupDeviceAuthResponse(client, deviceAuthResponse);

            var flow = new DeviceAuthorizationCodeFlow(client);
            await flow.StartAsync();
            Assert.True(flow.IsAuthenticating);

            flow.Reset();

            Assert.False(flow.IsAuthenticating);
            await Assert.ThrowsAsync<InvalidOperationException>(() => flow.ResumeAsync());
        }
    }
}
