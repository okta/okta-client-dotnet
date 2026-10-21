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
using NSubstitute;
using Okta.AuthFoundation.Exceptions;
using Okta.AuthFoundation.OAuth2;
using Okta.OAuth2;
using Okta.OAuth2.Flows;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    public class SessionLogoutFlowTests : IDisposable
    {
        private TestHttpMessageHandler _mockHandler;
        private HttpClient _httpClient;

        public SessionLogoutFlowTests()
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
        public async Task StartAsync_ReturnsLogoutUrlWithRequiredParameters()
        {
            var openIdConfig = TestHelpers.CreateOpenIdConfiguration();
            var oauth2Client = Substitute.For<OAuth2Client>(
                TestHelpers.CreateOAuth2ClientConfiguration(),
                _httpClient,
                null,
                null,
                null);
            oauth2Client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(openIdConfig));

            var logoutRedirectUri = new Uri("http://localhost:8080/logout-callback");
            var flow = new SessionLogoutFlow(oauth2Client, logoutRedirectUri);
            var context = new SessionLogoutFlowContext("test-id-token", "test-state");

            var logoutUrl = await flow.StartAsync(context);
            var query = HttpUtility.ParseQueryString(logoutUrl.Query);

            Assert.StartsWith("https://example.com/logout", logoutUrl.ToString());
            Assert.Equal("test-id-token", query["id_token_hint"]);
            Assert.Equal("http://localhost:8080/logout-callback", query["post_logout_redirect_uri"]);
            Assert.Equal("test-state", query["state"]);
        }

        [Fact]
        public async Task StartAsync_MissingEndSessionEndpoint_ThrowsOAuth2Exception()
        {
            var openIdConfig = new OpenIdConfiguration(
                TestHelpers.ExampleUri,
                TestHelpers.ExampleTokenEndpoint,
                TestHelpers.ExampleJwksEndpoint);
            openIdConfig.EndSessionEndpoint = null;

            var oauth2Client = Substitute.For<OAuth2Client>(
                TestHelpers.CreateOAuth2ClientConfiguration(),
                _httpClient,
                null,
                null,
                null);
            oauth2Client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(openIdConfig));

            var flow = new SessionLogoutFlow(oauth2Client, new Uri("http://localhost:8080/logout-callback"));
            var context = new SessionLogoutFlowContext("test-id-token", "test-state");

            var ex = await Assert.ThrowsAsync<OAuth2Exception>(() => flow.StartAsync(context));
            Assert.Contains("end_session_endpoint", ex.Message);
        }

        [Fact]
        public async Task StartAsync_NetworkError_ThrowsOAuth2Exception()
        {
            var oauth2Client = Substitute.For<OAuth2Client>(
                TestHelpers.CreateOAuth2ClientConfiguration(),
                _httpClient,
                null,
                null,
                null);
            oauth2Client.FetchOpenIdConfigurationAsync()
                .Returns(Task.FromException<OpenIdConfiguration>(new HttpRequestException("Network error")));

            var flow = new SessionLogoutFlow(oauth2Client, new Uri("http://localhost:8080/logout-callback"));
            var context = new SessionLogoutFlowContext("test-id-token", "test-state");

            var ex = await Assert.ThrowsAsync<HttpRequestException>(() => flow.StartAsync(context));
        }

        [Fact]
        public async Task StartAsync_CalledWhileInProgress_ThrowsFlowException()
        {
            var openIdConfig = TestHelpers.CreateOpenIdConfiguration();
            var tcs = new TaskCompletionSource<OpenIdConfiguration>();

            var oauth2Client = Substitute.For<OAuth2Client>(
                TestHelpers.CreateOAuth2ClientConfiguration(),
                _httpClient,
                null,
                null,
                null);
            oauth2Client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>()).Returns(tcs.Task);

            var flow = new SessionLogoutFlow(oauth2Client, new Uri("http://localhost:8080/logout-callback"));
            var context = new SessionLogoutFlowContext("test-id-token", "test-state");

            var firstCall = flow.StartAsync(context);

            var ex = await Assert.ThrowsAsync<FlowException>(() => flow.StartAsync(context));
            Assert.Contains("already in progress", ex.Message);

            tcs.SetResult(openIdConfig);
            await firstCall;
        }

        [Fact]
        public async Task StartAsync_ResetsStateAfterCompletion()
        {
            var openIdConfig = TestHelpers.CreateOpenIdConfiguration();
            var oauth2Client = Substitute.For<OAuth2Client>(
                TestHelpers.CreateOAuth2ClientConfiguration(),
                _httpClient,
                null,
                null,
                null);
            oauth2Client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(openIdConfig));

            var flow = new SessionLogoutFlow(oauth2Client, new Uri("http://localhost:8080/logout-callback"));
            var context = new SessionLogoutFlowContext("test-id-token", "test-state");

            await flow.StartAsync(context);
            var secondUrl = await flow.StartAsync(context);

            Assert.NotNull(secondUrl);
        }

        [Fact]
        public async Task StartAsync_ResetsStateAfterError()
        {
            var oauth2Client = Substitute.For<OAuth2Client>(
                TestHelpers.CreateOAuth2ClientConfiguration(),
                _httpClient,
                null,
                null,
                null);

            oauth2Client.FetchOpenIdConfigurationAsync()
                .Returns(
                    Task.FromException<OpenIdConfiguration>(new HttpRequestException("Network error")),
                    Task.FromResult(TestHelpers.CreateOpenIdConfiguration()));

            var flow = new SessionLogoutFlow(oauth2Client, new Uri("http://localhost:8080/logout-callback"));
            var context = new SessionLogoutFlowContext("test-id-token", "test-state");

            await Assert.ThrowsAsync<HttpRequestException>(() => flow.StartAsync(context));

            var secondUrl = await flow.StartAsync(context);
            Assert.NotNull(secondUrl);
        }
    }
}
