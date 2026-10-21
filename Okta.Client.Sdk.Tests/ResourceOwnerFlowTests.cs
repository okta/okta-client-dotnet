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
using Okta.AuthFoundation;
using Okta.AuthFoundation.Claims;
using Okta.AuthFoundation.Exceptions;
using Okta.AuthFoundation.Http;
using Okta.AuthFoundation.OAuth2;
using Okta.AuthFoundation.TokenManagement;
using Okta.OAuth2;
using Okta.OAuth2.Flows;
using Xunit;

namespace Okta.Client.Sdk.Tests;

public class ResourceOwnerFlowTests : IDisposable
{
    private TestHttpMessageHandler _mockHandler;
    private HttpClient _httpClient;

    public ResourceOwnerFlowTests()
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
    public async Task StartAsync_Successful_ReturnsToken()
    {
        var idToken = TestHelpers.CreateIdToken();
        var openIdConfig = TestHelpers.CreateOpenIdConfiguration();
        var token = TestHelpers.CreateToken(accessToken: "abc", idToken: idToken);
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

        var flow = new ResourceOwnerFlow(oauth2Client);

        var response = await flow.StartAsync("user", "pass");
        var result = response.Result;

        Assert.Equal("abc", result.AccessToken);
        Assert.Equal("1234567890", result.IdToken!.Subject());
        Assert.Equal("Bearer", result.TokenType);
        Assert.False(flow.IsAuthenticating);
        mockAuth.Received(1).AddAuthentication(Arg.Any<HttpRequestMessage>(), TestHelpers.DefaultClientId, Arg.Any<Dictionary<string, string>>());
    }

    [Fact]
    public async Task StartAsync_Failure_ReturnsFailureResponse()
    {
        var openIdConfig = TestHelpers.CreateOpenIdConfiguration();
        var oauth2Client = Substitute.For<OAuth2Client>(
            TestHelpers.CreateOAuth2ClientConfiguration(),
            _httpClient,
            null,
            null,
            null);
        oauth2Client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(openIdConfig));
        oauth2Client.ExchangeAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult(ApiResponse<Token>.Failure("exchange failed", HttpStatusCode.Unauthorized)));

        var flow = new ResourceOwnerFlow(oauth2Client);

        var response = await flow.StartAsync("user", "pass");
        Assert.False(response.IsSuccess);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("exchange failed", response.ErrorMessage);
        Assert.False(flow.IsAuthenticating);
    }

    [Fact]
    public async Task StartAsync_NetworkError_ThrowsException()
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
            .Returns(Task.FromException<ApiResponse<Token>>(new HttpRequestException("Network unreachable")));

        var flow = new ResourceOwnerFlow(oauth2Client);

        await Assert.ThrowsAsync<HttpRequestException>(() => flow.StartAsync("user", "pass"));
        Assert.False(flow.IsAuthenticating);
    }

    [Fact]
    public async Task StartAsync_ThrowsFlowException_WhenAlreadyInProgress()
    {
        var openIdConfig = TestHelpers.CreateOpenIdConfiguration();
        var requestStarted = new TaskCompletionSource<bool>();
        var requestComplete = new TaskCompletionSource<bool>();

        var oauth2Client = Substitute.For<OAuth2Client>(
            TestHelpers.CreateOAuth2ClientConfiguration(),
            _httpClient,
            null,
            null,
            null);
        oauth2Client.FetchOpenIdConfigurationAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(openIdConfig));
        oauth2Client.ExchangeAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<CancellationToken>())
            .Returns(async _ =>
            {
                requestStarted.SetResult(true);
                await requestComplete.Task;
                return ApiResponse<Token>.Success(TestHelpers.CreateToken());
            });

        var flow = new ResourceOwnerFlow(oauth2Client);

        var task1 = flow.StartAsync("user", "pass");
        await requestStarted.Task;

        var ex = await Assert.ThrowsAsync<FlowException>(() => flow.StartAsync("user2", "pass2"));
        Assert.Equal("Flow already in progress.", ex.Message);

        requestComplete.SetResult(true);
        await task1;
    }
}
