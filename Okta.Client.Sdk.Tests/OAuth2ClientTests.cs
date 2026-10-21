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
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Okta.AuthFoundation;
using Okta.AuthFoundation.Claims;
using Okta.AuthFoundation.Exceptions;
using Okta.AuthFoundation.JwtSecurity;
using Okta.AuthFoundation.OAuth2;
using Okta.AuthFoundation.TokenManagement;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    public class OAuth2ClientTests : IDisposable
    {
        private OAuth2ClientConfiguration _config;
        private IClientAuthentication _mockAuth;
        private OAuth2TokenRequest _request;
        private TestHttpMessageHandler _mockHandler;
        private HttpClient _httpClient;

        public OAuth2ClientTests()
        {
            _mockAuth = Substitute.For<IClientAuthentication>();
            _mockAuth.Method.Returns(ClientAuthentication.None);
            _config = new OAuth2ClientConfiguration(
                TestHelpers.ExampleUri,
                TestHelpers.ExampleOpenIdConfigUri,
                TestHelpers.DefaultClientId,
                scope: new List<string> { TestHelpers.DefaultScope },
                authentication: _mockAuth);
            _request = Substitute.For<OAuth2TokenRequest>();
            _request.Url = TestHelpers.ExampleTokenEndpoint;
            _request.ClientId = TestHelpers.DefaultClientId;
            _request.Body().Returns(new StringContent("grant_type=authorization_code"));
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
        public void Constructor_SetsConfiguration()
        {
            var client = new OAuth2Client(_config, _httpClient);
            Assert.Equal(_config, client.Configuration);
        }

        [Fact]
        public async Task ExchangeAsync_ReturnsToken_OnSuccessResponse()
        {
            var tokenJson = @"{
                ""access_token"": ""abc123"",
                ""token_type"": ""Bearer"",
                ""expires_in"": 3600
            }";

            _mockHandler.HandlerFunc = (request, cancellationToken) =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(tokenJson),
                });

            var client = Substitute.ForPartsOf<OAuth2Client>(_config, _httpClient, null, null, null);

            client.When(x => x.JwksAsync()).DoNotCallBase();
            var mockJsonWebKeySet = new JsonWebKeySet();
            client.JwksAsync().Returns(Task.FromResult(mockJsonWebKeySet));

            client.When(x => x.ValidateTokenAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<JsonWebKeySet>(), Arg.Any<Token>())).DoNotCallBase();
            client.ValidateTokenAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<JsonWebKeySet>(), Arg.Any<Token>()).Returns(callInfo => Task.FromResult(callInfo.ArgAt<Token>(2)));

            var response = await client.ExchangeAsync(_request);
            var token = response.Result;

            Assert.NotNull(token);
            Assert.Equal("abc123", token.AccessToken);
            Assert.Equal("Bearer", token.TokenType);
            Assert.InRange(token.ExpiresIn, 3595, 3600);
        }

        [Fact]
        public async Task ExchangeAsync_ReturnsFailedResponse_OnNonSuccessResponse()
        {
            _mockHandler.HandlerFunc = (request, cancellationToken) =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent("error content"),
                });

            var client = Substitute.ForPartsOf<OAuth2Client>(_config, _httpClient, null, null, null);
            client.When(x => x.JwksAsync()).DoNotCallBase();
            client.JwksAsync().Returns(Task.FromResult(new JsonWebKeySet()));

            var response = await client.ExchangeAsync(_request);

            Assert.False(response.IsSuccess);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Contains("error content", response.ErrorMessage);
        }

        [Fact]
        public async Task ValidateTokenAsync_ValidatesIdToken_AndVerifiesSignature()
        {
            var openIdConfigJson = @"{
                ""issuer"": ""https://example.com"",
                ""token_endpoint"": ""https://example.com/token"",
                ""jwks_uri"": ""https://example.com/jwks"",
                ""id_token_signing_alg_values_supported"": [""RS256""]
            }";

            _mockHandler.HandlerFunc = (request, cancellationToken) =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(openIdConfigJson),
                });

            var mockJwks = new JsonWebKeySet();
            var mockIdToken = TestHelpers.CreateIdTokenWithClaims();
            var token = TestHelpers.CreateToken(
                accessToken: "test_access_token",
                idToken: mockIdToken,
                context: TestHelpers.CreateTokenContext());

            var mockValidator = Substitute.For<IIdTokenValidator>();
            var client = Substitute.ForPartsOf<OAuth2Client>(_config, _httpClient, mockValidator, null, null);

            client.When(x => x.ValidateTokenAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<JsonWebKeySet>(), Arg.Any<Token>()))
                .DoNotCallBase();

            client.ValidateTokenAsync(Arg.Any<OAuth2TokenRequest>(), Arg.Any<JsonWebKeySet>(), Arg.Any<Token>())
                .Returns(async callInfo =>
                {
                    var requestArg = callInfo.ArgAt<OAuth2TokenRequest>(0);
                    var jwksArg = callInfo.ArgAt<JsonWebKeySet>(1);
                    var tokenArg = callInfo.ArgAt<Token>(2);

                    await client.FetchOpenIdConfigurationAsync();

                    mockValidator.Validate(tokenArg.IdToken!, TestHelpers.ExampleUri, TestHelpers.DefaultClientId, null);
                    return tokenArg;
                });

            var result = await client.ValidateTokenAsync(_request, mockJwks, token);

            Assert.NotNull(result);
            Assert.Equal("test_access_token", result.AccessToken);
            await client.Received(1).FetchOpenIdConfigurationAsync();
            mockValidator.Received(1).Validate(Arg.Any<Jwt>(), TestHelpers.ExampleUri, TestHelpers.DefaultClientId, null);
        }

        [Fact]
        public async Task ValidateTokenAsync_AnchorsIdTokenIssuerOnConfiguredBaseUrl()
        {
            // The declared issuer differs from the configured base URL by a trailing slash, which is tolerated.
            // The id token is still validated against the configured base URL.
            var baseUrl = new Uri("https://example.com/oauth2/default");
            var config = new OAuth2ClientConfiguration(
                baseUrl,
                TestHelpers.DefaultClientId,
                scope: new List<string> { TestHelpers.DefaultScope },
                authentication: _mockAuth);

            var openIdConfigJson = @"{
                ""issuer"": ""https://example.com/oauth2/default/"",
                ""token_endpoint"": ""https://example.com/oauth2/default/v1/token"",
                ""jwks_uri"": ""https://example.com/oauth2/default/v1/keys"",
                ""id_token_signing_alg_values_supported"": [""RS256""]
            }";

            _mockHandler.HandlerFunc = (request, cancellationToken) =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(openIdConfigJson),
                });

            var token = TestHelpers.CreateToken(
                accessToken: "test_access_token",
                idToken: TestHelpers.CreateIdTokenWithClaims(issuer: "https://example.com/oauth2/default/"));

            var mockValidator = Substitute.For<IIdTokenValidator>();
            var mockJwkValidator = Substitute.For<IJwkValidator>();
            mockJwkValidator.ValidateAsync(Arg.Any<JsonWebToken>(), Arg.Any<IList<JsonWebKey>>()).Returns(Task.FromResult(true));
            _request.CreateValidatorContext(Arg.Any<string[]?>()).Returns(new IdTokenValidatorContext());

            var client = new OAuth2Client(config, _httpClient, mockValidator, Substitute.For<ITokenHashValidator>(), mockJwkValidator);

            await client.ValidateTokenAsync(_request, new JsonWebKeySet(), token);

            mockValidator.Received(1).Validate(
                Arg.Any<Jwt>(),
                baseUrl,
                TestHelpers.DefaultClientId,
                Arg.Any<IdTokenValidatorContext>());
        }

        [Fact]
        public async Task ValidateTokenAsync_NullIdToken_ReturnsTokenWithoutValidating()
        {
            var mockJwks = new JsonWebKeySet();
            var token = TestHelpers.CreateToken(accessToken: "test_access_token");

            // token.IdToken is null by default
            var mockValidator = Substitute.For<IIdTokenValidator>();
            var client = new OAuth2Client(_config, _httpClient, mockValidator, null);

            var result = await client.ValidateTokenAsync(_request, mockJwks, token);

            Assert.NotNull(result);
            Assert.Equal("test_access_token", result.AccessToken);
            mockValidator.DidNotReceive().Validate(Arg.Any<Jwt>(), Arg.Any<Uri>(), Arg.Any<string>(), Arg.Any<IdTokenValidatorContext>());
        }

        [Fact]
        public async Task RevokeAsync_SendsCorrectRequest_ForAccessToken()
        {
            // Arrange
            var token = TestHelpers.CreateToken(accessToken: "test-access-token");
            var revocationEndpoint = new Uri("https://example.com/revoke");

            var openIdConfigJson = $@"{{
                ""issuer"": ""{TestHelpers.ExampleUri}"",
                ""token_endpoint"": ""{TestHelpers.ExampleTokenEndpoint}"",
                ""jwks_uri"": ""{TestHelpers.ExampleJwksEndpoint}"",
                ""revocation_endpoint"": ""{revocationEndpoint}""
            }}";

            HttpRequestMessage? capturedRequest = null;
            _mockHandler.HandlerFunc = (request, cancellationToken) =>
            {
                if (request.RequestUri?.ToString().Contains("/.well-known/openid-configuration") == true)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(openIdConfigJson),
                    });
                }
                else if (request.RequestUri == revocationEndpoint)
                {
                    capturedRequest = request;
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            };

            var client = new OAuth2Client(_config, _httpClient);

            // Act
            await client.RevokeAsync(token, TokenRevokeType.Access);

            // Assert
            Assert.NotNull(capturedRequest);
            Assert.Equal(HttpMethod.Post, capturedRequest.Method);
            Assert.Equal(revocationEndpoint, capturedRequest.RequestUri);

            var content = await capturedRequest.Content!.ReadAsStringAsync();
            Assert.Contains("token=test-access-token", content);
            Assert.Contains("token_type_hint=access_token", content);
            _mockAuth.Received(1).AddAuthentication(Arg.Any<HttpRequestMessage>(), TestHelpers.DefaultClientId, Arg.Any<Dictionary<string, string>>());
        }

        [Fact]
        public async Task RevokeAsync_SendsCorrectRequest_ForRefreshToken()
        {
            // Arrange
            var token = TestHelpers.CreateToken(
                accessToken: "test-access-token",
                refreshToken: "test-refresh-token");
            var revocationEndpoint = new Uri("https://example.com/revoke");

            var openIdConfigJson = $@"{{
                ""issuer"": ""{TestHelpers.ExampleUri}"",
                ""token_endpoint"": ""{TestHelpers.ExampleTokenEndpoint}"",
                ""jwks_uri"": ""{TestHelpers.ExampleJwksEndpoint}"",
                ""revocation_endpoint"": ""{revocationEndpoint}""
            }}";

            HttpRequestMessage? capturedRequest = null;
            _mockHandler.HandlerFunc = (request, cancellationToken) =>
            {
                if (request.RequestUri?.ToString().Contains("/.well-known/openid-configuration") == true)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(openIdConfigJson),
                    });
                }
                else if (request.RequestUri == revocationEndpoint)
                {
                    capturedRequest = request;
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            };

            var client = new OAuth2Client(_config, _httpClient);

            // Act
            await client.RevokeAsync(token, TokenRevokeType.Refresh);

            // Assert
            Assert.NotNull(capturedRequest);
            Assert.Equal(HttpMethod.Post, capturedRequest.Method);
            Assert.Equal(revocationEndpoint, capturedRequest.RequestUri);

            var content = await capturedRequest.Content!.ReadAsStringAsync();
            Assert.Contains("token=test-refresh-token", content);
            Assert.Contains("token_type_hint=refresh_token", content);
        }

        [Fact]
        public async Task RevokeAsync_ThrowsArgumentOutOfRangeException_ForInvalidTokenType()
        {
            // Arrange
            var token = TestHelpers.CreateToken();
            var client = new OAuth2Client(_config, _httpClient);

            // Act & Assert
            var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
                () => client.RevokeAsync(token, (TokenRevokeType)999));
            Assert.Contains("Invalid TokenRevokeType", ex.Message);
        }

        [Fact]
        public async Task RevokeAsync_ThrowsInvalidOperationException_WhenRefreshTokenMissing()
        {
            // Arrange
            var token = TestHelpers.CreateToken(refreshToken: null);
            var client = new OAuth2Client(_config, _httpClient);

            // Act & Assert
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(
                () => client.RevokeAsync(token, TokenRevokeType.Refresh));
            Assert.Contains("Missing expected token", ex.Message);
            Assert.Contains("Refresh", ex.Message);
        }

        [Fact]
        public async Task RevokeAsync_ThrowsException_WhenRevocationEndpointMissing()
        {
            // Arrange
            var token = TestHelpers.CreateToken();

            var openIdConfigJson = $@"{{
                ""issuer"": ""{TestHelpers.ExampleUri}"",
                ""token_endpoint"": ""{TestHelpers.ExampleTokenEndpoint}"",
                ""jwks_uri"": ""{TestHelpers.ExampleJwksEndpoint}""
            }}";

            _mockHandler.HandlerFunc = (request, cancellationToken) =>
            {
                if (request.RequestUri?.ToString().Contains("/.well-known/openid-configuration") == true)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(openIdConfigJson),
                    });
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            };

            var client = new OAuth2Client(_config, _httpClient);

            // Act & Assert
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(
                () => client.RevokeAsync(token, TokenRevokeType.Access));
            Assert.Contains("No revocation endpoint found in the OpenID configuration", ex.Message);
        }

        [Fact]
        public async Task FetchOpenIdConfigurationAsync_ThrowsOAuth2Exception_OnHttpFailure()
        {
            // Arrange
            _mockHandler.HandlerFunc = (request, cancellationToken) =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
                {
                    Content = new StringContent("Service Unavailable"),
                });

            var client = new OAuth2Client(_config, _httpClient);

            // Act & Assert
            var ex = await Assert.ThrowsAsync<OAuth2Exception>(
                () => client.FetchOpenIdConfigurationAsync());
            Assert.Contains("Failed to retrieve OpenID configuration", ex.Message);
        }

        [Fact]
        public async Task FetchOpenIdConfigurationAsync_ThrowsOAuth2Exception_WhenIssuerHostDiffers()
        {
            // Arrange
            RespondWithOpenIdConfiguration("https://attacker.example.net");

            var client = new OAuth2Client(_config, _httpClient);

            // Act & Assert
            var ex = await Assert.ThrowsAsync<OAuth2Exception>(
                () => client.FetchOpenIdConfigurationAsync());
            Assert.Contains("does not match the configured issuer", ex.Message);
            Assert.Contains("https://attacker.example.net", ex.Message);
        }

        [Fact]
        public async Task FetchOpenIdConfigurationAsync_ThrowsOAuth2Exception_WhenIssuerPathDiffers()
        {
            // Arrange
            var baseUrl = new Uri("https://example.okta.com/oauth2/default");
            RespondWithOpenIdConfiguration("https://example.okta.com/oauth2/other");

            var client = new OAuth2Client(TestHelpers.CreateOAuth2ClientConfiguration(baseUrl), _httpClient);

            // Act & Assert
            var ex = await Assert.ThrowsAsync<OAuth2Exception>(
                () => client.FetchOpenIdConfigurationAsync());
            Assert.Contains("does not match the configured issuer", ex.Message);
        }

        [Fact]
        public async Task FetchOpenIdConfigurationAsync_ThrowsOAuth2Exception_WhenIssuerSchemeIsDowngraded()
        {
            // Arrange
            RespondWithOpenIdConfiguration("http://example.com");

            var client = new OAuth2Client(_config, _httpClient);

            // Act & Assert
            await Assert.ThrowsAsync<OAuth2Exception>(
                () => client.FetchOpenIdConfigurationAsync());
        }

        [Fact]
        public async Task FetchOpenIdConfigurationAsync_ThrowsOAuth2Exception_WhenIssuerPortDiffers()
        {
            // Arrange
            RespondWithOpenIdConfiguration("https://example.com:8443");

            var client = new OAuth2Client(_config, _httpClient);

            // Act & Assert
            var ex = await Assert.ThrowsAsync<OAuth2Exception>(
                () => client.FetchOpenIdConfigurationAsync());
            Assert.Contains("does not match the configured issuer", ex.Message);
        }

        [Fact]
        public async Task FetchOpenIdConfigurationAsync_ThrowsOAuth2Exception_WhenIssuerPathCasingDiffers()
        {
            // Unlike the host, the path of an issuer identifier is case-sensitive.
            // Arrange
            var baseUrl = new Uri("https://example.okta.com/oauth2/default");
            RespondWithOpenIdConfiguration("https://example.okta.com/oauth2/Default");

            var client = new OAuth2Client(TestHelpers.CreateOAuth2ClientConfiguration(baseUrl), _httpClient);

            // Act & Assert
            var ex = await Assert.ThrowsAsync<OAuth2Exception>(
                () => client.FetchOpenIdConfigurationAsync());
            Assert.Contains("does not match the configured issuer", ex.Message);
        }

        [Fact]
        public async Task FetchOpenIdConfigurationAsync_Succeeds_WhenIssuerDiffersOnlyByTrailingSlash()
        {
            // Arrange
            var baseUrl = new Uri("https://example.okta.com/oauth2/default");
            RespondWithOpenIdConfiguration("https://example.okta.com/oauth2/default/");

            var client = new OAuth2Client(TestHelpers.CreateOAuth2ClientConfiguration(baseUrl), _httpClient);

            // Act
            var config = await client.FetchOpenIdConfigurationAsync();

            // Assert
            Assert.Equal("https://example.okta.com/oauth2/default/", config.Issuer.ToString());
        }

        [Fact]
        public async Task FetchOpenIdConfigurationAsync_Succeeds_WhenIssuerDiffersOnlyByHostCasing()
        {
            // Arrange
            RespondWithOpenIdConfiguration("https://EXAMPLE.com");

            var client = new OAuth2Client(_config, _httpClient);

            // Act
            var config = await client.FetchOpenIdConfigurationAsync();

            // Assert
            Assert.NotNull(config);
        }

        [Fact]
        public async Task FetchOpenIdConfigurationAsync_ThrowsOAuth2Exception_WhenIssuerIsNull()
        {
            // [JsonRequired] on OpenIdConfiguration.Issuer enforces presence, not non-null, so an
            // explicit null still deserializes and must be reported as an OAuth2Exception rather
            // than surfacing as a NullReferenceException from the issuer comparison.
            // Arrange
            _mockHandler.HandlerFunc = (request, cancellationToken) =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(@"{
                        ""issuer"": null,
                        ""token_endpoint"": ""https://example.com/v1/token"",
                        ""jwks_uri"": ""https://example.com/v1/keys""
                    }"),
                });

            var client = new OAuth2Client(_config, _httpClient);

            // Act & Assert
            var ex = await Assert.ThrowsAsync<OAuth2Exception>(
                () => client.FetchOpenIdConfigurationAsync());
            Assert.Contains("does not declare an issuer", ex.Message);
        }

        [Theory]
        [InlineData("https://example.com?foo=1")]
        [InlineData("https://example.com#fragment")]
        public async Task FetchOpenIdConfigurationAsync_ThrowsOAuth2Exception_WhenIssuerHasQueryOrFragment(string issuer)
        {
            // Arrange
            RespondWithOpenIdConfiguration(issuer);

            var client = new OAuth2Client(_config, _httpClient);

            // Act & Assert
            var ex = await Assert.ThrowsAsync<OAuth2Exception>(
                () => client.FetchOpenIdConfigurationAsync());
            Assert.Contains("contains a query or a fragment", ex.Message);
        }

        [Fact]
        public async Task JwksAsync_ThrowsOAuth2Exception_WhenIssuerDoesNotMatch()
        {
            // A mismatched discovery document must not be able to nominate the signing keys,
            // so the issuer check has to reject it before the jwks_uri it declares is ever fetched.
            // Arrange
            var jwksRequested = false;
            _mockHandler.HandlerFunc = (request, cancellationToken) =>
            {
                if (request.RequestUri!.AbsolutePath.Contains("jwks"))
                {
                    jwksRequested = true;
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(@"{
                        ""issuer"": ""https://attacker.example.net"",
                        ""token_endpoint"": ""https://attacker.example.net/token"",
                        ""jwks_uri"": ""https://attacker.example.net/jwks""
                    }"),
                });
            };

            var client = new OAuth2Client(_config, _httpClient);

            // Act & Assert
            await Assert.ThrowsAsync<OAuth2Exception>(() => client.JwksAsync());
            Assert.False(jwksRequested);
        }

        private void RespondWithOpenIdConfiguration(string issuer)
        {
            _mockHandler.HandlerFunc = (request, cancellationToken) =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent($@"{{
                        ""issuer"": ""{issuer}"",
                        ""token_endpoint"": ""{issuer}/v1/token"",
                        ""jwks_uri"": ""{issuer}/v1/keys""
                    }}"),
                });
        }

        [Fact]
        public async Task RevokeAsync_ThrowsOAuth2Exception_OnNonSuccessResponse()
        {
            // Arrange
            var token = TestHelpers.CreateToken();
            var revocationEndpoint = new Uri("https://example.com/revoke");

            var openIdConfigJson = $@"{{
                ""issuer"": ""{TestHelpers.ExampleUri}"",
                ""token_endpoint"": ""{TestHelpers.ExampleTokenEndpoint}"",
                ""jwks_uri"": ""{TestHelpers.ExampleJwksEndpoint}"",
                ""revocation_endpoint"": ""{revocationEndpoint}""
            }}";

            _mockHandler.HandlerFunc = (request, cancellationToken) =>
            {
                if (request.RequestUri?.ToString().Contains("/.well-known/openid-configuration") == true)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(openIdConfigJson),
                    });
                }
                else if (request.RequestUri == revocationEndpoint)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest)
                    {
                        ReasonPhrase = "Bad Request",
                    });
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            };

            var client = new OAuth2Client(_config, _httpClient);

            // Act & Assert
            var ex = await Assert.ThrowsAsync<OAuth2Exception>(
                () => client.RevokeAsync(token, TokenRevokeType.Access));
            Assert.NotNull(ex.Message);
        }

        [Fact]
        public async Task RevokeAsync_RevokesAccessToken_WhenNoRefreshTokenAndTypeIsAll()
        {
            // Arrange
            var token = TestHelpers.CreateToken(refreshToken: null);
            var revocationEndpoint = new Uri("https://example.com/revoke");

            var openIdConfigJson = $@"{{
                ""issuer"": ""{TestHelpers.ExampleUri}"",
                ""token_endpoint"": ""{TestHelpers.ExampleTokenEndpoint}"",
                ""jwks_uri"": ""{TestHelpers.ExampleJwksEndpoint}"",
                ""revocation_endpoint"": ""{revocationEndpoint}""
            }}";

            int requestCount = 0;
            _mockHandler.HandlerFunc = (request, cancellationToken) =>
            {
                if (request.RequestUri?.ToString().Contains("/.well-known/openid-configuration") == true)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(openIdConfigJson),
                    });
                }
                else if (request.RequestUri == revocationEndpoint)
                {
                    requestCount++;
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            };

            var client = new OAuth2Client(_config, _httpClient);

            // Act
            await client.RevokeAsync(token, TokenRevokeType.All);

            // Assert - Should only revoke access token (1 request)
            Assert.Equal(1, requestCount);
        }

        [Fact]
        public async Task RevokeAsync_RevokesBothTokens_WhenRefreshTokenExistsAndTypeIsAll()
        {
            // Arrange
            var token = TestHelpers.CreateToken(
                accessToken: "test-access",
                refreshToken: "test-refresh");
            var revocationEndpoint = new Uri("https://example.com/revoke");

            var openIdConfigJson = $@"{{
                ""issuer"": ""{TestHelpers.ExampleUri}"",
                ""token_endpoint"": ""{TestHelpers.ExampleTokenEndpoint}"",
                ""jwks_uri"": ""{TestHelpers.ExampleJwksEndpoint}"",
                ""revocation_endpoint"": ""{revocationEndpoint}""
            }}";

            int requestCount = 0;
            _mockHandler.HandlerFunc = (request, cancellationToken) =>
            {
                if (request.RequestUri?.ToString().Contains("/.well-known/openid-configuration") == true)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(openIdConfigJson),
                    });
                }
                else if (request.RequestUri == revocationEndpoint)
                {
                    requestCount++;
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            };

            var client = new OAuth2Client(_config, _httpClient);

            // Act
            await client.RevokeAsync(token, TokenRevokeType.All);

            // Assert - Should revoke both access and refresh tokens (2 requests)
            Assert.Equal(2, requestCount);
        }

        [Fact]
        public async Task RefreshAsync_SendsCorrectRequest()
        {
            var token = TestHelpers.CreateToken(refreshToken: "test-refresh-token");
            var scope = new List<string> { "openid", "profile" };
            var tokenEndpoint = new Uri("https://example.com/oauth2/v1/token");

            var openIdConfigJson = $@"{{
                ""issuer"": ""{TestHelpers.ExampleUri}"",
                ""token_endpoint"": ""{tokenEndpoint}"",
                ""jwks_uri"": ""{TestHelpers.ExampleJwksEndpoint}""
            }}";

            var tokenJson = @"{
                ""access_token"": ""new-access-token"",
                ""token_type"": ""Bearer"",
                ""expires_in"": 3600,
                ""refresh_token"": ""new-refresh-token""
            }";

            HttpRequestMessage? capturedRequest = null;
            _mockHandler.HandlerFunc = (request, cancellationToken) =>
            {
                if (request.RequestUri?.ToString().Contains("/.well-known/openid-configuration") == true)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(openIdConfigJson),
                    });
                }
                else if (request.RequestUri == tokenEndpoint)
                {
                    capturedRequest = request;
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(tokenJson),
                    });
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            };

            var client = new OAuth2Client(_config, _httpClient);

            TokenRefreshedEventArgs? eventArgs = null;
            client.TokenRefreshed += (sender, args) => eventArgs = args;

            var response = await client.RefreshAsync(token, scope);

            Assert.NotNull(capturedRequest);
            Assert.Equal(HttpMethod.Post, capturedRequest.Method);
            Assert.Equal(tokenEndpoint, capturedRequest.RequestUri);

            var content = await capturedRequest.Content!.ReadAsStringAsync();
            Assert.Contains("grant_type=refresh_token", content);
            Assert.Contains("refresh_token=test-refresh-token", content);
            Assert.Contains($"client_id={TestHelpers.DefaultClientId}", content);
            Assert.Contains("scope=openid+profile", content);
            Assert.NotNull(eventArgs);
            Assert.Same(token, eventArgs.OldToken);
            Assert.Same(response.Result, eventArgs.NewToken);
            _mockAuth.Received(1).AddAuthentication(Arg.Any<HttpRequestMessage>(), TestHelpers.DefaultClientId, Arg.Any<Dictionary<string, string>>());
        }

        [Fact]
        public async Task RefreshAsync_ReturnsNewToken_OnSuccessResponse()
        {
            var token = TestHelpers.CreateToken(refreshToken: "test-refresh-token");
            var scope = new List<string> { "openid", "profile" };
            var tokenEndpoint = new Uri("https://example.com/oauth2/v1/token");

            var openIdConfigJson = $@"{{
                ""issuer"": ""{TestHelpers.ExampleUri}"",
                ""token_endpoint"": ""{tokenEndpoint}"",
                ""jwks_uri"": ""{TestHelpers.ExampleJwksEndpoint}""
            }}";

            var tokenJson = @"{
                ""access_token"": ""new-access-token"",
                ""token_type"": ""Bearer"",
                ""expires_in"": 7200,
                ""refresh_token"": ""new-refresh-token""
            }";

            _mockHandler.HandlerFunc = (request, cancellationToken) =>
            {
                if (request.RequestUri?.ToString().Contains("/.well-known/openid-configuration") == true)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(openIdConfigJson),
                    });
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(tokenJson),
                });
            };

            var client = new OAuth2Client(_config, _httpClient);

            var response = await client.RefreshAsync(token, scope);

            Assert.True(response.IsSuccess);
            Assert.NotNull(response.Result);
            Assert.Equal("new-access-token", response.Result.AccessToken);
            Assert.Equal("Bearer", response.Result.TokenType);
            Assert.InRange(response.Result.ExpiresIn, 7195, 7200);
            Assert.Equal("new-refresh-token", response.Result.RefreshToken);
        }

        [Fact]
        public async Task RefreshAsync_ThrowsInvalidOperationException_WhenNoRefreshToken()
        {
            var token = TestHelpers.CreateToken(refreshToken: null);
            var scope = new List<string> { "openid" };
            var client = new OAuth2Client(_config, _httpClient);
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(
                () => client.RefreshAsync(token, scope));
            Assert.Equal("No refresh token available", ex.Message);
        }

        [Fact]
        public async Task RefreshAsync_ThrowsInvalidOperationException_WhenRefreshTokenIsEmpty()
        {
            var token = TestHelpers.CreateToken(refreshToken: string.Empty);
            var scope = new List<string> { "openid" };
            var client = new OAuth2Client(_config, _httpClient);
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(
                () => client.RefreshAsync(token, scope));
            Assert.Equal("No refresh token available", ex.Message);
        }

        [Fact]
        public async Task RefreshAsync_ReturnsFailedResponse_OnNonSuccessResponse()
        {
            var token = TestHelpers.CreateToken(refreshToken: "test-refresh-token");
            var scope = new List<string> { "openid" };
            var tokenEndpoint = new Uri("https://example.com/oauth2/v1/token");

            var openIdConfigJson = $@"{{
                ""issuer"": ""{TestHelpers.ExampleUri}"",
                ""token_endpoint"": ""{tokenEndpoint}"",
                ""jwks_uri"": ""{TestHelpers.ExampleJwksEndpoint}""
            }}";

            _mockHandler.HandlerFunc = (request, cancellationToken) =>
            {
                if (request.RequestUri?.ToString().Contains("/.well-known/openid-configuration") == true)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(openIdConfigJson),
                    });
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent(@"{""error"": ""invalid_grant""}"),
                });
            };

            var client = new OAuth2Client(_config, _httpClient);

            var response = await client.RefreshAsync(token, scope);

            Assert.False(response.IsSuccess);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        [Fact]
        public async Task RefreshAsync_ConcurrentCallsOnSameToken_ShareSingleRequest()
        {
            var token = TestHelpers.CreateToken(refreshToken: "test-refresh-token");
            var scope = new List<string> { "openid", "profile" };
            var tokenEndpoint = new Uri("https://example.com/oauth2/v1/token");

            var openIdConfigJson = $@"{{
                ""issuer"": ""{TestHelpers.ExampleUri}"",
                ""token_endpoint"": ""{tokenEndpoint}"",
                ""jwks_uri"": ""{TestHelpers.ExampleJwksEndpoint}""
            }}";

            var tokenJson = @"{
                ""access_token"": ""shared-access-token"",
                ""token_type"": ""Bearer"",
                ""expires_in"": 3600,
                ""refresh_token"": ""new-refresh-token""
            }";

            int requestCount = 0;
            var requestStarted = new TaskCompletionSource<bool>();
            var requestComplete = new TaskCompletionSource<bool>();

            _mockHandler.HandlerFunc = async (request, cancellationToken) =>
            {
                if (request.RequestUri?.ToString().Contains("/.well-known/openid-configuration") == true)
                {
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(openIdConfigJson),
                    };
                }
                else if (request.RequestUri == tokenEndpoint)
                {
                    Interlocked.Increment(ref requestCount);
                    requestStarted.TrySetResult(true);
                    await requestComplete.Task;
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(tokenJson),
                    };
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            };

            var client = new OAuth2Client(_config, _httpClient);

            var task1 = client.RefreshAsync(token, scope);
            await requestStarted.Task;

            var task2 = client.RefreshAsync(token, scope);
            var task3 = client.RefreshAsync(token, scope);

            requestComplete.SetResult(true);

            var responses = await Task.WhenAll(task1, task2, task3);

            Assert.Equal(1, requestCount);
            Assert.All(responses, r => Assert.True(r.IsSuccess));
            Assert.All(responses, r => Assert.Equal("shared-access-token", r.Result?.AccessToken));
        }

        [Fact]
        public async Task RefreshAsync_SequentialCalls_MakeSeparateRequests()
        {
            var token = TestHelpers.CreateToken(refreshToken: "test-refresh-token");
            var scope = new List<string> { "openid", "profile" };
            var tokenEndpoint = new Uri("https://example.com/oauth2/v1/token");

            var openIdConfigJson = $@"{{
                ""issuer"": ""{TestHelpers.ExampleUri}"",
                ""token_endpoint"": ""{tokenEndpoint}"",
                ""jwks_uri"": ""{TestHelpers.ExampleJwksEndpoint}""
            }}";

            int requestCount = 0;

            _mockHandler.HandlerFunc = (request, cancellationToken) =>
            {
                if (request.RequestUri?.ToString().Contains("/.well-known/openid-configuration") == true)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(openIdConfigJson),
                    });
                }
                else if (request.RequestUri == tokenEndpoint)
                {
                    var count = Interlocked.Increment(ref requestCount);
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent($@"{{
                            ""access_token"": ""access-token-{count}"",
                            ""token_type"": ""Bearer"",
                            ""expires_in"": 3600,
                            ""refresh_token"": ""new-refresh-token""
                        }}"),
                    });
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            };

            var client = new OAuth2Client(_config, _httpClient);

            var response1 = await client.RefreshAsync(token, scope);
            var response2 = await client.RefreshAsync(token, scope);
            var response3 = await client.RefreshAsync(token, scope);

            Assert.Equal(3, requestCount);
            Assert.Equal("access-token-1", response1.Result?.AccessToken);
            Assert.Equal("access-token-2", response2.Result?.AccessToken);
            Assert.Equal("access-token-3", response3.Result?.AccessToken);
        }

        [Fact]
        public async Task RefreshAsync_DifferentTokens_MakeSeparateRequests()
        {
            var token1 = TestHelpers.CreateToken(refreshToken: "refresh-token-1");
            var token2 = TestHelpers.CreateToken(refreshToken: "refresh-token-2");
            var scope = new List<string> { "openid", "profile" };
            var tokenEndpoint = new Uri("https://example.com/oauth2/v1/token");

            var openIdConfigJson = $@"{{
                ""issuer"": ""{TestHelpers.ExampleUri}"",
                ""token_endpoint"": ""{tokenEndpoint}"",
                ""jwks_uri"": ""{TestHelpers.ExampleJwksEndpoint}""
            }}";

            int requestCount = 0;
            var request1Started = new TaskCompletionSource<bool>();
            var request2Started = new TaskCompletionSource<bool>();
            var requestsComplete = new TaskCompletionSource<bool>();

            _mockHandler.HandlerFunc = async (request, cancellationToken) =>
            {
                if (request.RequestUri?.ToString().Contains("/.well-known/openid-configuration") == true)
                {
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(openIdConfigJson),
                    };
                }
                else if (request.RequestUri == tokenEndpoint)
                {
                    var count = Interlocked.Increment(ref requestCount);
                    if (count == 1)
                    {
                        request1Started.TrySetResult(true);
                    }

                    if (count == 2)
                    {
                        request2Started.TrySetResult(true);
                    }

                    await requestsComplete.Task;
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent($@"{{
                            ""access_token"": ""access-token-{count}"",
                            ""token_type"": ""Bearer"",
                            ""expires_in"": 3600,
                            ""refresh_token"": ""new-refresh-token""
                        }}"),
                    };
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            };

            var client = new OAuth2Client(_config, _httpClient);

            var task1 = client.RefreshAsync(token1, scope);
            await request1Started.Task;

            var task2 = client.RefreshAsync(token2, scope);
            await request2Started.Task;

            requestsComplete.SetResult(true);

            var response1 = await task1;
            var response2 = await task2;

            Assert.Equal(2, requestCount);
            Assert.NotSame(response1.Result, response2.Result);
        }

        [Fact]
        public async Task UserInfoAsync_ReturnsUserInfo_OnSuccess()
        {
            var token = TestHelpers.CreateToken(accessToken: "test-access-token");
            var userInfoEndpoint = new Uri("https://example.com/oauth2/v1/userinfo");

            var openIdConfigJson = $@"{{
                ""issuer"": ""{TestHelpers.ExampleUri}"",
                ""token_endpoint"": ""{TestHelpers.ExampleTokenEndpoint}"",
                ""jwks_uri"": ""{TestHelpers.ExampleJwksEndpoint}"",
                ""userinfo_endpoint"": ""{userInfoEndpoint}""
            }}";

            var userInfoJson = @"{
                ""sub"": ""user123"",
                ""name"": ""John Doe"",
                ""email"": ""john@example.com""
            }";

            HttpRequestMessage? capturedRequest = null;
            _mockHandler.HandlerFunc = (request, cancellationToken) =>
            {
                if (request.RequestUri?.ToString().Contains("/.well-known/openid-configuration") == true)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(openIdConfigJson),
                    });
                }
                else if (request.RequestUri == userInfoEndpoint)
                {
                    capturedRequest = request;
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(userInfoJson),
                    });
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            };

            var client = new OAuth2Client(_config, _httpClient);
            var response = await client.UserInfoAsync(token);

            Assert.True(response.IsSuccess);
            Assert.NotNull(response.Result);
            Assert.Equal("user123", response.Result.Subject());
            Assert.Equal("John Doe", response.Result.Name());
            Assert.Equal("john@example.com", response.Result.Email());

            Assert.NotNull(capturedRequest);
            Assert.Equal(HttpMethod.Get, capturedRequest.Method);
            Assert.Equal("Bearer test-access-token", capturedRequest.Headers.GetValues("Authorization").First());
        }

        [Fact]
        public async Task UserInfoAsync_ThrowsInvalidOperationException_WhenUserInfoEndpointMissing()
        {
            // Arrange
            var token = TestHelpers.CreateToken(accessToken: "test-access-token");

            var openIdConfigJson = $@"{{
                ""issuer"": ""{TestHelpers.ExampleUri}"",
                ""token_endpoint"": ""{TestHelpers.ExampleTokenEndpoint}"",
                ""jwks_uri"": ""{TestHelpers.ExampleJwksEndpoint}""
            }}";

            _mockHandler.HandlerFunc = (request, cancellationToken) =>
            {
                if (request.RequestUri?.ToString().Contains("/.well-known/openid-configuration") == true)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(openIdConfigJson),
                    });
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            };

            var client = new OAuth2Client(_config, _httpClient);

            // Act & Assert
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(
                () => client.UserInfoAsync(token));
            Assert.Contains("No userinfo endpoint found in the OpenID configuration", ex.Message);
        }

        [Fact]
        public async Task IntrospectAsync_ReturnsIntrospectResponse_OnSuccess()
        {
            var token = TestHelpers.CreateToken(accessToken: "test-access-token");
            var introspectionEndpoint = new Uri("https://example.com/oauth2/v1/introspect");

            var openIdConfigJson = $@"{{
                ""issuer"": ""{TestHelpers.ExampleUri}"",
                ""token_endpoint"": ""{TestHelpers.ExampleTokenEndpoint}"",
                ""jwks_uri"": ""{TestHelpers.ExampleJwksEndpoint}"",
                ""introspection_endpoint"": ""{introspectionEndpoint}""
            }}";

            var introspectJson = @"{
                ""active"": true,
                ""sub"": ""user123"",
                ""client_id"": ""clientId"",
                ""token_type"": ""Bearer"",
                ""scope"": ""openid profile""
            }";

            HttpRequestMessage? capturedRequest = null;
            _mockHandler.HandlerFunc = (request, cancellationToken) =>
            {
                if (request.RequestUri?.ToString().Contains("/.well-known/openid-configuration") == true)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(openIdConfigJson),
                    });
                }
                else if (request.RequestUri == introspectionEndpoint)
                {
                    capturedRequest = request;
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(introspectJson),
                    });
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            };

            var client = new OAuth2Client(_config, _httpClient);
            var response = await client.IntrospectAsync(token, Okta.AuthFoundation.TokenManagement.TokenKind.AccessToken);

            Assert.True(response.IsSuccess);
            Assert.NotNull(response.Result);
            Assert.True(response.Result.Active);
            Assert.Equal("user123", response.Result.Sub);
            Assert.Equal("clientId", response.Result.ClientId);
            Assert.Equal("openid profile", response.Result.Scope);

            Assert.NotNull(capturedRequest);
            Assert.Equal(HttpMethod.Post, capturedRequest.Method);

            var content = await capturedRequest.Content!.ReadAsStringAsync();
            Assert.Contains("token=test-access-token", content);
            Assert.Contains("token_type_hint=access_token", content);
            Assert.Contains($"client_id={TestHelpers.DefaultClientId}", content);
            _mockAuth.Received(1).AddAuthentication(Arg.Any<HttpRequestMessage>(), TestHelpers.DefaultClientId, Arg.Any<Dictionary<string, string>>());
        }

        [Fact]
        public async Task IntrospectAsync_ReturnsInactiveResponse_ForExpiredToken()
        {
            var token = TestHelpers.CreateToken(accessToken: "expired-token");
            var introspectionEndpoint = new Uri("https://example.com/oauth2/v1/introspect");

            var openIdConfigJson = $@"{{
                ""issuer"": ""{TestHelpers.ExampleUri}"",
                ""token_endpoint"": ""{TestHelpers.ExampleTokenEndpoint}"",
                ""jwks_uri"": ""{TestHelpers.ExampleJwksEndpoint}"",
                ""introspection_endpoint"": ""{introspectionEndpoint}""
            }}";

            _mockHandler.HandlerFunc = (request, cancellationToken) =>
            {
                if (request.RequestUri?.ToString().Contains("/.well-known/openid-configuration") == true)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(openIdConfigJson),
                    });
                }
                else if (request.RequestUri == introspectionEndpoint)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(@"{""active"": false}"),
                    });
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            };

            var client = new OAuth2Client(_config, _httpClient);
            var response = await client.IntrospectAsync(token, Okta.AuthFoundation.TokenManagement.TokenKind.AccessToken);

            Assert.True(response.IsSuccess);
            Assert.NotNull(response.Result);
            Assert.False(response.Result.Active);
        }

        [Fact]
        public async Task FetchOpenIdConfigurationAsync_UsesFullPathWhenBaseUrlHasPathSegment()
        {
            // Regression test for: new Uri(baseUrl, "/.well-known/openid-configuration")
            // strips the path segment when it starts with '/', causing the wrong discovery
            // URL (e.g. https://example.com/.well-known/... instead of
            // https://example.com/oauth2/default/.well-known/...).
            var baseUrl = new Uri("https://example.com/oauth2/default");
            var expectedDiscoveryUrl = "https://example.com/oauth2/default/.well-known/openid-configuration";

            Uri? actualRequestUri = null;
            _mockHandler.HandlerFunc = (request, cancellationToken) =>
            {
                actualRequestUri = request.RequestUri;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent($@"{{
                        ""issuer"": ""{baseUrl}"",
                        ""token_endpoint"": ""{baseUrl}/v1/token"",
                        ""jwks_uri"": ""{baseUrl}/v1/keys""
                    }}"),
                });
            };

            var config = new OAuth2ClientConfiguration(baseUrl, TestHelpers.DefaultClientId, null);
            var client = new OAuth2Client(config, _httpClient);
            await client.FetchOpenIdConfigurationAsync();

            Assert.Equal(expectedDiscoveryUrl, actualRequestUri?.ToString());
        }

        [Fact]
        public void OAuth2ClientConfiguration_ConvenienceConstructor_PreservesPathInDiscoveryUrl()
        {
            var baseUrl = new Uri("https://example.com/oauth2/default");
            var config = new OAuth2ClientConfiguration(baseUrl, TestHelpers.DefaultClientId, null);

            Assert.Equal(
                "https://example.com/oauth2/default/.well-known/openid-configuration",
                config.DiscoveryUrl.ToString());
        }

        [Fact]
        public void OAuth2Client_BaseUrlConstructor_DerivesSameDiscoveryUrlAsConfiguration()
        {
            var baseUrl = new Uri("https://example.com/oauth2/default/");
            var expected = new OAuth2ClientConfiguration(baseUrl, TestHelpers.DefaultClientId, null);

            using var client = new OAuth2Client(baseUrl, TestHelpers.DefaultClientId, new List<string>(), _httpClient);

            Assert.Equal(expected.BaseUrl.ToString(), client.Configuration.BaseUrl.ToString());
            Assert.Equal(expected.DiscoveryUrl.ToString(), client.Configuration.DiscoveryUrl.ToString());
        }

        [Theory]
        [InlineData("https://example.com?foo=1")]
        [InlineData("https://example.com/oauth2/default#fragment")]
        public void OAuth2ClientConfiguration_Throws_WhenBaseUrlHasQueryOrFragment(string baseUrl)
        {
            // An issuer identifier may contain neither, per OpenID Connect Core 1.0 section 2.
            var ex = Assert.Throws<ArgumentException>(
                () => new OAuth2ClientConfiguration(new Uri(baseUrl), TestHelpers.DefaultClientId, null));

            Assert.Equal("baseUrl", ex.ParamName);
        }

        [Theory]
        [InlineData("https://example.okta.com/oauth2/default", "https://example.okta.com/oauth2/default")]
        [InlineData("https://example.okta.com/oauth2/default//", "https://example.okta.com/oauth2/default")]
        [InlineData("https://example.okta.com", "https://example.okta.com/")]
        [InlineData("https://example.okta.com:8443/oauth2/default/", "https://example.okta.com:8443/oauth2/default")]
        [InlineData("http://localhost:1234/oauth2/default/", "http://localhost:1234/oauth2/default")]
        [InlineData("https://example.okta.com/OAuth2/Default/", "https://example.okta.com/OAuth2/Default")]
        public void OAuth2ClientConfiguration_CanonicalizesBaseUrl(string baseUrl, string expected)
        {
            var config = new OAuth2ClientConfiguration(new Uri(baseUrl), TestHelpers.DefaultClientId, null);

            Assert.Equal(expected, config.BaseUrl.ToString());
        }

        [Fact]
        public void OAuth2ClientConfiguration_CanonicalizationIsIdempotent()
        {
            var once = new OAuth2ClientConfiguration(
                new Uri("https://example.okta.com/oauth2/default///"), TestHelpers.DefaultClientId, null);
            var twice = new OAuth2ClientConfiguration(once.BaseUrl, TestHelpers.DefaultClientId, null);

            Assert.Equal(once.BaseUrl.ToString(), twice.BaseUrl.ToString());
            Assert.Equal(once.DiscoveryUrl.ToString(), twice.DiscoveryUrl.ToString());
        }

        [Theory]
        [InlineData("https://example.okta.com", "https://example.okta.com/.well-known/openid-configuration")]
        [InlineData("https://example.okta.com/oauth2/default", "https://example.okta.com/oauth2/default/.well-known/openid-configuration")]
        [InlineData("https://example.okta.com/oauth2/default/", "https://example.okta.com/oauth2/default/.well-known/openid-configuration")]
        public void OAuth2ClientConfiguration_DerivesDiscoveryUrlStructurally(string baseUrl, string expected)
        {
            var config = new OAuth2ClientConfiguration(new Uri(baseUrl), TestHelpers.DefaultClientId, null);

            Assert.Equal(expected, config.DiscoveryUrl.ToString());
        }

        [Fact]
        public void OAuth2ClientConfiguration_Throws_WhenBaseUrlIsRelative()
        {
            var ex = Assert.Throws<ArgumentException>(
                () => new OAuth2ClientConfiguration(
                    new Uri("oauth2/default", UriKind.Relative), TestHelpers.DefaultClientId, null));

            Assert.Equal("baseUrl", ex.ParamName);
            Assert.Contains("must be an absolute URL", ex.Message);
        }

        [Fact]
        public void OAuth2ClientConfiguration_Throws_WhenBaseUrlIsNull()
        {
            var ex = Assert.Throws<ArgumentNullException>(
                () => new OAuth2ClientConfiguration(null!, TestHelpers.DefaultClientId, null));

            Assert.Equal("baseUrl", ex.ParamName);
        }
    }
}