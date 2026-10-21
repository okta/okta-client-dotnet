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
using System.Net;
using System.Threading.Tasks;
using NSubstitute;
using Okta.AuthFoundation.OAuth2;
using Okta.AuthFoundation.TokenManagement;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    public class CredentialCoordinatorTests : IDisposable
    {
        private readonly ITokenStorage _storage;
        private readonly ICredentialDataSource _dataSource;
        private readonly CredentialCoordinator _coordinator;
        private readonly OAuth2ClientConfiguration _config;
        private readonly OAuth2Client _client;

        public CredentialCoordinatorTests()
        {
            _storage = Substitute.For<ITokenStorage>();
            _dataSource = Substitute.For<ICredentialDataSource>();
            _coordinator = new CredentialCoordinator(_storage, _dataSource);
            _config = TestHelpers.CreateOAuth2ClientConfiguration();
            _client = new OAuth2Client(_config);
        }

        public void Dispose()
        {
            _coordinator.Dispose();
            GC.SuppressFinalize(this);
        }

        [Fact]
        public async Task Store_AddsTokenToStorage()
        {
            var token = TestHelpers.CreateToken();
            _storage.AllIdsAsync().Returns(Task.FromResult<List<string>>(new List<string>()));
            _storage.SetDefaultTokenIdAsync(Arg.Any<string?>()).Returns(Task.CompletedTask);

            var metadata = TestHelpers.CreateTokenMetadata(token, new Dictionary<string, string> { ["example"] = "example" });
            _dataSource.For(Arg.Any<Token>(), Arg.Any<TokenMetadata?>())
                .Returns(new Credential(token, _client, metadata));

            await _coordinator.StoreAsync(token);

            await _storage.Received().AddAsync(token, Arg.Any<TokenMetadata?>());
        }

        [Fact]
        public async Task Store_AlwaysPassesFullMetadataWithClaimsToStorage()
        {
            var idToken = TestHelpers.CreateIdToken(subject: "user-123");
            var token = TestHelpers.CreateToken(idToken: idToken);
            _storage.AllIdsAsync().Returns(Task.FromResult<List<string>>(new List<string>()));
            _storage.SetDefaultTokenIdAsync(Arg.Any<string?>()).Returns(Task.CompletedTask);

            TokenMetadata? capturedMetadata = null;
            _storage.AddAsync(Arg.Any<Token>(), Arg.Do<TokenMetadata?>(m => capturedMetadata = m))
                    .Returns(Task.CompletedTask);
            _dataSource.For(Arg.Any<Token>(), Arg.Any<TokenMetadata?>())
                       .Returns(c => new Credential(c.ArgAt<Token>(0), _client, c.ArgAt<TokenMetadata?>(1)!));

            await _coordinator.StoreAsync(token);

            Assert.NotNull(capturedMetadata);
            Assert.NotNull(capturedMetadata!.Claims);
        }

        [Fact]
        public async Task With_ReturnsCredentialIfExists()
        {
            var token = TestHelpers.CreateToken(id: "id2");
            var metadata = TestHelpers.CreateTokenMetadata(token, new Dictionary<string, string> { ["tag3"] = "tag3" });
            var credential = new Credential(token, _client, metadata);

            _storage.GetAsync("id2").Returns(Task.FromResult<Token?>(token));
            _dataSource.For(token, Arg.Any<TokenMetadata?>()).Returns(credential);

            var result = await _coordinator.WithAsync("id2");

            Assert.Equal(credential, result);
        }

        [Fact]
        public async Task Find_FiltersByPredicate()
        {
            var token = TestHelpers.CreateToken(id: "id3");
            var metadata = TestHelpers.CreateTokenMetadata(token, new Dictionary<string, string> { ["tag3"] = "tag3" });
            var credential = new Credential(token, _client, metadata);

            _storage.AllIdsAsync().Returns(new List<string> { "id3" });
            _storage.GetMetadataAsync("id3").Returns(metadata);
            _storage.GetAsync("id3").Returns(token);
            _dataSource.For(token, metadata).Returns(credential);

            var results = await _coordinator.FindAsync(m => m.Tags?.ContainsKey("tag3") == true);

            Assert.Single(results);
            Assert.Equal(credential, results[0]);
        }

        [Fact]
        public async Task GetDefaultAsync_ReturnsDefaultCredential_IfAlreadySet()
        {
            var token = TestHelpers.CreateToken();
            var metadata = TestHelpers.CreateTokenMetadata(token);
            var credential = new Credential(token, _client, metadata);

            await _coordinator.SetDefaultAsync(credential);
            var result = await _coordinator.GetDefaultAsync();

            Assert.Equal(credential, result);
        }

        [Fact]
        public async Task GetDefaultAsync_ReturnsCredentialFromStorage_IfDefaultIdSet()
        {
            _storage.GetDefaultTokenIdAsync().Returns("id1");

            var token = TestHelpers.CreateToken(id: "id1");
            var metadata = TestHelpers.CreateTokenMetadata(token);
            var credential = new Credential(token, _client, metadata);

            _storage.GetAsync("id1").Returns(token);
            _dataSource.For(token, Arg.Any<TokenMetadata?>()).Returns(credential);

            var result = await _coordinator.GetDefaultAsync();

            Assert.Equal(credential, result);
        }

        [Fact]
        public async Task GetDefaultAsync_ReturnsNull_IfNoDefault()
        {
            _storage.GetDefaultTokenIdAsync().Returns((string?)null);

            var result = await _coordinator.GetDefaultAsync();

            Assert.Null(result);
        }

        [Fact]
        public async Task SetDefaultAsync_SetsGivenCredential()
        {
            _storage.AllIdsAsync().Returns(new List<string> { "id1" });

            var token = TestHelpers.CreateToken(id: "id1");
            var metadata = TestHelpers.CreateTokenMetadata(token);
            var credential = new Credential(token, _client, metadata);

            _storage.GetAsync("id1").Returns(token);
            _dataSource.For(token, Arg.Any<TokenMetadata?>()).Returns(credential);

            await _coordinator.SetDefaultAsync(credential);

            Assert.Equal(credential, await _coordinator.GetDefaultAsync());
        }

        [Fact]
        public async Task SetDefaultAsync_NullClearsDefault()
        {
            await _coordinator.SetDefaultAsync(null);

            await _storage.Received().SetDefaultTokenIdAsync(null);
        }

        [Fact]
        public async Task RemoveAsync_RemovesCredentialFromStorageAndDataSource()
        {
            var token = TestHelpers.CreateToken(id: "id1");
            var metadata = TestHelpers.CreateTokenMetadata(token);
            var credential = new Credential(token, _client, metadata);

            await _coordinator.RemoveAsync(credential);

            await _storage.Received().RemoveAsync("id1");
            _dataSource.Received().Remove(credential);
        }

        [Fact]
        public async Task ClearAsync_ClearsStorageAndDataSource()
        {
            await _coordinator.ClearAsync();

            await _storage.Received().ClearAsync();
            _dataSource.Received().Clear();
        }

        [Fact]
        public async Task CredentialAdded_SubscribesToTokenRefreshedOnClient()
        {
            var replaceCalledTcs = new TaskCompletionSource<bool>();
            var storage = Substitute.For<ITokenStorage>();
            storage.ReplaceAsync(Arg.Any<string>(), Arg.Any<Token>())
                   .Returns(Task.CompletedTask)
                   .AndDoes(_ => replaceCalledTcs.TrySetResult(true));

            var tokenEndpoint = new Uri("https://example.com/oauth2/v1/token");
            var openIdConfigJson = $@"{{
                ""issuer"": ""{TestHelpers.ExampleUri}"",
                ""token_endpoint"": ""{tokenEndpoint}"",
                ""jwks_uri"": ""{TestHelpers.ExampleJwksEndpoint}""
            }}";

            var newTokenJson = @"{
                ""access_token"": ""new-access-token"",
                ""token_type"": ""Bearer"",
                ""expires_in"": 3600,
                ""refresh_token"": ""new-refresh-token""
            }";

            var mockHandler = new TestHttpMessageHandler((request, cancellationToken) =>
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
                    Content = new StringContent(newTokenJson),
                });
            });
            var httpClient = new HttpClient(mockHandler);
            var config = TestHelpers.CreateOAuth2ClientConfiguration();
            var client = new OAuth2Client(config, httpClient);
            var oldToken = TestHelpers.CreateToken(
                id: "test-token-id",
                refreshToken: "old-refresh-token",
                context: TestHelpers.CreateTokenContext());
            var metadata = TestHelpers.CreateTokenMetadata(oldToken);
            var credential = new Credential(oldToken, client, metadata);

            var dataSource = new TestCredentialDataSource(credential);
            var coordinator = new CredentialCoordinator(storage, dataSource);

            dataSource.For(oldToken, metadata);

            await credential.Client.RefreshAsync(oldToken, new List<string> { "openid" });

            var completed = await Task.WhenAny(replaceCalledTcs.Task, Task.Delay(5000));
            Assert.True(completed == replaceCalledTcs.Task, "ReplaceAsync was not called within timeout");

            await storage.Received().ReplaceAsync("test-token-id", Arg.Any<Token>());
        }
    }
}
