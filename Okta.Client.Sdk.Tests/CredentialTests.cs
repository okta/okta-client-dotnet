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

using System.Text.Json;
using NSubstitute;
using Okta.AuthFoundation;
using Okta.AuthFoundation.Claims;
using Okta.AuthFoundation.Http;
using Okta.AuthFoundation.OAuth2;
using Okta.AuthFoundation.TokenManagement;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    public class CredentialTests
    {
        private readonly ICredentialCoordinator _mockCoordinator;
        private readonly OAuth2Client _mockClient;
        private readonly Token _token;
        private readonly TokenMetadata _metadata;

        public CredentialTests()
        {
            _mockCoordinator = Substitute.For<ICredentialCoordinator>();
            _mockClient = Substitute.ForPartsOf<OAuth2Client>(
                TestHelpers.CreateOAuth2ClientConfiguration(),
                null,
                null,
                null,
                null);
            _token = TestHelpers.CreateToken();
            _metadata = TestHelpers.CreateTokenMetadata(_token);

            TestableCredential.SetCoordinator(_mockCoordinator);
        }

        private sealed class TestableCredential : Credential
        {
            public TestableCredential(Token token, OAuth2Client client, TokenMetadata metadata)
                : base(token, client, metadata)
            {
            }

            public static void SetCoordinator(ICredentialCoordinator coordinator)
            {
                Coordinator = coordinator;
            }
        }

        [Fact]
        public async Task StoreAsync_CallsCoordinatorStoreAsync()
        {
            var expectedCredential = new Credential(_token, _mockClient, _metadata);
            _mockCoordinator.StoreAsync(_token, null).Returns(Task.FromResult(expectedCredential));

            var result = await Credential.StoreAsync(_token);

            await _mockCoordinator.Received(1).StoreAsync(_token, null);
            Assert.Equal(expectedCredential, result);
        }

        [Fact]
        public async Task StoreAsync_WithTags_CallsCoordinatorStoreAsync()
        {
            var tags = new Dictionary<string, string> { ["env"] = "prod", ["app"] = "mobile" };
            var expectedCredential = new Credential(_token, _mockClient, _metadata);
            _mockCoordinator.StoreAsync(_token, tags).Returns(Task.FromResult(expectedCredential));

            var result = await Credential.StoreAsync(_token, tags);

            await _mockCoordinator.Received(1).StoreAsync(_token, tags);
            Assert.Equal(expectedCredential, result);
        }

        [Fact]
        public async Task AllIDs_CallsCoordinatorAllIdsAsync()
        {
            var expectedIds = new List<string> { "id1", "id2", "id3" };
            _mockCoordinator.AllIdsAsync().Returns(Task.FromResult(expectedIds));

            var result = await Credential.AllIDsAsync();

            await _mockCoordinator.Received(1).AllIdsAsync();
            Assert.Equal(expectedIds, result);
        }

        [Fact]
        public async Task DefaultCredentialAsync_CallsCoordinatorGetDefaultAsync()
        {
            var expectedCredential = new Credential(_token, _mockClient, _metadata);
            _mockCoordinator.GetDefaultAsync().Returns(Task.FromResult<Credential?>(expectedCredential));

            var result = await Credential.GetDefaultAsync();

            await _mockCoordinator.Received(1).GetDefaultAsync();
            Assert.Equal(expectedCredential, result);
        }

        [Fact]
        public async Task DefaultCredentialAsync_ReturnsNull_WhenNoDefault()
        {
            _mockCoordinator.GetDefaultAsync().Returns(Task.FromResult<Credential?>(null));

            var result = await Credential.GetDefaultAsync();

            await _mockCoordinator.Received(1).GetDefaultAsync();
            Assert.Null(result);
        }

        [Fact]
        public async Task WithIdAsync_CallsCoordinatorWithAsync()
        {
            var id = "test-id";
            var expectedCredential = new Credential(_token, _mockClient, _metadata);
            _mockCoordinator.WithAsync(id).Returns(Task.FromResult<Credential?>(expectedCredential));

            var result = await Credential.WithIdAsync(id);

            await _mockCoordinator.Received(1).WithAsync(id);
            Assert.Equal(expectedCredential, result);
        }

        [Fact]
        public async Task WithIdAsync_ReturnsNull_WhenCredentialNotFound()
        {
            var id = "non-existent-id";
            _mockCoordinator.WithAsync(id).Returns(Task.FromResult<Credential?>(null));

            var result = await Credential.WithIdAsync(id);

            await _mockCoordinator.Received(1).WithAsync(id);
            Assert.Null(result);
        }

        [Fact]
        public async Task FindAsync_CallsCoordinatorFindAsync()
        {
            Func<TokenMetadata, bool> predicate = m => m.Tags?.ContainsKey("tag") == true;
            var expectedCredentials = new List<Credential>
            {
                new Credential(_token, _mockClient, _metadata),
            };
            _mockCoordinator.FindAsync(predicate).Returns(Task.FromResult(expectedCredentials));

            var result = await Credential.FindAsync(predicate);

            await _mockCoordinator.Received(1).FindAsync(predicate);
            Assert.Equal(expectedCredentials, result);
        }

        [Fact]
        public async Task FindAsync_ReturnsEmptyList_WhenNoMatches()
        {
            Func<TokenMetadata, bool> predicate = m => m.Tags?.ContainsKey("non-existent-tag") == true;
            var expectedCredentials = new List<Credential>();
            _mockCoordinator.FindAsync(predicate).Returns(Task.FromResult(expectedCredentials));

            var result = await Credential.FindAsync(predicate);

            await _mockCoordinator.Received(1).FindAsync(predicate);
            Assert.Empty(result);
        }

        [Fact]
        public void Tags_Property_ReadsFromMetadata()
        {
            var tags = new Dictionary<string, string> { ["env"] = "prod" };
            var metadata = new TokenMetadata(_token, tags);
            var credential = new TestableCredential(_token, _mockClient, metadata);

            Assert.Equal("prod", credential.Tags?["env"]);
        }

        [Fact]
        public async Task SetTagsAsync_UpdatesTagsAndPersistsToStorage()
        {
            _mockCoordinator.UpdateTagsAsync(Arg.Any<Credential>(), Arg.Any<Dictionary<string, string>?>()).Returns(Task.CompletedTask);
            var credential = new TestableCredential(_token, _mockClient, _metadata);

            var newTags = new Dictionary<string, string> { ["env"] = "staging" };
            await credential.SetTagsAsync(newTags);

            Assert.Equal("staging", credential.Tags?["env"]);
            await _mockCoordinator.Received(1).UpdateTagsAsync(credential, newTags);
        }

        [Fact]
        public async Task SetTagsAsync_WithNull_ClearsTags()
        {
            _mockCoordinator.UpdateTagsAsync(Arg.Any<Credential>(), Arg.Any<Dictionary<string, string>?>()).Returns(Task.CompletedTask);
            var metadata = new TokenMetadata(_token, new Dictionary<string, string> { ["env"] = "prod" });
            var credential = new TestableCredential(_token, _mockClient, metadata);

            await credential.SetTagsAsync(null);

            Assert.Null(credential.Tags);
        }

        [Fact]
        public async Task RevokeAsync_CallsClientRevokeAsync_WithAccessType()
        {
            _mockClient.When(x => x.RevokeAsync(_token, TokenRevokeType.Access)).DoNotCallBase();
            _mockClient.RevokeAsync(_token, TokenRevokeType.Access).Returns(Task.CompletedTask);
            var credential = new Credential(_token, _mockClient, _metadata);

            await credential.RevokeAsync(TokenRevokeType.Access);

            await _mockClient.Received(1).RevokeAsync(_token, TokenRevokeType.Access);
        }

        [Fact]
        public async Task RevokeAsync_CallsClientRevokeAsync_WithRefreshType()
        {
            var tokenWithRefresh = TestHelpers.CreateToken(refreshToken: "refresh-token");
            _mockClient.When(x => x.RevokeAsync(tokenWithRefresh, TokenRevokeType.Refresh)).DoNotCallBase();
            _mockClient.RevokeAsync(tokenWithRefresh, TokenRevokeType.Refresh).Returns(Task.CompletedTask);
            var credential = new Credential(tokenWithRefresh, _mockClient, _metadata);

            await credential.RevokeAsync(TokenRevokeType.Refresh);

            await _mockClient.Received(1).RevokeAsync(tokenWithRefresh, TokenRevokeType.Refresh);
        }

        [Fact]
        public async Task RevokeAsync_CallsClientRevokeAsync_WithAllType()
        {
            _mockClient.When(x => x.RevokeAsync(_token, TokenRevokeType.All)).DoNotCallBase();
            _mockClient.RevokeAsync(_token, TokenRevokeType.All).Returns(Task.CompletedTask);
            var credential = new Credential(_token, _mockClient, _metadata);

            await credential.RevokeAsync(TokenRevokeType.All);

            await _mockClient.Received(1).RevokeAsync(_token, TokenRevokeType.All);
        }

        [Fact]
        public async Task RevokeAsync_DefaultsToAllType()
        {
            _mockClient.When(x => x.RevokeAsync(_token, TokenRevokeType.All)).DoNotCallBase();
            _mockClient.RevokeAsync(_token, TokenRevokeType.All).Returns(Task.CompletedTask);
            var credential = new Credential(_token, _mockClient, _metadata);

            await credential.RevokeAsync();

            await _mockClient.Received(1).RevokeAsync(_token, TokenRevokeType.All);
        }

        [Fact]
        public async Task RevokeAsync_CallsCoordinatorRemoveAsync_WhenTypeIsAll()
        {
            _mockClient.When(x => x.RevokeAsync(_token, TokenRevokeType.All)).DoNotCallBase();
            _mockClient.RevokeAsync(_token, TokenRevokeType.All).Returns(Task.CompletedTask);
            _mockCoordinator.RemoveAsync(Arg.Any<Credential>()).Returns(Task.CompletedTask);
            var credential = new Credential(_token, _mockClient, _metadata);

            await credential.RevokeAsync(TokenRevokeType.All);

            await _mockCoordinator.Received(1).RemoveAsync(credential);
        }

        [Fact]
        public async Task RevokeAsync_CallsCoordinatorRemoveAsync_WhenAccessTokenOnlyAndTypeIsAccess()
        {
            var tokenWithoutRefresh = TestHelpers.CreateToken(refreshToken: null);
            _mockClient.When(x => x.RevokeAsync(tokenWithoutRefresh, TokenRevokeType.Access)).DoNotCallBase();
            _mockClient.RevokeAsync(tokenWithoutRefresh, TokenRevokeType.Access).Returns(Task.CompletedTask);
            _mockCoordinator.RemoveAsync(Arg.Any<Credential>()).Returns(Task.CompletedTask);
            var credential = new Credential(tokenWithoutRefresh, _mockClient, _metadata);

            await credential.RevokeAsync(TokenRevokeType.Access);

            await _mockCoordinator.Received(1).RemoveAsync(credential);
        }

        [Fact]
        public async Task RevokeAsync_DoesNotCallCoordinatorRemoveAsync_WhenAccessTypeAndRefreshTokenExists()
        {
            var tokenWithRefresh = TestHelpers.CreateToken(refreshToken: "refresh-token");
            _mockClient.When(x => x.RevokeAsync(tokenWithRefresh, TokenRevokeType.Access)).DoNotCallBase();
            _mockClient.RevokeAsync(tokenWithRefresh, TokenRevokeType.Access).Returns(Task.CompletedTask);
            var credential = new Credential(tokenWithRefresh, _mockClient, _metadata);

            await credential.RevokeAsync(TokenRevokeType.Access);

            await _mockCoordinator.DidNotReceive().RemoveAsync(credential);
        }

        [Fact]
        public async Task RevokeAsync_CallsCoordinatorRemoveAsync_WhenRefreshTokenExistsAndTypeIsRefresh()
        {
            var tokenWithRefresh = TestHelpers.CreateToken(refreshToken: "refresh-token");
            _mockClient.When(x => x.RevokeAsync(tokenWithRefresh, TokenRevokeType.Refresh)).DoNotCallBase();
            _mockClient.RevokeAsync(tokenWithRefresh, TokenRevokeType.Refresh).Returns(Task.CompletedTask);
            _mockCoordinator.RemoveAsync(Arg.Any<Credential>()).Returns(Task.CompletedTask);
            var credential = new Credential(tokenWithRefresh, _mockClient, _metadata);

            await credential.RevokeAsync(TokenRevokeType.Refresh);

            await _mockCoordinator.Received(1).RemoveAsync(credential);
        }

        [Fact]
        public void Id_ReturnsTokenId()
        {
            var tokenWithId = TestHelpers.CreateToken(id: "test-token-id");
            var credential = new Credential(tokenWithId, _mockClient, _metadata);

            Assert.Equal("test-token-id", credential.Id);
        }

        [Fact]
        public async Task RefreshAsync_CallsClientRefreshAsync_WithTokenAndScope()
        {
            var scope = new List<string> { "openid", "profile" };
            var tokenWithScope = TestHelpers.CreateToken();
            tokenWithScope.Scope = scope;
            var refreshedToken = TestHelpers.CreateToken(accessToken: "new-access-token");
            var successResponse = ApiResponse<Token>.Success(refreshedToken);

            _mockClient.When(x => x.RefreshAsync(tokenWithScope, scope)).DoNotCallBase();
            _mockClient.RefreshAsync(tokenWithScope, scope).Returns(Task.FromResult(successResponse));

            var credential = new Credential(tokenWithScope, _mockClient, _metadata);

            await credential.RefreshAsync();

            await _mockClient.Received(1).RefreshAsync(tokenWithScope, scope);
        }

        [Fact]
        public async Task RefreshAsync_UpdatesToken_OnSuccess()
        {
            var scope = new List<string> { "openid" };
            var originalToken = TestHelpers.CreateToken(accessToken: "original-access-token");
            originalToken.Scope = scope;
            var refreshedToken = TestHelpers.CreateToken(accessToken: "refreshed-access-token");
            var successResponse = ApiResponse<Token>.Success(refreshedToken);

            _mockClient.When(x => x.RefreshAsync(originalToken, scope)).DoNotCallBase();
            _mockClient.RefreshAsync(originalToken, scope).Returns(Task.FromResult(successResponse));

            var credential = new Credential(originalToken, _mockClient, _metadata);

            await credential.RefreshAsync();

            Assert.Equal("refreshed-access-token", credential.Token.AccessToken);
        }

        [Fact]
        public async Task RefreshAsync_ThrowsOAuth2Exception_OnFailure()
        {
            var scope = new List<string> { "openid" };
            var tokenWithScope = TestHelpers.CreateToken();
            tokenWithScope.Scope = scope;
            var failureResponse = ApiResponse<Token>.Failure("Invalid refresh token", System.Net.HttpStatusCode.BadRequest);

            _mockClient.When(x => x.RefreshAsync(tokenWithScope, scope)).DoNotCallBase();
            _mockClient.RefreshAsync(tokenWithScope, scope).Returns(Task.FromResult(failureResponse));

            var credential = new Credential(tokenWithScope, _mockClient, _metadata);

            var exception = await Assert.ThrowsAsync<Okta.AuthFoundation.Exceptions.OAuth2Exception>(
                async () => await credential.RefreshAsync());
        }

        [Fact]
        public async Task RefreshAsync_ThrowsOAuth2Exception_WhenSuccessResponseHasNullResult()
        {
            var scope = new List<string> { "openid" };
            var originalToken = TestHelpers.CreateToken(accessToken: "original-access-token");
            originalToken.Scope = scope;

            // Simulate a success response with a null result (e.g., unexpected server behavior)
            var nullResultResponse = ApiResponse<Token>.Success(null!, System.Net.HttpStatusCode.OK);

            _mockClient.When(x => x.RefreshAsync(originalToken, scope)).DoNotCallBase();
            _mockClient.RefreshAsync(originalToken, scope).Returns(Task.FromResult(nullResultResponse));

            var credential = new Credential(originalToken, _mockClient, _metadata);

            var ex = await Assert.ThrowsAsync<Okta.AuthFoundation.Exceptions.OAuth2Exception>(
                async () => await credential.RefreshAsync());
            Assert.Contains("response contained no token data", ex.Message);
        }

        [Fact]
        public async Task RefreshAsync_DoesNotUpdateToken_OnFailure()
        {
            var scope = new List<string> { "openid" };
            var originalToken = TestHelpers.CreateToken(accessToken: "original-access-token");
            originalToken.Scope = scope;
            var failureResponse = ApiResponse<Token>.Failure("Refresh failed", System.Net.HttpStatusCode.Unauthorized);

            _mockClient.When(x => x.RefreshAsync(originalToken, scope)).DoNotCallBase();
            _mockClient.RefreshAsync(originalToken, scope).Returns(Task.FromResult(failureResponse));

            var credential = new Credential(originalToken, _mockClient, _metadata);

            try
            {
                await credential.RefreshAsync();
            }
            catch (Okta.AuthFoundation.Exceptions.OAuth2Exception)
            {
                // Expected exception
            }

            Assert.Equal("original-access-token", credential.Token.AccessToken);
        }

        [Fact]
        public async Task RemoveAsync_CallsCoordinatorRemoveAsync()
        {
            _mockCoordinator.RemoveAsync(Arg.Any<Credential>()).Returns(Task.CompletedTask);
            var credential = new Credential(_token, _mockClient, _metadata);

            await credential.RemoveAsync();

            await _mockClient.DidNotReceive().RevokeAsync(Arg.Any<Token>(), Arg.Any<TokenRevokeType>());
            await _mockCoordinator.Received(1).RemoveAsync(credential);
        }

        [Fact]
        public async Task ClearAsync_CallsCoordinatorClearAsync()
        {
            _mockCoordinator.ClearAsync().Returns(Task.CompletedTask);

            await Credential.ClearAsync();

            await _mockCoordinator.Received(1).ClearAsync();
        }

        [Fact]
        public async Task RefreshIfNeededAsync_CallsRefresh_WhenTokenIsExpired()
        {
            var scope = new List<string> { "openid" };
            var expiredToken = new Token(TestHelpers.CreateTokenContext())
            {
                Id = TestHelpers.DefaultId,
                AccessToken = "expired-access-token",
                TokenType = TestHelpers.DefaultTokenType,
                ExpiresIn = TestHelpers.DefaultExpiresIn,
                IssuedAt = DateTime.UtcNow.AddSeconds(-(TestHelpers.DefaultExpiresIn + 60)),
                Scope = scope,
            };

            var refreshedToken = TestHelpers.CreateToken(accessToken: "refreshed-access-token");
            var successResponse = ApiResponse<Token>.Success(refreshedToken);

            _mockClient.When(x => x.RefreshAsync(expiredToken, scope)).DoNotCallBase();
            _mockClient.RefreshAsync(expiredToken, scope).Returns(Task.FromResult(successResponse));

            var credential = new Credential(expiredToken, _mockClient, _metadata);

            await credential.RefreshIfNeededAsync();

            await _mockClient.Received(1).RefreshAsync(expiredToken, scope);
            Assert.Equal("refreshed-access-token", credential.Token.AccessToken);
        }

        [Fact]
        public async Task RefreshIfNeededAsync_DoesNotCallRefresh_WhenTokenIsNotExpired()
        {
            var scope = new List<string> { "openid" };
            var validToken = new Token(TestHelpers.CreateTokenContext())
            {
                Id = TestHelpers.DefaultId,
                AccessToken = "valid-access-token",
                TokenType = TestHelpers.DefaultTokenType,
                ExpiresIn = TestHelpers.DefaultExpiresIn,
                IssuedAt = DateTime.UtcNow,
                Scope = scope,
            };

            var credential = new Credential(validToken, _mockClient, _metadata);

            await credential.RefreshIfNeededAsync();

            await _mockClient.DidNotReceive().RefreshAsync(Arg.Any<Token>(), Arg.Any<List<string>>());
            Assert.Equal("valid-access-token", credential.Token.AccessToken);
        }

        [Fact]
        public async Task UserInfoAsync_CallsClientUserInfoAsync_AndReturnsResult()
        {
            var userInfo = JsonSerializer.Deserialize<UserInfo>(@"{""sub"":""user123"",""name"":""John Doe""}")!;
            var successResponse = ApiResponse<UserInfo>.Success(userInfo);

            _mockClient.When(x => x.UserInfoAsync(_token)).DoNotCallBase();
            _mockClient.UserInfoAsync(_token).Returns(Task.FromResult(successResponse));

            var credential = new Credential(_token, _mockClient, _metadata);

            var result = await credential.UserInfoAsync();

            await _mockClient.Received(1).UserInfoAsync(_token);
            Assert.Equal("user123", result.Subject());
            Assert.Equal("John Doe", result.Name());
        }

        [Fact]
        public async Task UserInfoAsync_ReturnsCachedResult_OnSubsequentCalls()
        {
            var userInfo = JsonSerializer.Deserialize<UserInfo>(@"{""sub"":""user123"",""name"":""John Doe""}")!;
            var successResponse = ApiResponse<UserInfo>.Success(userInfo);

            _mockClient.When(x => x.UserInfoAsync(_token)).DoNotCallBase();
            _mockClient.UserInfoAsync(_token).Returns(Task.FromResult(successResponse));

            var credential = new Credential(_token, _mockClient, _metadata);

            var first = await credential.UserInfoAsync();
            var second = await credential.UserInfoAsync();

            await _mockClient.Received(1).UserInfoAsync(_token);
            Assert.Same(first, second);
        }

        [Fact]
        public async Task UserInfoAsync_ThrowsOAuth2Exception_OnFailure()
        {
            var failureResponse = ApiResponse<UserInfo>.Failure("Unauthorized", System.Net.HttpStatusCode.Unauthorized);

            _mockClient.When(x => x.UserInfoAsync(_token)).DoNotCallBase();
            _mockClient.UserInfoAsync(_token).Returns(Task.FromResult(failureResponse));

            var credential = new Credential(_token, _mockClient, _metadata);

            var exception = await Assert.ThrowsAsync<Okta.AuthFoundation.Exceptions.OAuth2Exception>(
                async () => await credential.UserInfoAsync());
        }

        [Fact]
        public async Task IntrospectAsync_ReturnsResult_WhenTokenIsActive()
        {
            var introspectResponse = new IntrospectResponse { Active = true, Sub = "user123" };
            var successResponse = ApiResponse<IntrospectResponse>.Success(introspectResponse);

            _mockClient.When(x => x.IntrospectAsync(_token, TokenKind.AccessToken)).DoNotCallBase();
            _mockClient.IntrospectAsync(_token, TokenKind.AccessToken).Returns(Task.FromResult(successResponse));

            var credential = new Credential(_token, _mockClient, _metadata);

            var result = await credential.IntrospectAsync();

            Assert.True(result.Active);
            Assert.Equal("user123", result.Sub);
            await _mockCoordinator.DidNotReceive().RemoveAsync(credential);
        }

        [Fact]
        public async Task IntrospectAsync_RemovesCredential_WhenTokenIsInactive()
        {
            var introspectResponse = new IntrospectResponse { Active = false };
            var successResponse = ApiResponse<IntrospectResponse>.Success(introspectResponse);

            _mockClient.When(x => x.IntrospectAsync(_token, TokenKind.AccessToken)).DoNotCallBase();
            _mockClient.IntrospectAsync(_token, TokenKind.AccessToken).Returns(Task.FromResult(successResponse));
            _mockCoordinator.RemoveAsync(Arg.Any<Credential>()).Returns(Task.CompletedTask);

            var credential = new Credential(_token, _mockClient, _metadata);

            var result = await credential.IntrospectAsync();

            Assert.False(result.Active);
            await _mockCoordinator.Received(1).RemoveAsync(credential);
        }

        [Fact]
        public async Task IntrospectAsync_ThrowsOAuth2Exception_OnFailure()
        {
            var failureResponse = ApiResponse<IntrospectResponse>.Failure("Server error", System.Net.HttpStatusCode.InternalServerError);

            _mockClient.When(x => x.IntrospectAsync(_token, TokenKind.AccessToken)).DoNotCallBase();
            _mockClient.IntrospectAsync(_token, TokenKind.AccessToken).Returns(Task.FromResult(failureResponse));

            var credential = new Credential(_token, _mockClient, _metadata);

            var exception = await Assert.ThrowsAsync<Okta.AuthFoundation.Exceptions.OAuth2Exception>(
                async () => await credential.IntrospectAsync());
        }

        [Fact]
        public async Task AuthorizeAsync_CallsTokenAuthorizeAsync()
        {
            var credential = new Credential(_token, _mockClient, _metadata);
            var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/api");

            await credential.AuthorizeAsync(request);

            Assert.NotNull(request.Headers.Authorization);
            Assert.Equal(_token.TokenType, request.Headers.Authorization.Scheme);
            Assert.Equal(_token.AccessToken, request.Headers.Authorization.Parameter);
        }
    }
}
