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

namespace Okta.Client.Sdk.Tests
{
    public class TokenMetadataTests
    {
        [Fact]
        public void Tags_IsDictionary_WhenProvidedAtConstruction()
        {
            var token = TestHelpers.CreateToken();
            var tags = new Dictionary<string, string> { ["env"] = "prod", ["app"] = "mobile" };

            var metadata = new TokenMetadata(token, tags);

            Assert.IsType<Dictionary<string, string>>(metadata.Tags);
            Assert.Equal("prod", metadata.Tags!["env"]);
            Assert.Equal("mobile", metadata.Tags["app"]);
        }

        [Fact]
        public void Tags_IsNull_WhenTokenAndParameterBothNull()
        {
            var token = TestHelpers.CreateToken();

            var metadata = new TokenMetadata(token, tags: null);

            Assert.Null(metadata.Tags);
        }

        [Fact]
        public void Claims_AlwaysExtractedFromIdToken()
        {
            var idToken = TestHelpers.CreateIdToken(subject: "user-123");
            var token = TestHelpers.CreateToken(idToken: idToken);

            var metadata = new TokenMetadata(token);

            Assert.NotNull(metadata.Claims);
            Assert.Equal("user-123", metadata.GetValue<string>("sub"));
        }

        [Fact]
        public void Claims_PopulatedFromIdToken()
        {
            var idToken = TestHelpers.CreateIdToken(subject: "user-123", name: "Alice");
            var token = TestHelpers.CreateToken(idToken: idToken);

            var metadata = new TokenMetadata(token);

            Assert.NotNull(metadata.Claims);
            Assert.Equal("user-123", metadata.GetValue<string>("sub"));
            Assert.Equal("Alice", metadata.GetValue<string>("name"));
        }

        [Fact]
        public void Claims_PopulatedFromJwtAccessToken_WhenNoIdToken()
        {
            var header = Base64UrlEncode("{\"alg\":\"RS256\"}");
            var payload = Base64UrlEncode("{\"sub\":\"at-user\",\"email\":\"at@example.com\"}");
            var accessToken = $"{header}.{payload}.fakesig";

            var token = TestHelpers.CreateToken(accessToken: accessToken);

            var metadata = new TokenMetadata(token);

            Assert.NotNull(metadata.Claims);
            Assert.Equal("at-user", metadata.GetValue<string>("sub"));
            Assert.Equal("at@example.com", metadata.GetValue<string>("email"));
        }

        [Fact]
        public void Claims_IsNull_WhenAccessTokenIsNotJwt()
        {
            var token = TestHelpers.CreateToken(accessToken: "opaque-token-not-a-jwt");

            var metadata = new TokenMetadata(token);

            Assert.Null(metadata.Claims);
        }

        [Fact]
        public void Claims_PrefersIdToken_OverAccessToken()
        {
            var idToken = TestHelpers.CreateIdToken(subject: "id-token-sub");
            var header = Base64UrlEncode("{\"alg\":\"RS256\"}");
            var payload = Base64UrlEncode("{\"sub\":\"access-token-sub\"}");
            var accessToken = $"{header}.{payload}.fakesig";

            var token = TestHelpers.CreateToken(accessToken: accessToken, idToken: idToken);

            var metadata = new TokenMetadata(token);

            Assert.Equal("id-token-sub", metadata.GetValue<string>("sub"));
        }

        [Fact]
        public void Claims_PreservesNonStringTypes()
        {
            var header = Base64UrlEncode("{\"alg\":\"RS256\"}");
            var payload = Base64UrlEncode("{\"sub\":\"user\",\"email_verified\":true,\"login_count\":5}");
            var accessToken = $"{header}.{payload}.fakesig";

            var token = TestHelpers.CreateToken(accessToken: accessToken);

            var metadata = new TokenMetadata(token);

            Assert.True(metadata.GetValue<bool>("email_verified"));
            Assert.Equal(5, metadata.GetValue<int>("login_count"));
        }

        [Fact]
        public void GetValue_ReturnsStringValue()
        {
            var idToken = TestHelpers.CreateIdToken(subject: "user-123");
            var token = TestHelpers.CreateToken(idToken: idToken);
            var metadata = new TokenMetadata(token);

            Assert.Equal("user-123", metadata.GetValue<string>("sub"));
        }

        [Fact]
        public void GetValue_ReturnsNull_WhenClaimAbsent()
        {
            var idToken = TestHelpers.CreateIdToken(subject: "user-123");
            var token = TestHelpers.CreateToken(idToken: idToken);
            var metadata = new TokenMetadata(token);

            Assert.Null(metadata.GetValue<string>("nonexistent_claim"));
        }

        [Fact]
        public void GetValue_ReturnsNull_WhenClaimsIsNull()
        {
            var token = TestHelpers.CreateToken();
            var metadata = new TokenMetadata(token);

            Assert.Null(metadata.GetValue<string>("sub"));
        }

        [Fact]
        public void GetValue_Typed_ReturnsDefault_WhenClaimAbsent()
        {
            var idToken = TestHelpers.CreateIdToken(subject: "user-123");
            var token = TestHelpers.CreateToken(idToken: idToken);
            var metadata = new TokenMetadata(token);

            Assert.Null(metadata.GetValue<bool?>("nonexistent_claim"));
        }

        [Fact]
        public void GetValue_ByEnum_ReturnsStringValue()
        {
            var idToken = TestHelpers.CreateIdToken(subject: "user-123");
            var token = TestHelpers.CreateToken(idToken: idToken);
            var metadata = new TokenMetadata(token);

            Assert.Equal("user-123", metadata.GetValue<string>(JwtClaim.Subject));
        }

        private static string Base64UrlEncode(string input)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(input);
            return Convert.ToBase64String(bytes)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');
        }
    }
}
