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
using Microsoft.IdentityModel.JsonWebTokens;
using Okta.AuthFoundation;
using Okta.AuthFoundation.Claims;
using Okta.AuthFoundation.JwtSecurity;
using Okta.AuthFoundation.OAuth2;
using Okta.AuthFoundation.TokenManagement;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    public class ClaimsTests
    {
        [Fact]
        public void JWT_ExtractsPayload_FromEncodedToken()
        {
            var header = Base64UrlEncode("{\"alg\":\"RS256\"}");
            var payload = Base64UrlEncode("{\"sub\":\"user-123\",\"email\":\"user@example.com\"}");
            var jwt = new Jwt($"{header}.{payload}.fakesig");

            Assert.Equal("user-123", jwt.GetValue<string>("sub"));
            Assert.Equal("user@example.com", jwt.GetValue<string>("email"));
        }

        [Fact]
        public void JWT_WrapsJsonWebToken()
        {
            var inner = new JsonWebToken(
                header: "{\"alg\":\"RS256\"}",
                payload: "{\"sub\":\"user-abc\"}");
            var jwt = new Jwt(inner);

            Assert.Same(inner, jwt.InnerToken);
            Assert.Equal("user-abc", jwt.GetValue<string>("sub"));
        }

        [Fact]
        public void GetValue_String_ReturnsString()
        {
            var jwt = MakeJwt("{\"sub\":\"hello\"}");
            Assert.Equal("hello", jwt.GetValue<string>(JwtClaim.Subject));
        }

        [Fact]
        public void GetValue_ReturnsNull_WhenClaimAbsent()
        {
            var jwt = MakeJwt("{\"sub\":\"hello\"}");
            Assert.Null(jwt.GetValue<string>("nonexistent"));
        }

        [Fact]
        public void GetValue_Bool_FromJsonTrue()
        {
            var jwt = MakeJwt("{\"email_verified\":true}");
            Assert.True(jwt.GetValue<bool>(JwtClaim.EmailVerified));
        }

        [Fact]
        public void GetValue_Bool_FromIntOne()
        {
            var jwt = MakeJwt("{\"email_verified\":1}");
            Assert.True(jwt.GetValue<bool>(JwtClaim.EmailVerified));
        }

        [Fact]
        public void GetValue_Bool_FromIntZero()
        {
            var jwt = MakeJwt("{\"email_verified\":0}");
            Assert.False(jwt.GetValue<bool>(JwtClaim.EmailVerified));
        }

        [Fact]
        public void GetValue_DateTime_FromUnixEpoch()
        {
            var epoch = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();
            var jwt = MakeJwt($"{{\"exp\":{epoch}}}");
            var result = jwt.GetValue<DateTime>(JwtClaim.ExpirationTime);
            Assert.Equal(new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc), result);
        }

        [Fact]
        public void GetValue_StringArray_FromJsonArray()
        {
            var jwt = MakeJwt("{\"groups\":[\"admin\",\"user\"]}");
            var result = jwt.GetValue<string[]>(JwtClaim.Groups);
            Assert.Equal(["admin", "user"], result);
        }

        [Fact]
        public void GetValue_StringArray_FromSpaceSeparatedString()
        {
            var jwt = MakeJwt("{\"scp\":\"openid profile email\"}");
            var result = jwt.GetValue<string[]>(JwtClaim.Scope);
            Assert.Equal(["openid", "profile", "email"], result);
        }

        [Fact]
        public void GetValue_Uri_FromString()
        {
            var jwt = MakeJwt("{\"iss\":\"https://example.okta.com\"}");
            var result = jwt.GetValue<Uri>(JwtClaim.Issuer);
            Assert.Equal(new Uri("https://example.okta.com"), result);
        }

        [Fact]
        public void GetValue_ByStringKey_Works()
        {
            var jwt = MakeJwt("{\"custom_dept\":\"engineering\"}");
            Assert.Equal("engineering", jwt.GetValue<string>("custom_dept"));
        }

        [Fact]
        public void RequireValue_ReturnsValue_WhenPresent()
        {
            var jwt = MakeJwt("{\"sub\":\"user-123\"}");
            Assert.Equal("user-123", jwt.RequireValue<string>(JwtClaim.Subject));
        }

        [Fact]
        public void RequireValue_Throws_WhenAbsent()
        {
            var jwt = MakeJwt("{\"sub\":\"user-123\"}");
            var ex = Assert.Throws<ClaimNotFoundException>(() => jwt.RequireValue<string>("missing"));
            Assert.Equal("missing", ex.ClaimKey);
        }

        [Fact]
        public void GetClaims_ReturnsRecognizedStandardClaims()
        {
            var jwt = MakeJwt("{\"sub\":\"user\",\"email\":\"u@example.com\",\"custom_x\":\"y\"}");
            var claims = jwt.GetClaims().ToList();
            Assert.Contains(JwtClaim.Subject, claims);
            Assert.Contains(JwtClaim.Email, claims);
            Assert.DoesNotContain(JwtClaim.Custom("custom_x"), claims);
        }

        [Fact]
        public void GetCustomClaims_ReturnsUnrecognizedKeys()
        {
            var jwt = MakeJwt("{\"sub\":\"user\",\"custom_dept\":\"eng\"}");
            var custom = jwt.GetCustomClaims().ToList();
            Assert.Contains("custom_dept", custom);
            Assert.DoesNotContain("sub", custom);
        }

        [Fact]
        public void GetAllClaims_ReturnsAllKeys()
        {
            var jwt = MakeJwt("{\"sub\":\"user\",\"custom_x\":\"y\"}");
            var all = jwt.GetAllClaims().ToList();
            Assert.Contains("sub", all);
            Assert.Contains("custom_x", all);
        }

        [Fact]
        public void JwtClaim_StandardInstances_AreEqual()
        {
            Assert.Equal(JwtClaim.Subject, JwtClaim.Subject);
            Assert.True(JwtClaim.Subject == JwtClaim.Subject);
        }

        [Fact]
        public void JwtClaim_Custom_EqualWhenSameKey()
        {
            Assert.Equal(JwtClaim.Custom("dept"), JwtClaim.Custom("dept"));
        }

        [Fact]
        public void JwtClaim_Custom_NotEqualToDifferentKey()
        {
            Assert.NotEqual(JwtClaim.Custom("dept"), JwtClaim.Custom("role"));
        }

        [Fact]
        public void JwtClaim_Custom_NotEqualToStandard()
        {
            Assert.NotEqual(JwtClaim.Custom("sub"), JwtClaim.Subject);
        }

        [Fact]
        public void Subject_ReturnsSubjectClaim()
        {
            var jwt = MakeJwt("{\"sub\":\"user-abc\"}");
            Assert.Equal("user-abc", jwt.Subject());
        }

        [Fact]
        public void Email_ReturnsEmailClaim()
        {
            var jwt = MakeJwt("{\"email\":\"test@example.com\"}");
            Assert.Equal("test@example.com", jwt.Email());
        }

        [Fact]
        public void EmailVerified_ReturnsBool()
        {
            var jwt = MakeJwt("{\"email_verified\":true}");
            Assert.True(jwt.EmailVerified());
        }

        [Fact]
        public void ExpirationTime_ReturnsDateTime()
        {
            var epoch = new DateTimeOffset(2025, 6, 1, 0, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();
            var jwt = MakeJwt($"{{\"exp\":{epoch}}}");
            Assert.Equal(new DateTime(2025, 6, 1, 0, 0, 0, DateTimeKind.Utc), jwt.ExpirationTime());
        }

        [Fact]
        public void Scope_ReturnsArrayFromSpaceSeparated()
        {
            var jwt = MakeJwt("{\"scp\":\"openid profile\"}");
            Assert.Equal(["openid", "profile"], jwt.Scope());
        }

        [Fact]
        public void UserInfo_DeserializesStandardClaims()
        {
            var userInfo = JsonSerializer.Deserialize<UserInfo>(
                @"{""sub"":""user123"",""email"":""user@example.com"",""email_verified"":true}");

            Assert.Equal("user123", userInfo!.Subject());
            Assert.Equal("user@example.com", userInfo.Email());
            Assert.True(userInfo.EmailVerified());
        }

        [Fact]
        public void UserInfo_AccessesCustomClaims()
        {
            var userInfo = JsonSerializer.Deserialize<UserInfo>(
                @"{""sub"":""user123"",""custom_department"":""engineering""}");

            Assert.Equal("engineering", userInfo!.GetValue<string>("custom_department"));
        }

        [Fact]
        public void UserInfo_GetCustomClaims_ReturnsNonStandardKeys()
        {
            var userInfo = JsonSerializer.Deserialize<UserInfo>(
                @"{""sub"":""user123"",""custom_department"":""engineering""}");

            var custom = userInfo!.GetCustomClaims().ToList();
            Assert.Contains("custom_department", custom);
            Assert.DoesNotContain("sub", custom);
        }

        [Fact]
        public void TokenMetadata_ImplementsIHasClaims()
        {
            var idToken = TestHelpers.CreateIdToken(subject: "meta-user");
            var token = TestHelpers.CreateToken(idToken: idToken);
            var metadata = new TokenMetadata(token);

            Assert.Equal("meta-user", metadata.GetValue<string>(JwtClaim.Subject));
            Assert.Equal("meta-user", metadata.Subject());
        }

        [Fact]
        public void TokenMetadata_Payload_IsEmpty_WhenNoClaims()
        {
            var token = TestHelpers.CreateToken();
            var metadata = new TokenMetadata(token);

            Assert.Empty(metadata.Payload);
        }

        private static Jwt MakeJwt(string payloadJson)
        {
            var header = Base64UrlEncode("{\"alg\":\"RS256\"}");
            var payload = Base64UrlEncode(payloadJson);
            return new Jwt($"{header}.{payload}.fakesig");
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
