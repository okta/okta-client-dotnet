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
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Okta.AuthFoundation;
using Okta.AuthFoundation.Exceptions;
using Okta.AuthFoundation.JwtSecurity;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    public class DefaultIdTokenValidatorTests
    {
        [Fact]
        public void Validate_ValidToken_DoesNotThrow()
        {
            var validator = new DefaultIdTokenValidator();
            var token = TestHelpers.CreateIdTokenWithClaims(
                issuer: "https://issuer.com",
                audience: "client123",
                subject: "user1");
            var context = new IdTokenValidatorContext
            {
                SupportedAlgs = new[] { "RS256" },
            };

            validator.Validate(token, new Uri("https://issuer.com"), "client123", context);
        }

        [Fact]
        public void Validate_InvalidIssuer_Throws()
        {
            var validator = new DefaultIdTokenValidator();
            var token = TestHelpers.CreateIdTokenWithClaims(
                issuer: "https://bad-issuer.com",
                audience: "client123",
                subject: "user1");
            var context = new IdTokenValidatorContext
            {
                SupportedAlgs = new[] { "RS256" },
            };

            Assert.Throws<JwtException>(() =>
                validator.Validate(token, new Uri("https://issuer.com"), "client123", context));
        }

        [Fact]
        public void Validate_InvalidAudience_Throws()
        {
            var validator = new DefaultIdTokenValidator();
            var token = TestHelpers.CreateIdTokenWithClaims(
                issuer: "https://issuer.com",
                audience: "wrong-client",
                subject: "user1");
            var context = new IdTokenValidatorContext
            {
                SupportedAlgs = new[] { "RS256" },
            };

            Assert.Throws<JwtException>(() =>
                validator.Validate(token, new Uri("https://issuer.com"), "client123", context));
        }

        [Fact]
        public void Validate_InvalidAlgorithm_Throws()
        {
            var validator = new DefaultIdTokenValidator();
            var token = TestHelpers.CreateIdTokenWithClaims(
                issuer: "https://issuer.com",
                audience: "client123",
                subject: "user1",
                algorithm: "HS256");
            var context = new IdTokenValidatorContext
            {
                SupportedAlgs = new[] { "RS256" },
            };

            Assert.Throws<JwtException>(() =>
                validator.Validate(token, new Uri("https://issuer.com"), "client123", context));
        }

        [Fact]
        public void Validate_ExpiredToken_Throws()
        {
            var validator = new DefaultIdTokenValidator();
            var now = DateTime.UtcNow;
            var token = TestHelpers.CreateIdTokenWithClaims(
                issuer: "https://issuer.com",
                audience: "client123",
                subject: "user1",
                issuedAt: now.AddMinutes(-10),
                expiresAt: now.AddMinutes(-5));
            var context = new IdTokenValidatorContext
            {
                SupportedAlgs = new[] { "RS256" },
            };

            Assert.Throws<JwtException>(() =>
                validator.Validate(token, new Uri("https://issuer.com"), "client123", context));
        }

        [Fact]
        public void Validate_IssuedAtTooFarInPast_Throws()
        {
            var validator = new DefaultIdTokenValidator();
            var now = DateTime.UtcNow;
            var token = TestHelpers.CreateIdTokenWithClaims(
                issuer: "https://issuer.com",
                audience: "client123",
                subject: "user1",
                issuedAt: now.AddMinutes(-10),
                expiresAt: now.AddMinutes(5));
            var context = new IdTokenValidatorContext
            {
                SupportedAlgs = new[] { "RS256" },
            };

            Assert.Throws<JwtException>(() =>
                validator.Validate(token, new Uri("https://issuer.com"), "client123", context));
        }

        [Fact]
        public void Validate_MissingSubject_Throws()
        {
            var validator = new DefaultIdTokenValidator();
            var now = DateTime.UtcNow;

            // Create Jwt without subject by using raw JSON
            var token = new Jwt(new JsonWebToken(
                header: "{\"alg\":\"RS256\"}",
                payload: $"{{\"iss\":\"https://issuer.com\",\"aud\":\"client123\",\"iat\":{new DateTimeOffset(now).ToUnixTimeSeconds()},\"exp\":{new DateTimeOffset(now.AddMinutes(5)).ToUnixTimeSeconds()}}}"));
            var context = new IdTokenValidatorContext
            {
                SupportedAlgs = new[] { "RS256" },
            };

            Assert.Throws<JwtException>(() =>
                validator.Validate(token, new Uri("https://issuer.com"), "client123", context));
        }

        [Fact]
        public void Validate_NonceMismatch_Throws()
        {
            var validator = new DefaultIdTokenValidator();
            var token = TestHelpers.CreateIdTokenWithClaims(
                issuer: "https://issuer.com",
                audience: "client123",
                subject: "user1",
                nonce: "abc");
            var context = new IdTokenValidatorContext
            {
                SupportedAlgs = new[] { "RS256" },
                Nonce = "xyz",
            };

            Assert.Throws<JwtException>(() =>
                validator.Validate(token, new Uri("https://issuer.com"), "client123", context));
        }

        [Fact]
        public void Validate_MaxAge_AuthTimeExceedsMaxAge_Throws()
        {
            var validator = new DefaultIdTokenValidator();
            var now = DateTime.UtcNow;
            var token = TestHelpers.CreateIdTokenWithClaims(
                issuer: "https://issuer.com",
                audience: "client123",
                subject: "user1",
                issuedAt: now.AddSeconds(-5),
                expiresAt: now.AddMinutes(5),
                authTime: now.AddMinutes(-10));   // authenticated 10 minutes ago
            var context = new IdTokenValidatorContext
            {
                SupportedAlgs = new[] { "RS256" },
                MaxAge = 60,   // only 60 seconds allowed since last auth
            };

            var ex = Assert.Throws<JwtException>(() =>
                validator.Validate(token, new Uri("https://issuer.com"), "client123", context));
            Assert.Contains("auth_time", ex.Message);
        }

        [Fact]
        public void Validate_MaxAge_AuthTimeWithinMaxAge_DoesNotThrow()
        {
            var validator = new DefaultIdTokenValidator();
            var now = DateTime.UtcNow;
            var token = TestHelpers.CreateIdTokenWithClaims(
                issuer: "https://issuer.com",
                audience: "client123",
                subject: "user1",
                issuedAt: now.AddSeconds(-5),
                expiresAt: now.AddMinutes(5),
                authTime: now.AddSeconds(-30));   // authenticated 30 seconds ago
            var context = new IdTokenValidatorContext
            {
                SupportedAlgs = new[] { "RS256" },
                MaxAge = 60,
            };

            // Should not throw
            validator.Validate(token, new Uri("https://issuer.com"), "client123", context);
        }

        [Fact]
        public void Validate_MaxAge_MissingAuthTime_Throws()
        {
            // OIDC Core 3.1.2.1: when max_age is requested, auth_time is required in the token.
            var validator = new DefaultIdTokenValidator();
            var now = DateTime.UtcNow;
            var token = TestHelpers.CreateIdTokenWithClaims(
                issuer: "https://issuer.com",
                audience: "client123",
                subject: "user1",
                issuedAt: now.AddSeconds(-5),
                expiresAt: now.AddMinutes(5));

            // no authTime
            var context = new IdTokenValidatorContext
            {
                SupportedAlgs = new[] { "RS256" },
                MaxAge = 300,
            };

            var ex = Assert.Throws<JwtException>(() =>
                validator.Validate(token, new Uri("https://issuer.com"), "client123", context));
            Assert.Contains("auth_time", ex.Message);
        }

        [Fact]
        public void Validate_MaxAge_NotSet_AuthTimeAbsent_DoesNotThrow()
        {
            // If max_age is not in the context, auth_time is not required.
            var validator = new DefaultIdTokenValidator();
            var token = TestHelpers.CreateIdTokenWithClaims(
                issuer: "https://issuer.com",
                audience: "client123",
                subject: "user1");
            var context = new IdTokenValidatorContext
            {
                SupportedAlgs = new[] { "RS256" },

                // no MaxAge
            };

            validator.Validate(token, new Uri("https://issuer.com"), "client123", context);
        }

        [Fact]
        public void Validate_MissingIat_ThrowsWithCorrectMessage()
        {
            var validator = new DefaultIdTokenValidator();
            var now = DateTime.UtcNow;
            var token = new Jwt(new JsonWebToken(
                header: "{\"alg\":\"RS256\"}",
                payload: $"{{\"iss\":\"https://issuer.com\",\"aud\":\"client123\",\"sub\":\"user1\",\"exp\":{new DateTimeOffset(now.AddMinutes(5)).ToUnixTimeSeconds()}}}"));
            var context = new IdTokenValidatorContext
            {
                SupportedAlgs = new[] { "RS256" },
            };

            var ex = Assert.Throws<JwtException>(() =>
                validator.Validate(token, new Uri("https://issuer.com"), "client123", context));
            Assert.Equal("Token issued at time (iat) exceeds grace interval.", ex.Message);
        }

        [Theory]
        [InlineData("")]
        [InlineData("issuer.com")]
        [InlineData("not a url")]
        public void Validate_MalformedIssuer_ThrowsJwtException(string issuer)
        {
            var validator = new DefaultIdTokenValidator();
            var token = TestHelpers.CreateIdTokenWithClaims(
                issuer: issuer,
                audience: "client123",
                subject: "user1");
            var context = new IdTokenValidatorContext
            {
                SupportedAlgs = new[] { "RS256" },
            };

            Assert.Throws<JwtException>(() =>
                validator.Validate(token, new Uri("https://issuer.com"), "client123", context));
        }

        [Fact]
        public void Validate_IssuerDiffersOnlyByTrailingSlash_DoesNotThrow()
        {
            var validator = new DefaultIdTokenValidator();
            var token = TestHelpers.CreateIdTokenWithClaims(
                issuer: "https://issuer.com/oauth2/default/",
                audience: "client123",
                subject: "user1");
            var context = new IdTokenValidatorContext
            {
                SupportedAlgs = new[] { "RS256" },
            };

            validator.Validate(token, new Uri("https://issuer.com/oauth2/default"), "client123", context);
        }

        [Fact]
        public void Validate_IssuerPathCasingDiffers_Throws()
        {
            var validator = new DefaultIdTokenValidator();
            var token = TestHelpers.CreateIdTokenWithClaims(
                issuer: "https://issuer.com/oauth2/Default",
                audience: "client123",
                subject: "user1");
            var context = new IdTokenValidatorContext
            {
                SupportedAlgs = new[] { "RS256" },
            };

            Assert.Throws<JwtException>(() =>
                validator.Validate(token, new Uri("https://issuer.com/oauth2/default"), "client123", context));
        }

        // TODO: Validate ACR values when implemented
    }
}
