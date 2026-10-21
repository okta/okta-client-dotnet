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

using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Okta.AuthFoundation;
using Okta.AuthFoundation.Exceptions;
using Okta.AuthFoundation.JwtSecurity;
using Okta.AuthFoundation.TokenManagement;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    public class DefaultTokenHashValidatorTests
    {
        private readonly DefaultTokenHashValidator _validator = new();

        [Fact]
        public async Task Validate_ValidAtHash_DoesNotThrow()
        {
            var accessToken = "test-access-token";
            var atHash = ComputeExpectedHash(accessToken);

            var idToken = CreateIdTokenWithHashes(atHash: atHash);
            var token = CreateToken(accessToken: accessToken);

            await _validator.ValidateAsync(idToken, token);
        }

        [Fact]
        public async Task Validate_InvalidAtHash_Throws()
        {
            var idToken = CreateIdTokenWithHashes(atHash: "invalid-hash-value");
            var token = CreateToken(accessToken: "test-access-token");

            await Assert.ThrowsAsync<JwtException>(() => _validator.ValidateAsync(idToken, token));
        }

        [Fact]
        public async Task Validate_ValidRtHash_DoesNotThrow()
        {
            var accessToken = "test-access-token";
            var refreshToken = "test-refresh-token";
            var atHash = ComputeExpectedHash(accessToken);
            var rtHash = ComputeExpectedHash(refreshToken);

            var idToken = CreateIdTokenWithHashes(atHash: atHash, rtHash: rtHash);
            var token = CreateToken(accessToken: accessToken, refreshToken: refreshToken);

            await _validator.ValidateAsync(idToken, token);
        }

        [Fact]
        public async Task Validate_InvalidRtHash_Throws()
        {
            var accessToken = "test-access-token";
            var atHash = ComputeExpectedHash(accessToken);

            var idToken = CreateIdTokenWithHashes(atHash: atHash, rtHash: "invalid-hash-value");
            var token = CreateToken(accessToken: accessToken, refreshToken: "test-refresh-token");

            await Assert.ThrowsAsync<JwtException>(() => _validator.ValidateAsync(idToken, token));
        }

        [Fact]
        public async Task Validate_NoHashClaims_DoesNotThrow()
        {
            var idToken = CreateIdTokenWithHashes();
            var token = CreateToken(accessToken: "test-access-token");

            await _validator.ValidateAsync(idToken, token);
        }

        [Fact]
        public async Task Validate_NoRefreshToken_SkipsRtHashValidation()
        {
            var accessToken = "test-access-token";
            var atHash = ComputeExpectedHash(accessToken);

            var idToken = CreateIdTokenWithHashes(atHash: atHash, rtHash: "some-hash");
            var token = CreateToken(accessToken: accessToken, refreshToken: null);

            await _validator.ValidateAsync(idToken, token);
        }

        [Fact]
        public async Task Validate_UnsupportedAlgorithm_Throws()
        {
            var idToken = CreateIdTokenWithHashes(atHash: "some-hash", algorithm: "none");
            var token = CreateToken(accessToken: "test-access-token");

            await Assert.ThrowsAsync<JwtException>(() => _validator.ValidateAsync(idToken, token));
        }

        [Fact]
        public async Task Validate_RS384Algorithm_Throws()
        {
            var idToken = CreateIdTokenWithHashes(atHash: "some-hash", algorithm: "RS384");
            var token = CreateToken(accessToken: "test-access-token");

            await Assert.ThrowsAsync<JwtException>(() => _validator.ValidateAsync(idToken, token));
        }

        [Fact]
        public void ComputeLeftHalfHash_ProducesCorrectValue()
        {
            var result = DefaultTokenHashValidator.ComputeLeftHalfHash("test-access-token");

            var expectedBase64 = ComputeExpectedHash("test-access-token");
            var expectedBytes = Base64UrlEncoder.DecodeBytes(expectedBase64);
            Assert.Equal(expectedBytes, result);
            Assert.True(result.Length > 0);
        }

        private static string ComputeExpectedHash(string tokenValue)
        {
            var tokenBytes = Encoding.ASCII.GetBytes(tokenValue);
            var fullHash = SHA256.HashData(tokenBytes);
            var leftHalf = new byte[fullHash.Length / 2];
            Array.Copy(fullHash, leftHalf, leftHalf.Length);
            return Base64UrlEncoder.Encode(leftHalf);
        }

        private static Jwt CreateIdTokenWithHashes(string? atHash = null, string? rtHash = null, string algorithm = "RS256")
        {
            var now = DateTimeOffset.UtcNow;
            var header = $"{{\"alg\":\"{algorithm}\"}}";
            var payload = $"{{\"iss\":\"https://example.com\",\"aud\":\"clientId\",\"sub\":\"user123\",\"iat\":{now.ToUnixTimeSeconds()},\"exp\":{now.AddMinutes(5).ToUnixTimeSeconds()}";

            if (atHash != null)
            {
                payload += $",\"at_hash\":\"{atHash}\"";
            }

            if (rtHash != null)
            {
                payload += $",\"rt_hash\":\"{rtHash}\"";
            }

            payload += "}";

            return new Jwt(new JsonWebToken(header, payload));
        }

        private static Token CreateToken(string accessToken = "test-access-token", string? refreshToken = null)
        {
            return new Token
            {
                TokenType = "Bearer",
                AccessToken = accessToken,
                ExpiresIn = 3600,
                RefreshToken = refreshToken,
            };
        }
    }
}
