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
using Okta.AuthFoundation.Exceptions;
using Okta.AuthFoundation.JwtSecurity;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    public class DefaultJwkValidatorTests
    {
        [Fact]
        public async Task Validate_ValidJwtSignature_ReturnsTrue()
        {
            var (jwt, jwks) = GenerateValidTestJwtAndKeys();
            var validator = new DefaultJwkValidator();

            bool isValid = await validator.ValidateAsync(jwt, jwks.Keys);

            Assert.True(isValid);
        }

        private static (JsonWebToken Jwt, JsonWebKeySet Jwks) GenerateValidTestJwtAndKeys()
        {
            var rsa = System.Security.Cryptography.RSA.Create(2048);
            var securityKey = new RsaSecurityKey(rsa)
            {
                KeyId = "test-key-id",
            };
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);
            var tokenHandler = new JsonWebTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new[]
                {
                    new System.Security.Claims.Claim("sub", "testuser"),
                    new System.Security.Claims.Claim("iss", "testissuer"),
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = signingCredentials,
            };

            var jwtString = tokenHandler.CreateToken(tokenDescriptor);
            var jwt = new JsonWebToken(jwtString);
            var jsonWebKey = JsonWebKeyConverter.ConvertFromRSASecurityKey(securityKey);
            jsonWebKey.Use = "sig";
            jsonWebKey.Alg = SecurityAlgorithms.RsaSha256;

            var jwks = new JsonWebKeySet();
            jwks.Keys.Add(jsonWebKey);

            return (jwt, jwks);
        }

        [Fact]
        public async Task Validate_NoMatchingPublicKey_ThrowsSecurityTokenSignatureKeyNotFoundException()
        {
            // Arrange: Create JWT with one key, JWKS with a different key
            var (jwt, _) = GenerateValidTestJwtAndKeys();

            // Create a different RSA key for JWKS (won't match JWT signature)
            var differentRsa = System.Security.Cryptography.RSA.Create(2048);
            var differentSecurityKey = new RsaSecurityKey(differentRsa)
            {
                KeyId = "different-key-id",
            };

            var differentJsonWebKey = JsonWebKeyConverter.ConvertFromRSASecurityKey(differentSecurityKey);
            differentJsonWebKey.Use = "sig";
            differentJsonWebKey.Alg = SecurityAlgorithms.RsaSha256;

            var jwks = new JsonWebKeySet();
            jwks.Keys.Add(differentJsonWebKey);

            var validator = new DefaultJwkValidator();

            // Act & Assert
            await Assert.ThrowsAsync<SecurityTokenSignatureKeyNotFoundException>(
                async () => await validator.ValidateAsync(jwt, jwks.Keys));
        }

        [Fact]
        public async Task Validate_MatchingKeyButInvalidSignature_ReturnsFalse()
        {
            // Arrange: Create valid JWT and keys
            var (jwt, jwks) = GenerateValidTestJwtAndKeys();

            // Tamper with the JWT signature by modifying the token string
            var jwtParts = jwt.EncodedToken.Split('.');
            if (jwtParts.Length == 3)
            {
                // Modify the signature part slightly to corrupt it
                var corruptedSignature = jwtParts[2].TrimEnd('=') + "corrupted";
                var tamperedJwtString = $"{jwtParts[0]}.{jwtParts[1]}.{corruptedSignature}";
                var tamperedJwt = new JsonWebToken(tamperedJwtString);

                var validator = new DefaultJwkValidator();

                // Act
                bool isValid = await validator.ValidateAsync(tamperedJwt, jwks.Keys);

                // Assert
                Assert.False(isValid);
            }
            else
            {
                throw new InvalidOperationException("JWT does not have expected 3-part structure");
            }
        }

        [Fact]
        public async Task Validate_EmptyKeySet_ThrowsSecurityTokenSignatureKeyNotFoundException()
        {
            // Arrange
            var (jwt, _) = GenerateValidTestJwtAndKeys();
            var emptyKeySet = new JsonWebKeySet();

            var validator = new DefaultJwkValidator();

            // Act & Assert
            await Assert.ThrowsAsync<SecurityTokenSignatureKeyNotFoundException>(
                async () => await validator.ValidateAsync(jwt, emptyKeySet.Keys));
        }

        [Fact]
        public async Task Validate_WithWrongAlgorithm_ThrowsSecurityTokenSignatureKeyNotFoundException()
        {
            // Arrange: Create JWT with RS256 but JWKS has only HS256 key
            var (jwt, _) = GenerateValidTestJwtAndKeys();

            // Create an HS256 key (which won't validate RS256 signature)
            var symmetricKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("this-is-a-secret-key-of-sufficient-length-for-hmac-256-validation"));
            var symmetricJsonWebKey = JsonWebKeyConverter.ConvertFromSymmetricSecurityKey(symmetricKey);
            symmetricJsonWebKey.Alg = SecurityAlgorithms.HmacSha256;

            var jwks = new JsonWebKeySet();
            jwks.Keys.Add(symmetricJsonWebKey);

            var validator = new DefaultJwkValidator();

            // Act & Assert - should not find matching key
            await Assert.ThrowsAsync<SecurityTokenSignatureKeyNotFoundException>(
                async () => await validator.ValidateAsync(jwt, jwks.Keys));
        }
    }
}
