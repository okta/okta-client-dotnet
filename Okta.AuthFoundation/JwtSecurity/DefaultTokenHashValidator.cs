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
using Microsoft.IdentityModel.Tokens;
using Okta.AuthFoundation.Claims;
using Okta.AuthFoundation.Exceptions;
using Okta.AuthFoundation.TokenManagement;

namespace Okta.AuthFoundation.JwtSecurity
{
    /// <summary>
    /// Default implementation of <see cref="ITokenHashValidator"/> that validates token hashes embedded in an ID token.
    /// </summary>
    public class DefaultTokenHashValidator : ITokenHashValidator
    {
        /// <summary>
        /// Validates the access token and refresh token hashes against the claims in the provided ID token.
        /// </summary>
        /// <param name="idToken">The ID token containing the hash claims to validate against.</param>
        /// <param name="token">The token whose access and refresh token values are validated.</param>
        /// <returns>A completed task.</returns>
        public Task ValidateAsync(Jwt idToken, Token token)
        {
            var alg = idToken.Algorithm;
            if (alg != SecurityAlgorithms.RsaSha256 && alg != "RS256")
            {
                throw new JwtException($"Unsupported JWT algorithm for hash validation: {alg}");
            }

            ValidateHash(idToken, "at_hash", token.AccessToken);

            if (!string.IsNullOrEmpty(token.RefreshToken))
            {
                ValidateHash(idToken, "rt_hash", token.RefreshToken);
            }

            return Task.CompletedTask;
        }

        private static void ValidateHash(Jwt idToken, string claimName, string tokenValue)
        {
            var expectedHash = idToken.GetValue<string>(claimName);
            if (string.IsNullOrEmpty(expectedHash))
            {
                return;
            }

            byte[] expectedBytes;
            try
            {
                expectedBytes = Base64UrlEncoder.DecodeBytes(expectedHash);
            }
            catch (FormatException)
            {
                throw new JwtException($"Token hash validation failed for {claimName}.");
            }

            var computedBytes = ComputeLeftHalfHash(tokenValue);

            if (!CryptographicOperations.FixedTimeEquals(computedBytes, expectedBytes))
            {
                throw new JwtException($"Token hash validation failed for {claimName}.");
            }
        }

        internal static byte[] ComputeLeftHalfHash(string tokenValue)
        {
            var tokenBytes = Encoding.ASCII.GetBytes(tokenValue);
            var fullHash = SHA256.HashData(tokenBytes);
            return fullHash[..(fullHash.Length / 2)];
        }
    }
}
