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

namespace Okta.OAuth2
{
    /// <summary>
    /// Represents a PKCE (Proof Key for Code Exchange) challenge and verifier pair.
    /// </summary>
    public class Pkce
    {
        /// <summary>
        /// Gets the code verifier.
        /// </summary>
        public string Verifier { get; }

        /// <summary>
        /// Gets the code challenge derived from the verifier.
        /// </summary>
        public string Challenge { get; }

        /// <summary>
        /// Gets the challenge method used (always "S256").
        /// </summary>
        public string Method { get; } = "S256";

        private Pkce(string verifier, string challenge)
        {
            Verifier = verifier;
            Challenge = challenge;
        }

        /// <summary>
        /// Generates a new PKCE verifier and challenge pair.
        /// </summary>
        /// <returns>A new <see cref="Pkce"/> instance with a cryptographically random verifier and its SHA256 challenge.</returns>
        public static Pkce Generate()
        {
            var verifier = GenerateVerifier();
            var challenge = GenerateChallenge(verifier);
            return new Pkce(verifier, challenge);
        }

        /// <summary>
        /// Generates a cryptographically secure random verifier string.
        /// </summary>
        /// <param name="byteLength">The number of random bytes to generate (default 32).</param>
        /// <returns>A Base64 URL encoded random string.</returns>
        public static string GenerateVerifier(int byteLength = 32)
        {
            var bytes = RandomNumberGenerator.GetBytes(byteLength);
            return Base64UrlEncoder.Encode(bytes);
        }

        /// <summary>
        /// Generates a PKCE code challenge from the verifier using SHA256.
        /// </summary>
        /// <param name="verifier">The code verifier.</param>
        /// <returns>A Base64 URL encoded SHA256 hash of the verifier.</returns>
        public static string GenerateChallenge(string verifier)
        {
            var bytes = Encoding.ASCII.GetBytes(verifier);
            var hash = SHA256.HashData(bytes);
            return Base64UrlEncoder.Encode(hash);
        }
    }
}
