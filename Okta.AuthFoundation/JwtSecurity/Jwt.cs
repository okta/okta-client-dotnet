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
using Microsoft.IdentityModel.Tokens;
using Okta.AuthFoundation.Claims;

namespace Okta.AuthFoundation.JwtSecurity
{
    /// <summary>
    /// Represents a JSON Web Token (JWT), providing access to header claims, payload claims, and encoded parts.
    /// Wraps the underlying token implementation and exposes claims via <see cref="IHasClaims"/>.
    /// </summary>
    public class Jwt : IHasClaims
    {
        private readonly IReadOnlyDictionary<string, JsonElement> _payload;

        internal JsonWebToken InnerToken { get; }

        /// <summary>
        /// Initializes a new <see cref="Jwt"/> by parsing a Base64Url-encoded JWT string.
        /// </summary>
        /// <param name="encodedToken">The complete encoded JWT string (header.payload.signature).</param>
        public Jwt(string encodedToken)
            : this(new JsonWebToken(encodedToken))
        {
        }

        internal Jwt(JsonWebToken jwt)
        {
            InnerToken = jwt;
            _payload = ExtractPayload(jwt.EncodedPayload)
                ?? (IReadOnlyDictionary<string, JsonElement>)new Dictionary<string, JsonElement>();
        }

        /// <inheritdoc />
        public IReadOnlyDictionary<string, JsonElement> Payload => _payload;

        /// <summary>
        /// Gets the original Base64Url-encoded JWT string.
        /// </summary>
        public string EncodedToken => InnerToken.EncodedToken;

        /// <summary>
        /// Gets the Base64Url-encoded header segment.
        /// </summary>
        public string EncodedHeader => InnerToken.EncodedHeader;

        /// <summary>
        /// Gets the Base64Url-encoded payload segment.
        /// </summary>
        public string EncodedPayload => InnerToken.EncodedPayload;

        /// <summary>
        /// Gets the Base64Url-encoded signature segment.
        /// </summary>
        public string EncodedSignature => InnerToken.EncodedSignature;

        /// <summary>
        /// Gets the signature algorithm (alg) from the token header, or null if not present.
        /// </summary>
        public string? Algorithm => string.IsNullOrEmpty(InnerToken.Alg) ? null : InnerToken.Alg;

        /// <summary>
        /// Gets the key ID (kid) from the token header, or null if not present.
        /// </summary>
        public string? KeyId => string.IsNullOrEmpty(InnerToken.Kid) ? null : InnerToken.Kid;

        /// <summary>
        /// Gets the token type (typ) from the token header, or null if not present.
        /// </summary>
        public string? Type => string.IsNullOrEmpty(InnerToken.Typ) ? null : InnerToken.Typ;

        /// <summary>
        /// Gets the content type (cty) from the token header, or null if not present.
        /// </summary>
        public string? ContentType => string.IsNullOrEmpty(InnerToken.Cty) ? null : InnerToken.Cty;

        /// <summary>
        /// Gets the X.509 certificate SHA-1 thumbprint (x5t) from the token header, or null if not present.
        /// </summary>
        public string? X509Thumbprint => string.IsNullOrEmpty(InnerToken.X5t) ? null : InnerToken.X5t;

        /// <summary>
        /// Gets the audience (aud) claim values. Returns an empty collection if not present.
        /// </summary>
        public IEnumerable<string> Audiences => InnerToken.Audiences;

        /// <summary>
        /// Gets whether this token has a cryptographic signature.
        /// </summary>
        public bool IsSigned => InnerToken.IsSigned;

        /// <summary>
        /// Gets whether this token is encrypted (JWE).
        /// </summary>
        public bool IsEncrypted => InnerToken.IsEncrypted;

        internal static IReadOnlyDictionary<string, JsonElement>? ExtractPayload(string encodedPayload)
        {
            try
            {
                var bytes = Base64UrlEncoder.DecodeBytes(encodedPayload);
                using var doc = JsonDocument.Parse(bytes);
                var dict = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    dict[prop.Name] = prop.Value.Clone();
                }

                return dict.Count > 0 ? dict : null;
            }
            catch
            {
                return null;
            }
        }
    }
}
