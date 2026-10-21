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
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Okta.AuthFoundation.Claims;
using Okta.AuthFoundation.JwtSecurity;

namespace Okta.AuthFoundation.TokenManagement
{
    /// <summary>
    /// Stores metadata associated with a token, including issuer, scope, client ID, tags, and a claims snapshot.
    /// </summary>
    public class TokenMetadata : IHasClaims
    {
        /// <summary>
        /// Gets or sets the issuer URI.
        /// </summary>
        [JsonPropertyName("issuer")]
        public Uri? Issuer { get; set; }

        /// <summary>
        /// Gets or sets the scope.
        /// </summary>
        [JsonPropertyName("scope")]
        public List<string>? Scope { get; set; }

        /// <summary>
        /// Gets or sets the client ID.
        /// </summary>
        [JsonPropertyName("client_id")]
        public string? ClientId { get; set; }

        /// <summary>
        /// Gets or sets the token identifier.
        /// </summary>
        [JsonPropertyName("id")]
        public string? Id { get; set; }

        /// <summary>
        /// Gets or sets the developer-assigned tags associated with this token.
        /// </summary>
        [JsonPropertyName("tags")]
        public Dictionary<string, string>? Tags { get; init; }

        /// <summary>
        /// Gets or sets a snapshot of claims from the ID token or JWT-encoded access token, used for claims-based credential querying.
        /// JSON types are preserved — booleans, numbers, and arrays are not coerced to strings.
        /// </summary>
        /// <remarks>
        /// Storage implementations strip claims before persisting unless
        /// <see cref="ITokenStorage.IncludeClaims"/> is enabled.
        /// </remarks>
        // JsonElement rather than string preserves type fidelity (e.g. email_verified stays bool, not "True").
        // Access via GetValue<T>/RequireValue<T> extension methods on IHasClaims.
        [JsonPropertyName("claims")]
        public Dictionary<string, JsonElement>? Claims { get; set; }

        private static readonly IReadOnlyDictionary<string, JsonElement> EmptyPayload =
            new Dictionary<string, JsonElement>();

        private readonly ILogger<TokenMetadata> _logger = OktaServices.Resolve<ILogger<TokenMetadata>>();

        /// <summary>
        /// Gets the claims payload, returning an empty dictionary if no claims are present.
        /// </summary>
        [JsonIgnore]
        public IReadOnlyDictionary<string, JsonElement> Payload => Claims ?? EmptyPayload;

        /// <summary>
        /// Parameterless constructor for JSON deserialization.
        /// </summary>
        [JsonConstructor]
        public TokenMetadata()
        {
        }

        /// <summary>
        /// Creates metadata from a token and optional tags.
        /// </summary>
        /// <param name="token">The token to extract metadata from.</param>
        /// <param name="tags">Optional tags to associate with the token.</param>
        public TokenMetadata(Token token, Dictionary<string, string>? tags = null)
        {
            var context = token.Context;
            this.Issuer = context?.Issuer;
            this.Scope = context?.Scope;
            this.ClientId = context?.ClientId;
            this.Id = token.Id;
            this.Tags = tags;
            this.Claims = ExtractClaims(token);
        }

        private Dictionary<string, JsonElement>? ExtractClaims(Token token)
        {
            if (token.IdToken != null)
            {
                return new Dictionary<string, JsonElement>(token.IdToken.Payload);
            }

            if (!string.IsNullOrEmpty(token.AccessToken))
            {
                try
                {
                    var at = new JsonWebToken(token.AccessToken);
                    var payload = Jwt.ExtractPayload(at.EncodedPayload);
                    return payload != null ? new Dictionary<string, JsonElement>(payload) : null;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Failed to extract claims from access token payload.");
                    return null;
                }
            }

            return null;
        }
    }
}
