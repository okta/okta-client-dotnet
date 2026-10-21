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

using System.Text.Json.Serialization;

namespace Okta.AuthFoundation.OAuth2
{
    /// <summary>
    /// Represents the response from an OAuth2 token introspection endpoint (RFC 7662).
    /// </summary>
    public class IntrospectResponse
    {
        /// <summary>
        /// Gets or sets whether the token is active (not expired, not revoked, and was issued by this server).
        /// </summary>
        [JsonPropertyName("active")]
        public bool Active { get; set; }

        /// <summary>
        /// Gets or sets the scope associated with the token.
        /// </summary>
        [JsonPropertyName("scope")]
        public string? Scope { get; set; }

        /// <summary>
        /// Gets or sets the client ID the token was issued to.
        /// </summary>
        [JsonPropertyName("client_id")]
        public string? ClientId { get; set; }

        /// <summary>
        /// Gets or sets the username of the resource owner who authorized the token.
        /// </summary>
        [JsonPropertyName("username")]
        public string? Username { get; set; }

        /// <summary>
        /// Gets or sets the type of the token (e.g., "Bearer").
        /// </summary>
        [JsonPropertyName("token_type")]
        public string? TokenType { get; set; }

        /// <summary>
        /// Gets or sets the expiration time of the token as a Unix timestamp.
        /// </summary>
        [JsonPropertyName("exp")]
        public long? Exp { get; set; }

        /// <summary>
        /// Gets or sets the time the token was issued as a Unix timestamp.
        /// </summary>
        [JsonPropertyName("iat")]
        public long? Iat { get; set; }

        /// <summary>
        /// Gets or sets the time before which the token is not valid as a Unix timestamp.
        /// </summary>
        [JsonPropertyName("nbf")]
        public long? Nbf { get; set; }

        /// <summary>
        /// Gets or sets the subject of the token.
        /// </summary>
        [JsonPropertyName("sub")]
        public string? Sub { get; set; }

        /// <summary>
        /// Gets or sets the intended audience of the token.
        /// </summary>
        [JsonPropertyName("aud")]
        public string? Aud { get; set; }

        /// <summary>
        /// Gets or sets the issuer of the token.
        /// </summary>
        [JsonPropertyName("iss")]
        public string? Iss { get; set; }

        /// <summary>
        /// Gets or sets the unique identifier for the token.
        /// </summary>
        [JsonPropertyName("jti")]
        public string? Jti { get; set; }

        /// <summary>
        /// Gets or sets the unique identifier for the user.
        /// </summary>
        [JsonPropertyName("uid")]
        public string? Uid { get; set; }
    }
}
