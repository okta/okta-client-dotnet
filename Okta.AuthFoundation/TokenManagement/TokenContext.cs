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
using Okta.AuthFoundation.OAuth2;

namespace Okta.AuthFoundation.TokenManagement
{
    /// <summary>
    /// Provides context about the OAuth2 token's origin, including the issuer, scope, and client ID.
    /// </summary>
    public class TokenContext
    {
        /// <summary>
        /// Gets the issuer URI.
        /// </summary>
        [JsonPropertyName("issuer")]
        public Uri Issuer { get; }

        /// <summary>
        /// Gets the requested scope.
        /// </summary>
        [JsonPropertyName("scope")]
        public List<string> Scope { get; }

        /// <summary>
        /// Gets the client ID.
        /// </summary>
        [JsonPropertyName("client_id")]
        public string ClientId { get; }

        /// <summary>
        /// Gets the client authentication method used when this token was originally minted (e.g. "None", "ClientSecret", "PrivateKeyJwt").
        /// </summary>
        [JsonPropertyName("authentication_method")]
        public string? AuthenticationMethod { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenContext"/> class.
        /// </summary>
        /// <param name="issuer">The issuer URI.</param>
        /// <param name="scope">The requested scope list.</param>
        /// <param name="clientId">The client ID.</param>
        /// <param name="authenticationMethod">The client authentication method name.</param>
        [JsonConstructor]
        public TokenContext(Uri issuer, List<string>? scope, string clientId, string? authenticationMethod = null)
        {
            Issuer = issuer;
            Scope = scope ?? new List<string>();
            ClientId = clientId;
            AuthenticationMethod = authenticationMethod;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenContext"/> class.
        /// </summary>
        /// <param name="issuer">The issuer URI.</param>
        /// <param name="scope">The requested scope as an enumerable sequence.</param>
        /// <param name="clientId">The client ID.</param>
        /// <param name="authenticationMethod">The client authentication method name.</param>
        public TokenContext(Uri issuer, IEnumerable<string>? scope, string clientId, string? authenticationMethod = null)
        {
            Issuer = issuer;
            Scope = scope?.ToList() ?? new List<string>();
            ClientId = clientId;
            AuthenticationMethod = authenticationMethod;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenContext"/> class.
        /// </summary>
        /// <param name="issuer">The issuer URI.</param>
        /// <param name="scope">The requested scope as a space-delimited string.</param>
        /// <param name="clientId">The client ID.</param>
        /// <param name="authenticationMethod">The client authentication method name.</param>
        public TokenContext(Uri issuer, string? scope, string clientId, string? authenticationMethod = null)
        {
            Issuer = issuer;
            Scope = string.IsNullOrEmpty(scope)
                ? new List<string>()
                : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
            ClientId = clientId;
            AuthenticationMethod = authenticationMethod;
        }
    }
}
