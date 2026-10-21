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
using System.Text.Json.Serialization;

namespace Okta.AuthFoundation.OAuth2
{
    /// <summary>
    /// Represents the OpenID configuration for an OAuth2 server.
    /// </summary>
    public class OpenIdConfiguration
    {
        /// <summary>
        /// Gets or sets the token endpoint URI.
        /// </summary>
        [JsonPropertyName("token_endpoint")]
        [JsonRequired]
        public Uri TokenEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the revocation endpoint URI. May be null if not present in the discovery document.
        /// </summary>
        [JsonPropertyName("revocation_endpoint")]
        public Uri? RevocationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the authorization endpoint URI. May be null if not included in the discovery document.
        /// </summary>
        [JsonPropertyName("authorization_endpoint")]
        public Uri? AuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the end session endpoint URI. May be null if not present in the discovery document.
        /// </summary>
        [JsonPropertyName("end_session_endpoint")]
        public Uri? EndSessionEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the JWKS URI.
        /// </summary>
        [JsonPropertyName("jwks_uri")]
        [JsonRequired]
        public Uri JwksUri { get; set; }

        /// <summary>
        /// Gets or sets the issuer URI.
        /// </summary>
        [JsonPropertyName("issuer")]
        [JsonRequired]
        public Uri Issuer { get; set; }

        /// <summary>
        /// Gets or sets the introspection endpoint URI. May be null if not present in the discovery document.
        /// </summary>
        [JsonPropertyName("introspection_endpoint")]
        public Uri? IntrospectionEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the userinfo endpoint URI. May be null if not present in the discovery document.
        /// </summary>
        [JsonPropertyName("userinfo_endpoint")]
        public Uri? UserInfoEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the device authorization endpoint URI. May be null if not present in the discovery document.
        /// </summary>
        [JsonPropertyName("device_authorization_endpoint")]
        public Uri? DeviceAuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the supported ID token signing algorithms.
        /// </summary>
        [JsonPropertyName("id_token_signing_alg_values_supported")]
        public string[]? IdTokenSigningAlgValuesSupported { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConfiguration"/> class with the specified issuer, token endpoint, and JWKS URI.
        /// </summary>
        /// <param name="issuer">The issuer URI.</param>
        /// <param name="tokenEndpoint">The token endpoint URI.</param>
        /// <param name="jwksUri">The JWKS URI.</param>
        public OpenIdConfiguration(Uri issuer, Uri tokenEndpoint, Uri jwksUri)
        {
            Issuer = issuer;
            TokenEndpoint = tokenEndpoint;
            this.JwksUri = jwksUri;
        }
    }
}