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

using Okta.AuthFoundation.OAuth2;

namespace Okta.AuthFoundation.JwtSecurity
{
    /// <summary>Provides context used to validate an ID token.</summary>
    public class IdTokenValidatorContext
    {
        /// <summary>Converts an <see cref="Okta.AuthFoundation.OAuth2.OAuth2TokenRequest"/> to an <see cref="IdTokenValidatorContext"/>.</summary>
        /// <param name="request">The token request to convert.</param>
        /// <returns>An <see cref="IdTokenValidatorContext"/> populated from the request.</returns>
        public static explicit operator IdTokenValidatorContext(OAuth2TokenRequest request)
        {
            return request.CreateValidatorContext();
        }

        /// <summary>Gets or sets the nonce value to validate against the ID token.</summary>
        public string? Nonce { get; set; }

        /// <summary>Gets or sets the maximum allowed authentication age, in seconds.</summary>
        public int? MaxAge { get; set; }

        /// <summary>Gets or sets the set of signing algorithms accepted for the ID token.</summary>
        public string[]? SupportedAlgs { get; set; }

        /// <summary>Gets or sets the required Authentication Context Class Reference values.</summary>
        public string[]? AcrValues { get; set; }
    }
}
