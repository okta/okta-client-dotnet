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

using Okta.AuthFoundation.Http;
using Okta.AuthFoundation.JwtSecurity;
using Okta.AuthFoundation.TokenManagement;

namespace Okta.AuthFoundation.OAuth2
{
    /// <summary>
    /// Represents a request for an OAuth2 token.
    /// </summary>
    public abstract class OAuth2TokenRequest : ApiRequest<Token>
    {
        /// <summary>
        /// Gets or sets the client ID for the token request.
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="OAuth2TokenRequest"/> class.
        /// </summary>
        /// <remarks>Sets the HTTP method to POST as required by OAuth2 token endpoints.</remarks>
        protected OAuth2TokenRequest()
        {
            Method = HttpMethod.Post;
        }

        /// <summary>
        /// Creates an <see cref="Okta.AuthFoundation.JwtSecurity.IdTokenValidatorContext"/> with validation parameters from this request.
        /// </summary>
        /// <param name="supportedAlgs">The supported signing algorithms, or <see langword="null"/> to use defaults.</param>
        /// <returns>An <see cref="Okta.AuthFoundation.JwtSecurity.IdTokenValidatorContext"/> populated from this request.</returns>
        public virtual IdTokenValidatorContext CreateValidatorContext(string[]? supportedAlgs = null)
        {
            return new IdTokenValidatorContext
            {
                SupportedAlgs = supportedAlgs,
            };
        }
    }
}
