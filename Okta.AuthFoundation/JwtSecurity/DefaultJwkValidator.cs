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

namespace Okta.AuthFoundation.JwtSecurity
{
    /// <summary>
    /// The default implementation of <see cref="IJwkValidator"/> that validates a JSON Web Token against a set of JSON Web Keys.
    /// </summary>
    public class DefaultJwkValidator : IJwkValidator
    {
        /// <summary>
        /// Validates the signature of a JSON Web Token against the provided key set.
        /// </summary>
        /// <param name="jwt">The JSON Web Token to validate.</param>
        /// <param name="keySet">The list of JSON Web Keys to validate the token signature against.</param>
        /// <returns><see langword="true"/> if the token signature is valid; otherwise, <see langword="false"/>.</returns>
        public async Task<bool> ValidateAsync(JsonWebToken jwt, IList<JsonWebKey> keySet)
        {
            var rawToken = jwt.EncodedToken;
            var handler = new JsonWebTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                RequireSignedTokens = true,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = keySet,
            };

            var result = await handler.ValidateTokenAsync(rawToken, validationParameters);
            if (result.Exception is SecurityTokenSignatureKeyNotFoundException)
            {
                throw result.Exception;
            }

            return result.IsValid;
        }
    }
}
