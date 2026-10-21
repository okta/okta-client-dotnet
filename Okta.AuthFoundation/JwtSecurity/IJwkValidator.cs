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
    /// Validates a JSON Web Token against a set of JSON Web Keys.
    /// </summary>
    public interface IJwkValidator
    {
        /// <summary>
        /// Validates the signature of the specified JWT using the provided key set.
        /// </summary>
        /// <param name="jwt">The JWT to validate.</param>
        /// <param name="keySet">The list of JSON Web Keys to validate against.</param>
        /// <returns>True if the JWT signature is valid; otherwise, false.</returns>
        public Task<bool> ValidateAsync(JsonWebToken jwt, IList<JsonWebKey> keySet);
    }
}
