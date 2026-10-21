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

using Okta.AuthFoundation.Claims;

namespace Okta.AuthFoundation.JwtSecurity
{
    /// <summary>
    /// Validates an ID token's claims against expected values (issuer, audience, expiration, etc.).
    /// </summary>
    public interface IIdTokenValidator
    {
        /// <summary>
        /// Gets all available validation checks.
        /// </summary>
        public static readonly ValidationCheck[] AllChecks = Enum.GetValues<ValidationCheck>();

        /// <summary>
        /// Validates the ID token's claims.
        /// </summary>
        /// <param name="idToken">The ID token to validate.</param>
        /// <param name="issuer">The expected issuer URI.</param>
        /// <param name="clientId">The expected client ID (audience).</param>
        /// <param name="context">Optional validation context with additional constraints.</param>
        /// <exception cref="Okta.AuthFoundation.Exceptions.JwtException">Thrown when a validation check fails.</exception>
        public void Validate(Jwt idToken, Uri issuer, string clientId, IdTokenValidatorContext? context);
    }
}
