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
using Okta.AuthFoundation.TokenManagement;

namespace Okta.AuthFoundation.JwtSecurity
{
    /// <summary>
    /// Validates token hash claims (at_hash, rt_hash) in an ID token against the actual token values.
    /// </summary>
    public interface ITokenHashValidator
    {
        /// <summary>
        /// Validates the hash claims in the ID token against the corresponding token values.
        /// </summary>
        /// <param name="idToken">The ID token containing hash claims to validate.</param>
        /// <param name="token">The token containing the actual values to hash and compare.</param>
        /// <exception cref="Okta.AuthFoundation.Exceptions.JwtException">Thrown when a hash claim does not match the computed hash.</exception>
        Task ValidateAsync(Jwt idToken, Token token);
    }
}
