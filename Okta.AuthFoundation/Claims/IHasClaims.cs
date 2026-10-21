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

namespace Okta.AuthFoundation.Claims
{
    /// <summary>
    /// Represents a type that contains a set of claims as a JSON payload.
    /// Implemented by <see cref="Jwt"/>, <see cref="OAuth2.UserInfo"/>, and <see cref="TokenManagement.TokenMetadata"/>.
    /// </summary>
    public interface IHasClaims
    {
        /// <summary>
        /// Gets the claims payload as a dictionary of JSON elements keyed by claim name.
        /// </summary>
        IReadOnlyDictionary<string, JsonElement> Payload { get; }
    }
}
