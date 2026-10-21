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
using System.Text.Json.Serialization;
using Okta.AuthFoundation.Claims;

namespace Okta.AuthFoundation.OAuth2
{
    /// <summary>
    /// Represents the user information returned from the UserInfo endpoint.
    /// Implements <see cref="IHasClaims"/> — access claims via extension methods
    /// such as <c>userInfo.Subject()</c>, <c>userInfo.Email()</c>, etc.
    /// Custom claims are accessible via <c>userInfo.GetValue&lt;T&gt;("claim_key")</c>.
    /// </summary>
    public class UserInfo : IHasClaims
    {
        private readonly Dictionary<string, JsonElement> _payload = new(StringComparer.Ordinal);

        IReadOnlyDictionary<string, JsonElement> IHasClaims.Payload => _payload;

        /// <summary>
        /// Gets or sets the raw claim data deserialized from the UserInfo endpoint response.
        /// </summary>
        [JsonExtensionData]
        public Dictionary<string, JsonElement>? AdditionalData
        {
            get => _payload;
            set
            {
                if (value is null)
                {
                    return;
                }

                foreach (var kv in value)
                {
                    _payload[kv.Key] = kv.Value;
                }
            }
        }
    }
}
