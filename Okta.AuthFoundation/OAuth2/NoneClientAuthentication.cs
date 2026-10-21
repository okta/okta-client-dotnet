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

namespace Okta.AuthFoundation.OAuth2
{
    /// <summary>
    /// Represents no client authentication. No additional credentials are added to requests.
    /// </summary>
    public sealed class NoneClientAuthentication : IClientAuthentication
    {
        /// <inheritdoc/>
        public ClientAuthentication Method => ClientAuthentication.None;

        /// <inheritdoc/>
        public void AddAuthentication(HttpRequestMessage request, string clientId, Dictionary<string, string> parameters)
        {
            // No additional authentication parameters for this method.
        }
    }
}
