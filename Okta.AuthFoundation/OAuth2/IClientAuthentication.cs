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
    /// Defines the contract for authenticating an OAuth2 client when interacting with an authorization server.
    /// </summary>
    public interface IClientAuthentication
    {
        /// <summary>
        /// Gets the authentication method this instance represents.
        /// </summary>
        ClientAuthentication Method { get; }

        /// <summary>
        /// Adds client authentication parameters to the outgoing request body.
        /// </summary>
        /// <param name="request">The outgoing HTTP request, used to read context such as the request URI.</param>
        /// <param name="clientId">The client ID from <see cref="OAuth2ClientConfiguration.ClientId"/>.</param>
        /// <param name="parameters">The form parameters to be included in the request body.</param>
        void AddAuthentication(HttpRequestMessage request, string clientId, Dictionary<string, string> parameters);
    }
}
