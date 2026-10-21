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
    /// Authenticates requests using a shared client secret (<c>client_secret_post</c>, RFC 6749 §2.3.1).
    /// </summary>
    public sealed class ClientSecretAuthentication : IClientAuthentication
    {
        private readonly string _clientSecret;

        /// <summary>
        /// Initializes a new instance of the <see cref="ClientSecretAuthentication"/> class.
        /// </summary>
        /// <param name="clientSecret">The client secret.</param>
        public ClientSecretAuthentication(string clientSecret)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(clientSecret);
            _clientSecret = clientSecret;
        }

        /// <inheritdoc/>
        public ClientAuthentication Method => ClientAuthentication.ClientSecret;

        /// <inheritdoc/>
        public void AddAuthentication(HttpRequestMessage request, string clientId, Dictionary<string, string> parameters)
        {
            parameters["client_secret"] = _clientSecret;
        }
    }
}
