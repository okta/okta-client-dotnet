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

using Okta.AuthFoundation.OAuth2;

namespace Okta.OAuth2.Requests
{
    /// <summary>
    /// Represents a token request for the resource owner password credentials flow.
    /// </summary>
    internal class ResourceOwnerFlowTokenRequest : OAuth2TokenRequest
    {
        private readonly OpenIdConfiguration _openIdConfiguration;
        private readonly IClientAuthentication _authentication;
        private readonly string _scope;
        private readonly string _username;
        private readonly string _password;

        internal ResourceOwnerFlowTokenRequest(
            OpenIdConfiguration openIdConfiguration,
            string clientId,
            IClientAuthentication authentication,
            string scope,
            string username,
            string password)
        {
            _openIdConfiguration = openIdConfiguration;
            ClientId = clientId;
            _authentication = authentication;
            _scope = scope;
            _username = username;
            _password = password;
            Url = _openIdConfiguration.TokenEndpoint;
        }

        public override HttpContent Body()
        {
            var parameters = new Dictionary<string, string>
            {
                { "client_id", ClientId },
                { "scope", _scope },
                { "grant_type", "password" },
                { "username", _username },
                { "password", _password },
            };
            _authentication.AddAuthentication(this, ClientId, parameters);
            return new FormUrlEncodedContent(parameters);
        }
    }
}
