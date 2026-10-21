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

using Okta.AuthFoundation.Http;
using Revoke = Okta.AuthFoundation.Empty;

namespace Okta.AuthFoundation.OAuth2
{
    /// <summary>
    /// Represents an API request to revoke an OAuth2 token.
    /// </summary>
    internal class RevokeRequest : ApiRequest<Revoke>
    {
        private readonly string _tokenString;
        private readonly string _hint;
        private readonly string _clientId;
        private readonly IClientAuthentication _authentication;

        internal RevokeRequest(string tokenString, string hint, string clientId, IClientAuthentication authentication, Uri revocationEndpoint)
        {
            _tokenString = tokenString;
            _hint = hint;
            _clientId = clientId;
            _authentication = authentication;
            Method = HttpMethod.Post;
            Url = revocationEndpoint;
        }

        public override HttpContent? Body()
        {
            var parameters = new Dictionary<string, string>
            {
                { "client_id", _clientId },
                { "token", _tokenString },
                { "token_type_hint", _hint },
            };
            _authentication.AddAuthentication(this, _clientId, parameters);
            return new FormUrlEncodedContent(parameters);
        }
    }
}
