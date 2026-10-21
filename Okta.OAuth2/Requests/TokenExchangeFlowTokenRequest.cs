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
    internal class TokenExchangeFlowTokenRequest : OAuth2TokenRequest
    {
        private static readonly HashSet<string> ReservedParameters = new(StringComparer.OrdinalIgnoreCase)
        {
            "grant_type", "client_id", "scope", "audience",
            "subject_token", "subject_token_type",
            "actor_token", "actor_token_type",
        };

        private readonly IClientAuthentication _authentication;
        private readonly ITokenExchangeToken _subjectToken;
        private readonly ITokenExchangeToken? _actorToken;
        private readonly string? _scope;
        private readonly string? _audience;
        private readonly Dictionary<string, string>? _additionalParameters;

        internal TokenExchangeFlowTokenRequest(
            OpenIdConfiguration openIdConfig,
            string clientId,
            IClientAuthentication authentication,
            ITokenExchangeToken subjectToken,
            ITokenExchangeToken? actorToken,
            string? scope,
            string? audience,
            Dictionary<string, string>? additionalParameters)
        {
            ClientId = clientId;
            _authentication = authentication;
            Url = openIdConfig.TokenEndpoint;
            _subjectToken = subjectToken;
            _actorToken = actorToken;
            _scope = scope;
            _audience = audience;
            _additionalParameters = additionalParameters;
        }

        public override HttpContent Body()
        {
            var parameters = new Dictionary<string, string>
            {
                { "grant_type", "urn:ietf:params:oauth:grant-type:token-exchange" },
                { "client_id", ClientId },
            };

            if (!string.IsNullOrEmpty(_scope))
            {
                parameters["scope"] = _scope;
            }

            if (!string.IsNullOrEmpty(_audience))
            {
                parameters["audience"] = _audience;
            }

            if (_additionalParameters != null)
            {
                foreach (var kvp in _additionalParameters)
                {
                    if (ReservedParameters.Contains(kvp.Key))
                    {
                        throw new ArgumentException($"Additional parameter '{kvp.Key}' conflicts with a reserved parameter.", "additionalParameters");
                    }

                    parameters[kvp.Key] = kvp.Value;
                }
            }

            parameters["subject_token"] = _subjectToken.Value;
            parameters["subject_token_type"] = _subjectToken.TypeUrn;

            if (_actorToken != null)
            {
                parameters["actor_token"] = _actorToken.Value;
                parameters["actor_token_type"] = _actorToken.TypeUrn;
            }

            _authentication.AddAuthentication(this, ClientId, parameters);
            return new FormUrlEncodedContent(parameters);
        }
    }
}
