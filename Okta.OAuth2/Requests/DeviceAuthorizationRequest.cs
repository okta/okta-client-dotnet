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
using Okta.AuthFoundation.OAuth2;

namespace Okta.OAuth2.Requests
{
    internal class DeviceAuthorizationRequest : ApiRequest<DeviceAuthorizationResponse>
    {
        private static readonly HashSet<string> ReservedParameters = new(StringComparer.OrdinalIgnoreCase) { "client_id", "scope" };

        private readonly string _clientId;
        private readonly IClientAuthentication _authentication;
        private readonly string _scope;
        private readonly Dictionary<string, string>? _additionalParameters;

        internal DeviceAuthorizationRequest(
            Uri deviceAuthorizationEndpoint,
            string clientId,
            IClientAuthentication authentication,
            string scope,
            Dictionary<string, string>? additionalParameters = null)
        {
            Url = deviceAuthorizationEndpoint;
            Method = HttpMethod.Post;
            _clientId = clientId;
            _authentication = authentication;
            _scope = scope;
            _additionalParameters = additionalParameters;
        }

        public override HttpContent Body()
        {
            var parameters = new Dictionary<string, string>
            {
                { "client_id", _clientId },
                { "scope", _scope },
            };

            if (_additionalParameters != null)
            {
                foreach (var param in _additionalParameters)
                {
                    if (ReservedParameters.Contains(param.Key))
                    {
                        throw new ArgumentException($"Additional parameter '{param.Key}' conflicts with a reserved parameter.", "additionalParameters");
                    }

                    parameters[param.Key] = param.Value;
                }
            }

            _authentication.AddAuthentication(this, _clientId, parameters);
            return new FormUrlEncodedContent(parameters);
        }
    }
}
