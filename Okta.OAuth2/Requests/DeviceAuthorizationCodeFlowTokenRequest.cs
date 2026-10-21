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
    internal class DeviceAuthorizationCodeFlowTokenRequest : OAuth2TokenRequest
    {
        private readonly IClientAuthentication _authentication;
        private readonly string _deviceCode;

        internal DeviceAuthorizationCodeFlowTokenRequest(
            OpenIdConfiguration openIdConfig,
            string clientId,
            IClientAuthentication authentication,
            string deviceCode)
        {
            ClientId = clientId;
            _authentication = authentication;
            Url = openIdConfig.TokenEndpoint;
            _deviceCode = deviceCode;
        }

        public override HttpContent Body()
        {
            var parameters = new Dictionary<string, string>
            {
                { "grant_type", "urn:ietf:params:oauth:grant-type:device_code" },
                { "device_code", _deviceCode },
                { "client_id", ClientId },
            };
            _authentication.AddAuthentication(this, ClientId, parameters);
            return new FormUrlEncodedContent(parameters);
        }
    }
}
