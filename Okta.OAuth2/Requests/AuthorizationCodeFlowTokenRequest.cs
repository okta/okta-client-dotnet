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

using System.Globalization;
using Okta.AuthFoundation.JwtSecurity;
using Okta.AuthFoundation.OAuth2;
using Okta.OAuth2.Flows;

namespace Okta.OAuth2.Requests
{
    /// <summary>
    /// Represents a token request for the authorization code flow.
    /// </summary>
    internal class AuthorizationCodeFlowTokenRequest : OAuth2TokenRequest
    {
        private readonly OpenIdConfiguration _openIdConfiguration;
        private readonly IClientAuthentication _authentication;
        private readonly string _code;
        private readonly string _redirectUri;
        private readonly string? _codeVerifier;
        private readonly string _nonce;
        private readonly int? _maxAge;
        private readonly string[]? _acrValues; // TODO: support acr_values in auth code flow

        internal AuthorizationCodeFlowTokenRequest(
            OpenIdConfiguration openIdConfig,
            string clientId,
            IClientAuthentication authentication,
            string code,
            AuthorizationCodeFlowContext flowContext)
        {
            ClientId = clientId;
            _authentication = authentication;
            Url = openIdConfig.TokenEndpoint;
            _openIdConfiguration = openIdConfig;
            _code = code;
            _redirectUri = flowContext.RedirectUri.ToString();
            _codeVerifier = flowContext.Verifier;
            _maxAge = flowContext.MaxAge;
            _nonce = flowContext.Nonce;
        }

        public override HttpContent Body()
        {
            var parameters = new Dictionary<string, string>
            {
                { "client_id", ClientId },
                { "grant_type", "authorization_code" },
                { "code", _code },
                { "redirect_uri", _redirectUri },
            };

            if (!string.IsNullOrEmpty(_codeVerifier))
            {
                parameters.Add("code_verifier", _codeVerifier);
            }

            if (_maxAge.HasValue)
            {
                parameters.Add("max_age", _maxAge.Value.ToString(CultureInfo.InvariantCulture));
            }

            _authentication.AddAuthentication(this, ClientId, parameters);
            return new FormUrlEncodedContent(parameters);
        }

        public override IdTokenValidatorContext CreateValidatorContext(string[]? supportedAlgs = null)
        {
            return new IdTokenValidatorContext
            {
                SupportedAlgs = supportedAlgs,
                Nonce = _nonce,
                MaxAge = _maxAge,
                AcrValues = _acrValues,
            };
        }
    }
}
