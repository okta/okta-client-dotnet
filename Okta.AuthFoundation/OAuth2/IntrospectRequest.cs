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

using Okta.AuthFoundation.Exceptions;
using Okta.AuthFoundation.Http;
using Okta.AuthFoundation.TokenManagement;

namespace Okta.AuthFoundation.OAuth2
{
    /// <summary>
    /// Represents an API request to the OAuth2 token introspection endpoint (RFC 7662).
    /// </summary>
    internal class IntrospectRequest : ApiRequest<IntrospectResponse>
    {
        private readonly string _tokenString;
        private readonly string _tokenTypeHint;
        private readonly string _clientId;
        private readonly IClientAuthentication _authentication;

        internal IntrospectRequest(Token token, TokenKind tokenKind, string clientId, IClientAuthentication authentication, Uri introspectionEndpoint)
        {
            switch (tokenKind)
            {
                case TokenKind.AccessToken:
                    _tokenString = token.AccessToken;
                    _tokenTypeHint = "access_token";
                    break;
                case TokenKind.RefreshToken:
                    _tokenString = token.RefreshToken!;
                    _tokenTypeHint = "refresh_token";
                    break;
                case TokenKind.IdToken:
                    _tokenString = token.IdToken?.EncodedToken!;
                    _tokenTypeHint = "id_token";
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(tokenKind), tokenKind, $"Introspection is not supported for token kind: {tokenKind}");
            }

            if (string.IsNullOrEmpty(_tokenString))
            {
                throw new InvalidOperationException($"No {tokenKind} available to introspect");
            }

            _clientId = clientId;
            _authentication = authentication;
            Method = HttpMethod.Post;
            Url = introspectionEndpoint;
        }

        public override HttpContent? Body()
        {
            var parameters = new Dictionary<string, string>
            {
                { "client_id", _clientId },
                { "token", _tokenString },
                { "token_type_hint", _tokenTypeHint },
            };
            _authentication.AddAuthentication(this, _clientId, parameters);
            return new FormUrlEncodedContent(parameters);
        }
    }
}
