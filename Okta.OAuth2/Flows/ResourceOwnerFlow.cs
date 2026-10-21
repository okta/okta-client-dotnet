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

using Okta.AuthFoundation;
using Okta.AuthFoundation.Exceptions;
using Okta.AuthFoundation.Http;
using Okta.AuthFoundation.OAuth2;
using Okta.AuthFoundation.TokenManagement;
using Okta.OAuth2.Requests;

namespace Okta.OAuth2.Flows
{
    /// <summary>
    /// Implements the OAuth2 Resource Owner Password Credentials (ROPC) grant.
    /// </summary>
    /// <remarks>
    /// OAuth 2.1 discourages the Resource Owner Password Credentials Grant because it exposes
    /// the user's credentials to the client application. Use <see cref="AuthorizationCodeFlow"/>
    /// with PKCE for new applications. This flow remains fully supported for legacy servers
    /// and scenarios that still require it. See
    /// <see href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.3">
    /// RFC 6749 §4.3</see> for the specification.
    /// </remarks>
    [NotRecommended(
        "Resource Owner Password Credentials Grant is discouraged by OAuth 2.1; use AuthorizationCodeFlow with PKCE for new applications. This flow remains fully supported.",
        Url = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.3")]
    public class ResourceOwnerFlow : AuthenticationFlow
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ResourceOwnerFlow"/> class with the specified OAuth2 client.
        /// </summary>
        /// <param name="client">The OAuth2 client to use.</param>
        public ResourceOwnerFlow(OAuth2Client client)
        {
            Client = client;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ResourceOwnerFlow"/> class with the specified issuer, client ID, and scope.
        /// </summary>
        /// <param name="issuer">The issuer URI.</param>
        /// <param name="clientId">The client ID.</param>
        /// <param name="scope">The scope to request.</param>
        public ResourceOwnerFlow(Uri issuer, string clientId, List<string> scope)
        {
            Client = new OAuth2Client(issuer, clientId, scope);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ResourceOwnerFlow"/> class from an <see cref="OktaConfiguration"/>.
        /// </summary>
        /// <param name="config">The Okta configuration.</param>
        public ResourceOwnerFlow(OktaConfiguration config)
        {
            Client = new OAuth2Client(config.ToOAuth2ClientConfiguration());
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ResourceOwnerFlow"/> class by loading configuration
        /// from the default <c>Okta.json</c> file.
        /// </summary>
        /// <exception cref="OktaConfigurationException">The exception thrown when the configuration file is not found or invalid.</exception>
        public ResourceOwnerFlow()
            : this(OktaConfiguration.LoadDefault())
        {
        }

        /// <summary>
        /// Starts the authentication process using the specified username and password.
        /// </summary>
        /// <param name="username">The username to authenticate.</param>
        /// <param name="password">The password to authenticate.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>An <see cref="Okta.AuthFoundation.Http.ApiResponse{T}"/> containing the <see cref="Okta.AuthFoundation.TokenManagement.Token"/> if authentication is successful.</returns>
        /// <exception cref="Exception">The exception thrown when authentication fails.</exception>
        public async Task<ApiResponse<Token>> StartAsync(string username, string password, CancellationToken cancellationToken = default)
        {
            StartFlow();
            OpenIdConfiguration configuration = await Client.FetchOpenIdConfigurationAsync(cancellationToken).ConfigureAwait(false);
            var scope = string.Join(" ", Client.Configuration.Scope ?? new List<string>());
            ResourceOwnerFlowTokenRequest request = new ResourceOwnerFlowTokenRequest(
                configuration,
                Client.Configuration.ClientId,
                Client.Configuration.Authentication,
                scope,
                username,
                password);
            try
            {
                return await Client.ExchangeAsync(request, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                Reset();
            }
        }
    }
}
