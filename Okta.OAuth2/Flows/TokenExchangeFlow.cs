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
using Okta.AuthFoundation.OAuth2;
using Okta.AuthFoundation.TokenManagement;
using Okta.OAuth2.Requests;

namespace Okta.OAuth2.Flows
{
    /// <summary>
    /// Implements the OAuth2 Token Exchange flow (RFC 8693).
    /// </summary>
    public class TokenExchangeFlow : AuthenticationFlow
    {
        /// <summary>
        /// Gets the default audience for token exchange requests.
        /// Set automatically when constructed from an <see cref="OktaConfiguration"/> that includes an audience.
        /// </summary>
        public string? Audience { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenExchangeFlow"/> class.
        /// </summary>
        /// <param name="client">The OAuth2 client to use for token operations.</param>
        public TokenExchangeFlow(OAuth2Client client)
        {
            Client = client;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenExchangeFlow"/> class from an <see cref="Okta.AuthFoundation.OAuth2.OktaConfiguration"/>.
        /// </summary>
        /// <param name="config">The Okta configuration.</param>
        public TokenExchangeFlow(OktaConfiguration config)
        {
            Client = new OAuth2Client(config.ToOAuth2ClientConfiguration());
            Audience = config.Audience;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenExchangeFlow"/> class by loading configuration
        /// from the default <c>Okta.json</c> file.
        /// </summary>
        /// <exception cref="Okta.AuthFoundation.Exceptions.OktaConfigurationException">The exception thrown when the configuration file is not found or invalid.</exception>
        public TokenExchangeFlow()
            : this(OktaConfiguration.LoadDefault())
        {
        }

        /// <summary>
        /// Exchanges the provided tokens for a new token.
        /// </summary>
        /// <param name="subjectToken">The subject token representing the identity being exchanged.</param>
        /// <param name="actorToken">The optional actor token representing the acting party (e.g. a device secret).</param>
        /// <param name="audience">The audience of the target authorization server.</param>
        /// <param name="additionalParameters">Any additional parameters to include in the request.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>An <see cref="Okta.AuthFoundation.Http.ApiResponse{T}"/> containing the exchanged token.</returns>
        /// <exception cref="Okta.OAuth2.FlowException">The exception thrown when a flow is already in progress.</exception>
        public async Task<ApiResponse<Token>> StartAsync(
            ITokenExchangeToken subjectToken,
            ITokenExchangeToken? actorToken = null,
            string? audience = null,
            Dictionary<string, string>? additionalParameters = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(subjectToken);

            StartFlow();
            try
            {
                var openIdConfig = await Client.FetchOpenIdConfigurationAsync(cancellationToken).ConfigureAwait(false);
                var scope = string.Join(" ", Client.Configuration.Scope ?? new List<string>());
                var request = new TokenExchangeFlowTokenRequest(
                    openIdConfig,
                    Client.Configuration.ClientId,
                    Client.Configuration.Authentication,
                    subjectToken,
                    actorToken,
                    string.IsNullOrEmpty(scope) ? null : scope,
                    string.IsNullOrWhiteSpace(audience) ? Audience : audience,
                    additionalParameters);
                return await Client.ExchangeAsync(request, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                Reset();
            }
        }
    }
}
