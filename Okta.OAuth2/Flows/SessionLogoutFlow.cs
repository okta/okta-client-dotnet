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
using Okta.AuthFoundation.OAuth2;

namespace Okta.OAuth2.Flows
{
    /// <summary>
    /// Implements the OAuth2 session logout flow for ending user sessions.
    /// </summary>
    public class SessionLogoutFlow
    {
        private bool _inProgress;

        /// <summary>
        /// Gets the OAuth2 client used for logout operations.
        /// </summary>
        public OAuth2Client Client { get; }

        /// <summary>
        /// Gets the redirect URI to return to after logout completes.
        /// </summary>
        public Uri LogoutRedirectUri { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SessionLogoutFlow"/> class.
        /// </summary>
        /// <param name="client">The OAuth2 client to use for logout operations.</param>
        /// <param name="logoutRedirectUri">The URI to redirect to after logout completes.</param>
        public SessionLogoutFlow(OAuth2Client client, Uri logoutRedirectUri)
        {
            Client = client;
            LogoutRedirectUri = logoutRedirectUri;
        }

        /// <summary>
        /// Starts the logout flow by generating the logout URL.
        /// </summary>
        /// <param name="context">The logout flow context containing the ID token and state.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>The logout URL to redirect the user to.</returns>
        /// <exception cref="Okta.OAuth2.FlowException">Thrown when the logout flow is already in progress.</exception>
        /// <exception cref="Okta.AuthFoundation.Exceptions.OAuth2Exception">Thrown when the end session endpoint is not available.</exception>
        public async Task<Uri> StartAsync(SessionLogoutFlowContext context, CancellationToken cancellationToken = default)
        {
            if (_inProgress)
            {
                throw new FlowException("Logout flow is already in progress.");
            }

            _inProgress = true;
            try
            {
                var openIdConfig = await Client.FetchOpenIdConfigurationAsync(cancellationToken).ConfigureAwait(false);
                if (openIdConfig.EndSessionEndpoint == null)
                {
                    throw new OAuth2Exception("Missing end_session_endpoint in openid_configuration.");
                }

                var logoutUrl = BuildLogoutUrl(
                    openIdConfig.EndSessionEndpoint,
                    context);
                return logoutUrl;
            }
            finally
            {
                Reset();
            }
        }

        /// <summary>
        /// Resets the logout flow state.
        /// </summary>
        public void Reset()
        {
            _inProgress = false;
        }

        private Uri BuildLogoutUrl(Uri url, SessionLogoutFlowContext context)
        {
            var uriBuilder = new UriBuilder(url);
            var query = System.Web.HttpUtility.ParseQueryString(uriBuilder.Query);
            query["id_token_hint"] = context.IdToken;
            query["post_logout_redirect_uri"] = LogoutRedirectUri.ToString();
            query["state"] = context.State;
            uriBuilder.Query = query.ToString();
            return uriBuilder.Uri;
        }
    }
}
