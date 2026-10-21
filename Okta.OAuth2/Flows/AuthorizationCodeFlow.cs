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
    /// Implements the OAuth2 Authorization Code flow with PKCE support.
    /// </summary>
    public class AuthorizationCodeFlow : AuthenticationFlow
    {
        private Uri _authorizeUrl;
        private AuthorizationCodeFlowContext _flowContext;

        /// <summary>
        /// Gets the redirect URI used for the authorization callback.
        /// </summary>
        public string RedirectUri { get; protected set; }

        /// <summary>
        /// Gets or sets the additional parameters included in the authorization request.
        /// </summary>
        public Dictionary<string, string> AdditionalParameters { get; protected set; } = new();

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthorizationCodeFlow"/> class.
        /// </summary>
        /// <param name="client">The OAuth2 client to use for token operations.</param>
        /// <param name="redirectUri">The redirect URI for the authorization callback.</param>
        /// <param name="additionalParameters">Additional parameters for the authorization request.</param>
        public AuthorizationCodeFlow(OAuth2Client client, string redirectUri, Dictionary<string, string>? additionalParameters = null)
        {
            Client = client;
            RedirectUri = redirectUri;
            AdditionalParameters = additionalParameters ?? new();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthorizationCodeFlow"/> class from an <see cref="OktaConfiguration"/>.
        /// </summary>
        /// <param name="config">The Okta configuration. Must have <see cref="Okta.AuthFoundation.OAuth2.OktaConfiguration.RedirectUri"/> set.</param>
        /// <param name="additionalParameters">Additional parameters for the authorization request.</param>
        /// <exception cref="Okta.AuthFoundation.Exceptions.OktaConfigurationException">Thrown when <see cref="Okta.AuthFoundation.OAuth2.OktaConfiguration.RedirectUri"/> is not set.</exception>
        public AuthorizationCodeFlow(OktaConfiguration config, Dictionary<string, string>? additionalParameters = null)
        {
            if (config.RedirectUri is null)
            {
                throw OktaConfigurationException.MissingFieldForFlow("RedirectUri", nameof(AuthorizationCodeFlow));
            }

            Client = new OAuth2Client(config.ToOAuth2ClientConfiguration());
            RedirectUri = config.RedirectUri.ToString();
            AdditionalParameters = additionalParameters ?? new();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthorizationCodeFlow"/> class by loading configuration
        /// from the default <c>Okta.json</c> file.
        /// </summary>
        /// <exception cref="Okta.AuthFoundation.Exceptions.OktaConfigurationException">Thrown when the configuration file is not found or invalid.</exception>
        public AuthorizationCodeFlow()
            : this(OktaConfiguration.LoadDefault())
        {
        }

        /// <summary>
        /// Starts the authorization code flow by generating the authorization URL.
        /// </summary>
        /// <param name="context">Optional context for the flow.</param>
        /// <param name="additionalParameters">Optional additional parameters to pass to the authorization endpoint.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>The authorization URL to redirect the user to.</returns>
        /// <exception cref="System.InvalidOperationException">Thrown when the authorization endpoint is missing from the OpenID configuration.</exception>
        /// <exception cref="System.Exception">Thrown when an error occurs during the authorization flow initialization.</exception>
        public async Task<Uri> StartAsync(AuthorizationCodeFlowContext? context = null, Dictionary<string, string>? additionalParameters = null, CancellationToken cancellationToken = default)
        {
            StartFlow();

            try
            {
                var openIdConfig = await Client.FetchOpenIdConfigurationAsync(cancellationToken).ConfigureAwait(false);
                var flowContext = Prepare(context);
                if (openIdConfig.AuthorizationEndpoint == null)
                {
                    throw new InvalidOperationException("Missing authorization_endpoint.");
                }

                _authorizeUrl = BuildAuthorizeUrl(openIdConfig.AuthorizationEndpoint, flowContext, additionalParameters ?? AdditionalParameters);
                _flowContext = flowContext;
                return _authorizeUrl;
            }
            catch
            {
                Reset();
                throw;
            }
        }

        /// <summary>
        /// Resumes the authorization code flow after the user has been redirected back from the authorization server.
        /// </summary>
        /// <param name="redirectUri">The full redirect URI containing the authorization code or error.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>An <see cref="ApiResponse{Token}"/> containing the token response.</returns>
        /// <exception cref="Okta.AuthFoundation.Exceptions.OAuth2Exception">Thrown when the authorization server returns an error or the state parameter is invalid.</exception>
        /// <exception cref="System.Exception">Thrown when an error occurs during token exchange.</exception>
        public async Task<ApiResponse<Token>> ResumeAsync(string redirectUri, CancellationToken cancellationToken = default)
        {
            if (_flowContext is null)
            {
                throw new InvalidOperationException("StartAsync must be called before ResumeAsync.");
            }

            IsAuthenticating = true;

            try
            {
                IRedirectUriParams values = ParseCallback(redirectUri);
                if (values is ErrorParams errorValues)
                {
                    throw new OAuth2Exception(error: errorValues.Error, errorDescription: errorValues.ErrorDescription);
                }

                var successValues = values as SuccessParams;

                if (successValues.State == null || successValues.State != _flowContext.State)
                {
                    throw new OAuth2Exception("State value parameters do not match.");
                }

                ApiResponse<Token> result = await ExchangeCodeForTokensAsync(successValues.Code, cancellationToken).ConfigureAwait(false);
                return result;
            }
            finally
            {
                Reset();
            }
        }

        private static IRedirectUriParams ParseCallback(string callbackUrl)
        {
            if (!Uri.TryCreate(callbackUrl, UriKind.Absolute, out var uri))
            {
                throw new OAuth2Exception("Invalid redirect URI format.");
            }

            var queryParams = System.Web.HttpUtility.ParseQueryString(uri.Query);

            if (queryParams["error"] != null)
            {
                return new ErrorParams(
                    queryParams["error"],
                    queryParams["error_description"],
                    queryParams["error_uri"]);
            }

            if (queryParams["code"] == null || queryParams["state"] == null)
            {
                throw new OAuth2Exception("Missing required parameters in redirect URI.");
            }

            return new SuccessParams(
                queryParams["code"],
                queryParams["state"]);
        }

        private AuthorizationCodeFlowContext Prepare(AuthorizationCodeFlowContext? providedContext = null)
        {
            var pkce = providedContext?.Pkce ?? Pkce.Generate();

            return new AuthorizationCodeFlowContext
            {
                RedirectUri = providedContext?.RedirectUri ?? new Uri(RedirectUri),
                State = providedContext?.State ?? Crypto.GenerateRandomString(),
                Verifier = pkce.Verifier,
                Pkce = pkce,
                Nonce = providedContext?.Nonce ?? Crypto.GenerateRandomString(),
                Scope = providedContext?.Scope ?? Client.Configuration.Scope,
                MaxAge = providedContext?.MaxAge,
            };
        }

        private Uri BuildAuthorizeUrl(Uri url, AuthorizationCodeFlowContext context, Dictionary<string, string>? additionalParameters = null)
        {
            var uriBuilder = new UriBuilder(url);
            var query = System.Web.HttpUtility.ParseQueryString(uriBuilder.Query);
            query["scope"] = string.Join(" ", context.Scope ?? Client.Configuration.Scope);
            query["state"] = context.State;
            query["client_id"] = Client.Configuration.ClientId;

            query["response_type"] = "code";
            query["redirect_uri"] = context.RedirectUri.ToString();

            if (context.Nonce != null)
            {
                query["nonce"] = context.Nonce;
            }

            if (context.Pkce != null)
            {
                query["code_challenge"] = context.Pkce.Challenge;
                query["code_challenge_method"] = context.Pkce.Method;
            }

            foreach (var param in additionalParameters ?? new Dictionary<string, string>())
            {
                if (query[param.Key] != null)
                {
                    throw new FlowException($"Additional parameter '{param.Key}' conflicts with a reserved parameter name.");
                }

                query[param.Key] = param.Value;
            }

            uriBuilder.Query = query.ToString();
            return uriBuilder.Uri;
        }

        private async Task<ApiResponse<Token>> ExchangeCodeForTokensAsync(string code, CancellationToken cancellationToken = default)
        {
            OpenIdConfiguration openIdConfig = await Client.FetchOpenIdConfigurationAsync(cancellationToken).ConfigureAwait(false);
            AuthorizationCodeFlowTokenRequest tokenRequest = new AuthorizationCodeFlowTokenRequest(
                openIdConfig,
                Client.Configuration.ClientId,
                Client.Configuration.Authentication,
                code,
                _flowContext);
            ApiResponse<Token> response = await Client.ExchangeAsync(tokenRequest, cancellationToken).ConfigureAwait(false);
            return response;
        }
    }
}
