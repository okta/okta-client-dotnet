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

using System.Net;
using Microsoft.IdentityModel.Tokens;
using Okta.AuthFoundation.Exceptions;
using Okta.AuthFoundation.Http;
using Okta.AuthFoundation.JwtSecurity;
using Okta.AuthFoundation.TokenManagement;

namespace Okta.AuthFoundation.OAuth2
{
    /// <summary>
    /// Provides methods for interacting with an OAuth2 server.
    /// </summary>
    public class OAuth2Client : ApiClient, IDisposable
    {
        private readonly IIdTokenValidator _idTokenValidator;
        private readonly ITokenHashValidator _tokenHashValidator;
        private readonly IJwkValidator _jwkValidator;
        private readonly CoalescedResult<OpenIdConfiguration> _openIdConfigurationResult = new(cacheResult: true);

        private JsonWebKeySet? _cachedJwks;

        /// <summary>
        /// Gets the configuration for this client.
        /// </summary>
        public OAuth2ClientConfiguration Configuration { get; }

        /// <summary>
        /// Occurs when a token has been successfully refreshed.
        /// </summary>
        public event EventHandler<TokenRefreshedEventArgs>? TokenRefreshed;

        /// <summary>
        /// Initializes a new instance of the <see cref="OAuth2Client"/> class with the specified configuration.
        /// </summary>
        /// <param name="configuration">The configuration to use for the client.</param>
        public OAuth2Client(OAuth2ClientConfiguration configuration, HttpClient? httpClient = null, IIdTokenValidator? idTokenValidator = null, ITokenHashValidator? tokenHashValidator = null, IJwkValidator? jwkValidator = null)
            : base(configuration.BaseUrl, httpClient ?? OktaServices.Resolve<IHttpClientFactory>().CreateClient(OktaServices.HttpClientName))
        {
            Configuration = configuration;
            _idTokenValidator = idTokenValidator ?? OktaServices.Resolve<IIdTokenValidator>();
            _tokenHashValidator = tokenHashValidator ?? OktaServices.Resolve<ITokenHashValidator>();
            _jwkValidator = jwkValidator ?? OktaServices.Resolve<IJwkValidator>();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OAuth2Client"/> class with the specified base URL, client ID, and scope.
        /// </summary>
        /// <param name="baseUrl">The base URL of the OAuth2 server.</param>
        /// <param name="clientId">The client ID used for authentication.</param>
        /// <param name="scope">The scope requested by the client.</param>
        public OAuth2Client(Uri baseUrl, string clientId, List<string> scope, HttpClient? httpClient = null, IIdTokenValidator? idTokenValidator = null)
            : this(
            new OAuth2ClientConfiguration(baseUrl, clientId, scope), httpClient, idTokenValidator)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OAuth2Client"/> class with the specified base URL, discovery URL, client ID, and scope.
        /// </summary>
        /// <param name="baseUrl">The base URL of the OAuth2 server.</param>
        /// <param name="discoveryUrl">The discovery URL for OpenID configuration.</param>
        /// <param name="clientId">The client ID used for authentication.</param>
        /// <param name="scope">The scope requested by the client.</param>
        public OAuth2Client(Uri baseUrl, Uri discoveryUrl, string clientId, List<string> scope)
            : this(
            new OAuth2ClientConfiguration(baseUrl, discoveryUrl, clientId, scope))
        {
        }

        /// <summary>
        /// Exchanges the specified token request for an OAuth2 token.
        /// </summary>
        /// <param name="request">The token request to exchange.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>An <see cref="ApiResponse{Token}"/> containing the exchanged token.</returns>
        /// <exception cref="ApiException">Thrown when the API returns a non-success response.</exception>
        public virtual async Task<ApiResponse<Token>> ExchangeAsync(OAuth2TokenRequest request, CancellationToken cancellationToken = default)
        {
            Task<ApiResponse<Token>> responseTask = request.SendAsync(this, cancellationToken);
            Task<JsonWebKeySet> jwksTask = JwksAsync(cancellationToken: cancellationToken);
            await Task.WhenAll(responseTask, jwksTask).ConfigureAwait(false);

            ApiResponse<Token> response = responseTask.Result;
            if (response.IsSuccess && response.Result != null)
            {
                Token token = response.Result;
                JsonWebKeySet keySet = jwksTask.Result;
                var tokenContext = new TokenManagement.TokenContext(
                    Configuration.BaseUrl,
                    Configuration.Scope,
                    Configuration.ClientId,
                    Configuration.Authentication.Method.ToString());
                token.Context = tokenContext;
                await ValidateTokenAsync(request, keySet, token, cancellationToken);
            }

            return response;
        }

        /// <summary>
        /// Revokes the specified token or tokens associated with the given revocation type.
        /// </summary>
        /// <param name="token">The token to revoke.</param>
        /// <param name="type">The type of token to revoke.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        public virtual async Task RevokeAsync(Token token, TokenRevokeType type, CancellationToken cancellationToken = default)
        {
            if (type == TokenRevokeType.All)
            {
                await RevokeAllAsync(token, cancellationToken);
                return;
            }

            string tokenString;
            string hint;

            switch (type)
            {
                case TokenRevokeType.Access:
                    tokenString = token.AccessToken;
                    hint = "access_token";
                    break;
                case TokenRevokeType.Refresh:
                    tokenString = token.RefreshToken!;
                    hint = "refresh_token";
                    break;
                case TokenRevokeType.DeviceSecret:
                    tokenString = token.DeviceSecret!;
                    hint = "device_secret";
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, "Invalid TokenRevokeType");
            }

            if (string.IsNullOrEmpty(tokenString) || string.IsNullOrEmpty(hint))
            {
                throw new InvalidOperationException($"Missing expected token {type}");
            }

            var openIdConfig = await FetchOpenIdConfigurationAsync(cancellationToken).ConfigureAwait(false);
            if (openIdConfig.RevocationEndpoint is null)
            {
                throw new InvalidOperationException(
                    $"No revocation endpoint found in the OpenID configuration from '{Configuration.DiscoveryUrl}'.");
            }

            var request = new RevokeRequest(tokenString, hint, Configuration.ClientId, Configuration.Authentication, openIdConfig.RevocationEndpoint);
            var response = await request.SendAsync(this, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccess)
            {
                throw new OAuth2Exception(response.ErrorMessage ?? response.StatusCode.ToString());
            }
        }

        private async Task RevokeAllAsync(Token token, CancellationToken cancellationToken = default)
        {
            var tasks = new List<Task>
            {
                RevokeAsync(token, TokenRevokeType.Access, cancellationToken),
            };

            if (!string.IsNullOrEmpty(token.RefreshToken))
            {
                tasks.Add(RevokeAsync(token, TokenRevokeType.Refresh, cancellationToken));
            }

            if (!string.IsNullOrEmpty(token.DeviceSecret))
            {
                tasks.Add(RevokeAsync(token, TokenRevokeType.DeviceSecret, cancellationToken));
            }

            await Task.WhenAll(tasks).ConfigureAwait(false);
        }

        /// <summary>
        /// Refreshes the specified token using its refresh token.
        /// </summary>
        /// <param name="token">The token to refresh.</param>
        /// <param name="scope">The scope to request, or <see langword="null"/> to use the configured default scope.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>An <see cref="ApiResponse{Token}"/> containing the refreshed token.</returns>
        public virtual async Task<ApiResponse<Token>> RefreshAsync(Token token, List<string>? scope, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(token.RefreshToken))
            {
                throw new InvalidOperationException("No refresh token available");
            }

            var requestedScope = scope ?? Configuration.Scope;

            var response = await token.RefreshAction.PerformAsync(
                () => ExecuteRefreshAsync(token, requestedScope, cancellationToken))
            .ConfigureAwait(false);

            if (response.IsSuccess && response.Result != null)
            {
                var newToken = response.Result.Merge(token);
                OnTokenRefreshed(new TokenRefreshedEventArgs(token, newToken));
                response = ApiResponse<Token>.Success(newToken, HttpStatusCode.OK, response.RequestId);
            }

            return response;
        }

        internal async Task<ApiResponse<Token>> ExecuteRefreshAsync(Token token, IEnumerable<string> scope, CancellationToken cancellationToken = default)
        {
            var refreshToken = token.RefreshToken;
            if (string.IsNullOrEmpty(refreshToken))
            {
                throw new ArgumentException("No refresh token available.", nameof(token));
            }

            var openIdConfig = await FetchOpenIdConfigurationAsync(cancellationToken).ConfigureAwait(false);
            var request = new RefreshRequest(
                refreshToken,
                Configuration.ClientId,
                Configuration.Authentication,
                string.Join(" ", scope),
                openIdConfig);

            var response = await request.SendAsync(this, cancellationToken).ConfigureAwait(false);

            return response;
        }

        /// <summary>
        /// Raises the <see cref="TokenRefreshed"/> event.
        /// </summary>
        /// <param name="e">The event arguments containing the old and new tokens.</param>
        protected virtual void OnTokenRefreshed(TokenRefreshedEventArgs e)
        {
            TokenRefreshed?.Invoke(this, e);
        }

        /// <summary>
        /// Validates the OAuth2 token by verifying the ID token's signature and claims.
        /// </summary>
        /// <param name="request">The token request that was used to obtain the token.</param>
        /// <param name="keySet">The JSON Web Key Set used to verify the token signature.</param>
        /// <param name="token">The token to validate.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>The validated <see cref="Token"/>.</returns>
        protected internal virtual async Task<Token> ValidateTokenAsync(OAuth2TokenRequest request, JsonWebKeySet keySet, Token token, CancellationToken cancellationToken = default)
        {
            if (token.IdToken is null)
            {
                return token;
            }

            OpenIdConfiguration config = await FetchOpenIdConfigurationAsync(cancellationToken).ConfigureAwait(false);
            var context = (IdTokenValidatorContext)request;
            context.SupportedAlgs = config.IdTokenSigningAlgValuesSupported;

            // The configured issuer is the trust anchor for the id token, so this check stays independent of the
            // discovery document that ValidateIssuer corroborates.
            _idTokenValidator.Validate(token.IdToken, Configuration.BaseUrl, Configuration.ClientId, context);

            bool isSignatureValid = false;
            try
            {
                isSignatureValid = await _jwkValidator.ValidateAsync(token.IdToken.InnerToken, keySet.Keys).ConfigureAwait(false);
            }
            catch (SecurityTokenSignatureKeyNotFoundException)
            {
                // try again with refetched keySet
                JsonWebKeySet newKeySet = await JwksAsync(skipCache: true, cancellationToken: cancellationToken).ConfigureAwait(false);
                try
                {
                    isSignatureValid = await _jwkValidator.ValidateAsync(token.IdToken.InnerToken, newKeySet.Keys).ConfigureAwait(false);
                }
                catch (SecurityTokenSignatureKeyNotFoundException)
                {
                }
            }

            if (!isSignatureValid)
            {
                throw new JwtException("Unable to verify id token signature");
            }

            await _tokenHashValidator.ValidateAsync(token.IdToken, token).ConfigureAwait(false);

            return token;
        }

        /// <summary>
        /// Retrieves the JSON Web Key Set from the OpenID provider.
        /// </summary>
        /// <param name="skipCache">Whether to skip the cached value and fetch fresh.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>A <see cref="JsonWebKeySet"/> containing the public keys used to verify token signatures.</returns>
        /// <exception cref="OAuth2Exception">Thrown when the JWKS cannot be retrieved or is invalid.</exception>
        public virtual async Task<JsonWebKeySet> JwksAsync(bool skipCache = false, CancellationToken cancellationToken = default)
        {
            if (!skipCache && _cachedJwks != null)
            {
                return _cachedJwks;
            }

            OpenIdConfiguration config = await FetchOpenIdConfigurationAsync(cancellationToken).ConfigureAwait(false);
            Uri jwksUri = config.JwksUri;

            using HttpResponseMessage response = await Client.GetAsync(jwksUri, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw new OAuth2Exception($"Failed to retrieve Jwks from {jwksUri}");
            }

            string jwksJson = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            JsonWebKeySet jwks = new JsonWebKeySet(jwksJson);

            if (jwks.Keys == null || jwks.Keys.Count == 0)
            {
                throw new OAuth2Exception($"Failed to retrieve Jwks from {jwksUri}");
            }

            _cachedJwks = jwks;

            return jwks;
        }

        /// <summary>
        /// Introspects a token to determine its active state and metadata.
        /// </summary>
        /// <param name="token">The token containing the value to introspect.</param>
        /// <param name="tokenKind">The kind of token to introspect (access or refresh).</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>An <see cref="ApiResponse{IntrospectResponse}"/> containing the introspection result.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the token kind is unsupported.</exception>
        /// <exception cref="InvalidOperationException">Thrown when the introspection endpoint is missing.</exception>
        public virtual async Task<ApiResponse<IntrospectResponse>> IntrospectAsync(Token token, TokenKind tokenKind, CancellationToken cancellationToken = default)
        {
            var openIdConfig = await FetchOpenIdConfigurationAsync(cancellationToken).ConfigureAwait(false);
            if (openIdConfig.IntrospectionEndpoint == null)
            {
                throw new InvalidOperationException(
                    $"No introspection endpoint found in the OpenID configuration from '{Configuration.DiscoveryUrl}'.");
            }

            var request = new IntrospectRequest(token, tokenKind, Configuration.ClientId, Configuration.Authentication, openIdConfig.IntrospectionEndpoint);
            var response = await request.SendAsync(this, cancellationToken).ConfigureAwait(false);

            return response;
        }

        /// <summary>
        /// Retrieves user information from the UserInfo endpoint with a generic type parameter.
        /// </summary>
        /// <typeparam name="T">The type of user information to deserialize. Must inherit from <see cref="UserInfo"/>.</typeparam>
        /// <param name="token">The token whose access token is used to authorize the request.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>An <see cref="ApiResponse{T}"/> containing the user information.</returns>
        public virtual async Task<ApiResponse<T>> UserInfoAsync<T>(Token token, CancellationToken cancellationToken = default)
            where T : UserInfo
        {
            if (string.IsNullOrEmpty(token.AccessToken))
            {
                throw new ArgumentException("Access token cannot be null or empty.", nameof(token));
            }

            var openIdConfig = await FetchOpenIdConfigurationAsync(cancellationToken).ConfigureAwait(false);
            if (openIdConfig.UserInfoEndpoint is null)
            {
                throw new InvalidOperationException(
                    $"No userinfo endpoint found in the OpenID configuration from '{Configuration.DiscoveryUrl}'.");
            }

            var request = new UserInfoRequest<T>(openIdConfig.UserInfoEndpoint);
            await token.AuthorizeAsync(request, cancellationToken).ConfigureAwait(false);
            var response = await request.SendAsync(this, cancellationToken).ConfigureAwait(false);

            return response;
        }

        /// <summary>
        /// Retrieves user information from the UserInfo endpoint with the default <see cref="UserInfo"/> type.
        /// </summary>
        /// <param name="token">The token whose access token is used to authorize the request.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>An <see cref="ApiResponse{UserInfo}"/> containing the user information.</returns>
        public virtual async Task<ApiResponse<UserInfo>> UserInfoAsync(Token token, CancellationToken cancellationToken = default)
        {
            return await UserInfoAsync<UserInfo>(token, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Fetches the OpenID configuration from the discovery URL.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>An <see cref="OpenIdConfiguration"/> object.</returns>
        /// <exception cref="OAuth2Exception">
        /// Thrown when the configuration cannot be retrieved, or when the <c>issuer</c> it declares does not
        /// match the configured <see cref="OAuth2ClientConfiguration.BaseUrl"/>.
        /// </exception>
        public virtual async Task<OpenIdConfiguration> FetchOpenIdConfigurationAsync(CancellationToken cancellationToken = default)
        {
            return await _openIdConfigurationResult.PerformAsync(async () =>
            {
                OpenIdConfigurationRequest request = new OpenIdConfigurationRequest(Configuration.DiscoveryUrl);
                ApiResponse<OpenIdConfiguration> response = await request.SendAsync(this, cancellationToken).ConfigureAwait(false);
                if (!response.IsSuccess || response.Result is null)
                {
                    throw new OAuth2Exception(
                        $"Failed to retrieve OpenID configuration from '{Configuration.DiscoveryUrl}': {(string.IsNullOrWhiteSpace(response.ErrorMessage) ? response.StatusCode.ToString() : response.ErrorMessage)}");
                }

                ValidateIssuer(response.Result.Issuer);

                return response.Result;
            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Verifies that the issuer declared by the discovery document matches the configured
        /// <see cref="OAuth2ClientConfiguration.BaseUrl"/>, as required by OpenID Connect Discovery 1.0 section 4.3.
        /// </summary>
        /// <param name="issuer">The issuer declared by the discovery document.</param>
        private void ValidateIssuer(Uri? issuer)
        {
            if (issuer is null)
            {
                throw new OAuth2Exception(
                    $"The OpenID configuration from '{Configuration.DiscoveryUrl}' does not declare an issuer.");
            }

            if (!issuer.IsAbsoluteUri)
            {
                throw new OAuth2Exception(
                    $"The OpenID configuration from '{Configuration.DiscoveryUrl}' declares issuer '{issuer}', which is not an absolute URL.");
            }

            if (!string.IsNullOrEmpty(issuer.Query) || !string.IsNullOrEmpty(issuer.Fragment))
            {
                throw new OAuth2Exception(
                    $"The OpenID configuration from '{Configuration.DiscoveryUrl}' declares issuer '{issuer}', which contains a query or a fragment.");
            }

            if (!OAuth2ClientConfiguration.IsSameIssuer(Configuration.BaseUrl, issuer))
            {
                throw new OAuth2Exception(
                    $"The OpenID configuration from '{Configuration.DiscoveryUrl}' declares issuer '{issuer}', which does not match the configured issuer '{Configuration.BaseUrl}'.");
            }
        }

        /// <summary>
        /// Releases all resources used by this instance.
        /// </summary>
        public void Dispose()
        {
            _openIdConfigurationResult.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}