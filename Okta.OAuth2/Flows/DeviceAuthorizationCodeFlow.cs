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

using System.Text.Json;
using Okta.AuthFoundation;
using Okta.AuthFoundation.Exceptions;
using Okta.AuthFoundation.Http;
using Okta.AuthFoundation.OAuth2;
using Okta.AuthFoundation.TokenManagement;
using Okta.OAuth2.Requests;

namespace Okta.OAuth2.Flows
{
    /// <summary>
    /// Implements the OAuth2 Device Authorization Code flow for browserless and input-constrained devices.
    /// </summary>
    public class DeviceAuthorizationCodeFlow : AuthenticationFlow
    {
        private readonly ITimeCoordinator _timeCoordinator = OktaServices.Resolve<ITimeCoordinator>();
        private DeviceAuthorizationResponse? _currentResponse;

        /// <summary>
        /// Gets the minimum polling interval in seconds enforced regardless of the server-provided interval.
        /// </summary>
        public int MinimumInterval { get; }

        /// <summary>
        /// Gets the number of seconds added to the polling interval when a slow_down error is received.
        /// </summary>
        public int SlowDownInterval { get; }

        /// <summary>
        /// Gets or sets the additional parameters sent with the device authorization request.
        /// </summary>
        public Dictionary<string, string> AdditionalParameters { get; protected set; } = new();

        /// <summary>
        /// Initializes a new instance of the <see cref="DeviceAuthorizationCodeFlow"/> class.
        /// </summary>
        /// <param name="client">The OAuth2 client to use for token operations.</param>
        /// <param name="additionalParameters">Additional parameters for the device authorization request.</param>
        /// <param name="minimumInterval">The minimum polling interval in seconds enforced regardless of the server-provided interval. Defaults to 5.</param>
        /// <param name="slowDownInterval">The number of seconds added to the polling interval when a slow_down error is received. Defaults to 5.</param>
        public DeviceAuthorizationCodeFlow(OAuth2Client client, Dictionary<string, string>? additionalParameters = null, int minimumInterval = 5, int slowDownInterval = 5)
        {
            Client = client;
            AdditionalParameters = additionalParameters ?? new();
            MinimumInterval = minimumInterval;
            SlowDownInterval = slowDownInterval;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DeviceAuthorizationCodeFlow"/> class from an <see cref="OktaConfiguration"/>.
        /// </summary>
        /// <param name="config">The Okta configuration.</param>
        /// <param name="additionalParameters">Additional parameters for the device authorization request.</param>
        /// <param name="minimumInterval">The minimum polling interval in seconds. Defaults to 5.</param>
        /// <param name="slowDownInterval">The number of seconds added on slow_down errors. Defaults to 5.</param>
        public DeviceAuthorizationCodeFlow(OktaConfiguration config, Dictionary<string, string>? additionalParameters = null, int minimumInterval = 5, int slowDownInterval = 5)
        {
            Client = new OAuth2Client(config.ToOAuth2ClientConfiguration());
            AdditionalParameters = additionalParameters ?? new();
            MinimumInterval = minimumInterval;
            SlowDownInterval = slowDownInterval;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DeviceAuthorizationCodeFlow"/> class by loading configuration
        /// from the default <c>Okta.json</c> file.
        /// </summary>
        /// <exception cref="OktaConfigurationException">Thrown when the configuration file is not found or invalid.</exception>
        public DeviceAuthorizationCodeFlow()
            : this(OktaConfiguration.LoadDefault())
        {
        }

        /// <summary>
        /// Starts the device authorization flow by requesting a device code and user code from the server.
        /// </summary>
        /// <param name="additionalParameters">Additional parameters to include in this specific request, overriding constructor-level parameters.</param>
        /// <returns>A <see cref="DeviceAuthorizationResponse"/> containing the user code and verification URI to display to the user.</returns>
        /// <exception cref="InvalidOperationException">Thrown when the device_authorization_endpoint is missing from the OpenID configuration.</exception>
        /// <exception cref="OAuth2Exception">Thrown when the server returns an error response.</exception>
        public async Task<DeviceAuthorizationResponse> StartAsync(Dictionary<string, string>? additionalParameters = null)
        {
            StartFlow();
            try
            {
                var openIdConfig = await Client.FetchOpenIdConfigurationAsync().ConfigureAwait(false);
                if (openIdConfig.DeviceAuthorizationEndpoint is null)
                {
                    throw new InvalidOperationException("Missing device_authorization_endpoint.");
                }

                var scope = string.Join(" ", Client.Configuration.Scope ?? new List<string>());
                var request = new DeviceAuthorizationRequest(
                    openIdConfig.DeviceAuthorizationEndpoint,
                    Client.Configuration.ClientId,
                    Client.Configuration.Authentication,
                    scope,
                    additionalParameters ?? AdditionalParameters);

                var response = await request.SendAsync(Client).ConfigureAwait(false);
                if (!response.IsSuccess || response.Result is null)
                {
                    throw new OAuth2Exception(response.ErrorMessage);
                }

                _currentResponse = response.Result;
                return _currentResponse;
            }
            catch
            {
                Reset();
                throw;
            }
        }

        /// <summary>
        /// Polls the token endpoint until the user authorizes the device or the authorization expires.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token to cancel polling.</param>
        /// <returns>An <see cref="ApiResponse{Token}"/> containing the token when the user completes authorization.</returns>
        /// <exception cref="InvalidOperationException">Thrown when called before <see cref="StartAsync"/>.</exception>
        /// <exception cref="OAuth2Exception">Thrown when the device authorization expires or is denied.</exception>
        /// <exception cref="OperationCanceledException">Thrown when cancelled via the cancellation token.</exception>
        public async Task<ApiResponse<Token>> ResumeAsync(CancellationToken cancellationToken = default)
        {
            if (_currentResponse is null)
            {
                throw new InvalidOperationException("StartAsync must be called before ResumeAsync.");
            }

            var openIdConfig = await Client.FetchOpenIdConfigurationAsync(cancellationToken).ConfigureAwait(false);
            var interval = Math.Max(MinimumInterval, _currentResponse.Interval);
            var expiry = _timeCoordinator.Now.AddSeconds(_currentResponse.ExpiresIn);

            try
            {
                while (true)
                {
                    await Task.Delay(TimeSpan.FromSeconds(interval), cancellationToken).ConfigureAwait(false);

                    if (_timeCoordinator.Now >= expiry)
                    {
                        throw new OAuth2Exception("Device authorization expired.");
                    }

                    var tokenRequest = new DeviceAuthorizationCodeFlowTokenRequest(
                        openIdConfig,
                        Client.Configuration.ClientId,
                        Client.Configuration.Authentication,
                        _currentResponse.DeviceCode);

                    // Nonce is intentionally not validated in the device authorization flow (RFC 8628).
                    var response = await Client.ExchangeAsync(tokenRequest, cancellationToken).ConfigureAwait(false);

                    if (response.IsSuccess)
                    {
                        return response;
                    }

                    var (error, errorDescription) = ParseOAuthError(response.ErrorMessage);
                    switch (error)
                    {
                        case "authorization_pending":
                            continue;
                        case "slow_down":
                            interval += SlowDownInterval;
                            continue;
                        case "expired_token":
                            throw new OAuth2Exception("Device authorization expired.");
                        case "access_denied":
                            throw new OAuth2Exception(errorDescription ?? "Device authorization access denied.");
                        default:
                            return response;
                    }
                }
            }
            finally
            {
                Reset();
            }
        }

        /// <inheritdoc />
        public override void Reset()
        {
            _currentResponse = null;
            base.Reset();
        }

        private static (string? Error, string? ErrorDescription) ParseOAuthError(string? errorMessage)
        {
            if (string.IsNullOrEmpty(errorMessage))
            {
                return (null, null);
            }

            try
            {
                using var doc = JsonDocument.Parse(errorMessage);
                var error = doc.RootElement.TryGetProperty("error", out var errorProp) ? errorProp.GetString() : null;
                var errorDescription = doc.RootElement.TryGetProperty("error_description", out var descProp) ? descProp.GetString() : null;
                return (error, errorDescription);
            }
            catch (JsonException)
            {
                return (null, null);
            }
        }
    }
}
