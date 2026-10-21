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

namespace Okta.AuthFoundation.OAuth2
{
    /// <summary>
    /// Represents the configuration settings for an OAuth2 client.
    /// </summary>
    public class OAuth2ClientConfiguration
    {
        private const string OpenIdConfigurationPath = "/.well-known/openid-configuration";

        /// <summary>
        /// Gets the base URL of the OAuth2 server, in canonical form with any trailing slashes removed.
        /// </summary>
        public Uri BaseUrl { get; }

        /// <summary>
        /// Gets the discovery URL for OpenID configuration.
        /// </summary>
        public Uri DiscoveryUrl { get; }

        /// <summary>
        /// Gets the client ID used for authentication.
        /// </summary>
        public string ClientId { get; }

        /// <summary>
        /// Gets the scopes requested by the client.
        /// </summary>
        public IReadOnlyList<string> Scope { get; }

        /// <summary>
        /// Gets the client authentication strategy used when interacting with the authorization server.
        /// Defaults to <see cref="NoneClientAuthentication"/> when not specified.
        /// </summary>
        public IClientAuthentication Authentication { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="OAuth2ClientConfiguration"/> class.
        /// </summary>
        /// <param name="baseUrl">The base URL of the OAuth2 server.</param>
        /// <param name="discoveryUrl">The discovery URL for OpenID configuration.</param>
        /// <param name="clientId">The client ID used for authentication.</param>
        /// <param name="scope">The scope requested by the client.</param>
        /// <param name="authentication">The client authentication strategy. Defaults to <see cref="NoneClientAuthentication"/>.</param>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="baseUrl"/> is relative, or carries a query or fragment. An issuer
        /// identifier may contain neither, per OpenID Connect Core 1.0 section 2.
        /// </exception>
        public OAuth2ClientConfiguration(
            Uri baseUrl,
            Uri discoveryUrl,
            string clientId,
            IEnumerable<string>? scope = null,
            IClientAuthentication? authentication = null)
        {
            BaseUrl = Canonicalize(baseUrl);
            DiscoveryUrl = discoveryUrl;
            ClientId = clientId;
            Scope = scope?.ToList().AsReadOnly() ?? (IReadOnlyList<string>)Array.Empty<string>();
            Authentication = authentication ?? new NoneClientAuthentication();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OAuth2ClientConfiguration"/> class.
        /// </summary>
        /// <param name="baseUrl">The base URL of the OAuth2 server.</param>
        /// <param name="discoveryUrl">The discovery URL for OpenID configuration.</param>
        /// <param name="clientId">The client ID used for authentication.</param>
        /// <param name="scope">The space-delimited scope string requested by the client.</param>
        /// <param name="authentication">The client authentication strategy. Defaults to <see cref="NoneClientAuthentication"/>.</param>
        public OAuth2ClientConfiguration(
            Uri baseUrl,
            Uri discoveryUrl,
            string clientId,
            string scope,
            IClientAuthentication? authentication = null)
            : this(baseUrl, discoveryUrl, clientId, scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList(), authentication)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OAuth2ClientConfiguration"/> class using the default OpenID configuration discovery URL.
        /// </summary>
        /// <param name="baseUrl">The base URL of the OAuth2 server.</param>
        /// <param name="clientId">The client ID used for authentication.</param>
        /// <param name="scope">The scope requested by the client.</param>
        /// <param name="authentication">The client authentication strategy. Defaults to <see cref="NoneClientAuthentication"/>.</param>
        public OAuth2ClientConfiguration(
            Uri baseUrl,
            string clientId,
            IEnumerable<string>? scope = null,
            IClientAuthentication? authentication = null)
            : this(baseUrl, BuildDiscoveryUrl(baseUrl), clientId, scope, authentication)
        {
        }

        /// <summary>
        /// Determines whether two URLs identify the same issuer.
        /// </summary>
        /// <param name="configured">The issuer configured by the consumer.</param>
        /// <param name="declared">The issuer to compare against it.</param>
        /// <returns><see langword="true"/> when both identify the same issuer.</returns>
        internal static bool IsSameIssuer(Uri configured, Uri declared) =>

            // Scheme, host, and port are case-insensitive per RFC 3986; the path is not. Trailing slashes carry
            // no meaning for an issuer identifier, and a server may declare one either way.
            string.Equals(configured.Scheme, declared.Scheme, StringComparison.OrdinalIgnoreCase)
            && string.Equals(configured.Authority, declared.Authority, StringComparison.OrdinalIgnoreCase)
            && string.Equals(
                configured.AbsolutePath.TrimEnd('/'),
                declared.AbsolutePath.TrimEnd('/'),
                StringComparison.Ordinal);

        // Trailing slashes are normalized, not rejected: a persisted TokenContext.Issuer is fed back through
        // these constructors when a stored credential is rehydrated.
        private static Uri Canonicalize(Uri baseUrl)
        {
            ArgumentNullException.ThrowIfNull(baseUrl);

            if (!baseUrl.IsAbsoluteUri)
            {
                throw new ArgumentException($"The issuer URL '{baseUrl}' must be an absolute URL.", nameof(baseUrl));
            }

            if (!string.IsNullOrEmpty(baseUrl.Query) || !string.IsNullOrEmpty(baseUrl.Fragment))
            {
                throw new ArgumentException(
                    $"The issuer URL '{baseUrl}' must not contain a query or a fragment.", nameof(baseUrl));
            }

            string path = baseUrl.AbsolutePath.TrimEnd('/');
            if (string.Equals(path, baseUrl.AbsolutePath, StringComparison.Ordinal))
            {
                return baseUrl;
            }

            return new UriBuilder(baseUrl) { Path = path }.Uri;
        }

        // Assigning the path through UriBuilder keeps the suffix out of any query or fragment.
        private static Uri BuildDiscoveryUrl(Uri baseUrl)
        {
            Uri canonical = Canonicalize(baseUrl);

            return new UriBuilder(canonical)
            {
                Path = canonical.AbsolutePath.TrimEnd('/') + OpenIdConfigurationPath,
            }.Uri;
        }
    }
}
