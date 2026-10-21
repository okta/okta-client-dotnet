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

using System.Text.Json.Serialization;
using Microsoft.IdentityModel.JsonWebTokens;
using Okta.AuthFoundation.Exceptions;
using Okta.AuthFoundation.Http;
using Okta.AuthFoundation.JwtSecurity;
using Okta.AuthFoundation.OAuth2;

namespace Okta.AuthFoundation.TokenManagement
{
    /// <summary>
    /// Represents an OAuth2 token.
    /// </summary>
    public class Token
    {
        private readonly ITimeCoordinator _timeCoordinator = OktaServices.Resolve<ITimeCoordinator>();

        /// <summary>
        /// Initializes a new instance of the <see cref="Token"/> class.
        /// </summary>
        public Token()
        {
            IssuedAt = _timeCoordinator.Now;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Token"/> class with the specified <see cref="TokenContext"/>.
        /// </summary>
        /// <param name="context">The token context to associate with this token.</param>
        public Token(TokenContext context)
        {
            Context = context;
            IssuedAt = _timeCoordinator.Now;
        }

        /// <summary>
        /// Gets or sets the type of the token.
        /// </summary>
        [JsonRequired]
        [JsonPropertyName("token_type")]
        public string TokenType { get; init; }

        /// <summary>
        /// Gets or sets the access token value.
        /// </summary>
        [JsonRequired]
        [JsonPropertyName("access_token")]
        public string AccessToken { get; init; }

        /// <summary>
        /// Gets or sets the number of seconds until the token expires, as returned by the authorization server.
        /// </summary>
        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; init; }

        /// <summary>
        /// Gets or sets the refresh token value.
        /// </summary>
        [JsonPropertyName("refresh_token")]
        public string? RefreshToken { get; init; } = null;

        /// <summary>
        /// Gets or sets the device secret value.
        /// </summary>
        [JsonPropertyName("device_secret")]
        public string? DeviceSecret { get; init; } = null;

        [JsonPropertyName("id_token")]
        [JsonInclude]
        private string? _idTokenRaw;

        // IdToken cannot recursively check if it is null, nor can it access its own
        // backing field in the getter, so we make our own backing field here
        private Jwt? _idToken;

        /// <summary>
        /// Gets or sets the ID token.
        /// </summary>
        [JsonIgnore]
        public Jwt? IdToken
        {
            get
            {
                if (_idToken != null)
                {
                    return _idToken;
                }

                if (!string.IsNullOrEmpty(_idTokenRaw))
                {
                    _idToken = new Jwt(_idTokenRaw);
                    return _idToken;
                }

                return null;
            }

            set
            {
                _idTokenRaw = value?.EncodedToken;
                _idToken = value;
            }
        }

        /// <summary>
        /// Gets the token identifier, defaulting to a new GUID if not present in the server response.
        /// </summary>
        [JsonPropertyName("id")]
        [JsonInclude]
        public string Id { get; internal set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Gets the context associated with the token.
        /// </summary>
        [JsonPropertyName("token_context")]
        public TokenContext? Context { get; internal set; }

        /// <summary>
        /// Gets the time at which the token was issued, defaulting to the current time if not present in the server response.
        /// </summary>
        [JsonPropertyName("issued_at")]
        public DateTime? IssuedAt { get; init; }

        /// <summary>
        /// Gets the absolute expiration time, calculated from <see cref="IssuedAt"/> and <see cref="ExpiresIn"/>, or <c>null</c> if <see cref="IssuedAt"/> is not set.
        /// </summary>
        [JsonIgnore]
        public DateTime? ExpiresAt => IssuedAt?.AddSeconds(ExpiresIn);

        /// <summary>
        /// Gets or sets the scope of the token as a whitespace-separated string (for JSON serialization).
        /// </summary>
        [JsonPropertyName("scope")]
        [JsonInclude]
        private string? ScopeRaw { get; set; }

        private List<string>? _scope;

        /// <summary>
        /// Gets or sets the scope of the token as a list of strings.
        /// </summary>
        [JsonIgnore]
        public List<string>? Scope
        {
            get
            {
                if (_scope != null)
                {
                    return _scope;
                }

                if (!string.IsNullOrEmpty(ScopeRaw))
                {
                    _scope = ScopeRaw.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
                    return _scope;
                }

                return null;
            }

            set
            {
                _scope = value;
                ScopeRaw = value != null ? string.Join(" ", value) : null;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the token is being refreshed.
        /// </summary>
        internal bool IsRefreshing { get; set; }

        internal CoalescedResult<ApiResponse<Token>> RefreshAction { get; } = new();

        /// <summary>
        /// Creates a new <see cref="Token"/> by exchanging a refresh token string using the supplied client.
        /// </summary>
        /// <param name="refreshToken">The refresh token string.</param>
        /// <param name="client">The OAuth2 client to use for the exchange.</param>
        /// <returns>The resulting <see cref="Token"/>.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="client"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="refreshToken"/> is null or whitespace.</exception>
        /// <exception cref="OAuth2Exception">Thrown when the OpenID configuration cannot be retrieved or the exchange fails.</exception>
        /// <exception cref="JwtException">Thrown when the ID token in the response fails signature validation.</exception>
        public static async Task<Token> FromAsync(string refreshToken, OAuth2Client client)
        {
            ArgumentNullException.ThrowIfNull(client);
            ArgumentException.ThrowIfNullOrWhiteSpace(refreshToken);

            var openIdConfig = await client.FetchOpenIdConfigurationAsync().ConfigureAwait(false);
            var request = new RefreshRequest(
                refreshToken,
                client.Configuration.ClientId,
                client.Configuration.Authentication,
                string.Join(" ", client.Configuration.Scope),
                openIdConfig);
            var response = await client.ExchangeAsync(request).ConfigureAwait(false);
            if (!response.IsSuccess || response.Result is null)
            {
                throw new OAuth2Exception(string.IsNullOrWhiteSpace(response.ErrorMessage)
                    ? "An unexpected OAuth2 error occurred."
                    : response.ErrorMessage);
            }

            return response.Result;
        }

        /// <summary>
        /// Returns a token of the requested type.
        /// </summary>
        /// <param name="kind">The kind of token to retrieve.</param>
        /// <returns>The token value of the requested type.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown if the token kind is not recognized.</exception>
        public string RetrieveToken(TokenKind kind)
        {
            switch (kind)
            {
                case TokenKind.RefreshToken:
                    if (string.IsNullOrEmpty(RefreshToken))
                    {
                        throw new InvalidOperationException("This token does not contain a refresh token.");
                    }

                    return RefreshToken;
                case TokenKind.AccessToken:
                    return AccessToken;
                case TokenKind.IdToken:
                    if (IdToken is null)
                    {
                        throw new InvalidOperationException("This token does not contain an ID token.");
                    }

                    return IdToken.EncodedToken;
                case TokenKind.DeviceSecret:
                    if (string.IsNullOrEmpty(DeviceSecret))
                    {
                        throw new InvalidOperationException("This token does not contain a device secret.");
                    }

                    return DeviceSecret;
                default: throw new ArgumentOutOfRangeException(nameof(kind));
            }
        }

        /// <summary>
        /// Merges this token (typically from a refresh response) with an existing token,
        /// returning a new <see cref="Token"/> instance. The existing token's ID is always
        /// preserved so the refreshed token replaces the original in storage. Fields absent
        /// from the refresh response (refresh token, device secret) are carried forward from
        /// the existing token.
        /// </summary>
        /// <param name="existingToken">The existing token to merge with.</param>
        /// <returns>A new <see cref="Token"/> with merged values.</returns>
        public Token Merge(Token existingToken)
        {
            return new Token()
            {
                Id = existingToken.Id,
                TokenType = TokenType,
                ExpiresIn = ExpiresIn,
                AccessToken = AccessToken,
                Scope = Scope,
                RefreshToken = RefreshToken ?? existingToken.RefreshToken,
                IdToken = IdToken,
                DeviceSecret = DeviceSecret ?? existingToken.DeviceSecret,

                // IssuedAt on the response reflects when it was received; without this
                // override the object initializer would leave IssuedAt at whatever the
                // parameterless constructor set (= merge-invocation time).
                IssuedAt = IssuedAt,

                // Refresh responses do not carry token_context, so this.Context is null.
                // Carry the existing credential's context forward so metadata derivation
                // and downstream persistence retain issuer/scope/clientId.
                Context = Context ?? existingToken.Context,
            };
        }

        /// <summary>
        /// Authorizes an outgoing HTTP request by attaching the appropriate authorization header.
        /// </summary>
        /// <param name="request">The HTTP request message to authorize.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (this.TokenType == "DPoP")
            {
                throw new NotSupportedException("DPoP tokens are not supported in this version.");
            }

            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(TokenType, AccessToken);
            return Task.CompletedTask;
        }

        /// <summary>
        /// Returns a string representation of the token.
        /// </summary>
        /// <returns>A string describing the token type, scope, expiry, and identifier.</returns>
        public override string ToString()
        {
            var scope = Scope != null ? string.Join(" ", Scope) : "(none)";
            var expiry = ExpiresIn > 0
                ? $"expires_in={ExpiresIn}s"
                : "no expiry";
            return $"Token(type={TokenType}, scope={scope}, {expiry}, id={Id})";
        }
    }
}