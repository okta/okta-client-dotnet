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

namespace Okta.AuthFoundation.TokenManagement
{
    /// <summary>
    /// Represents an OAuth2 credential with static methods for credential management and instance methods for token operations.
    /// </summary>
    public class Credential
    {
        // Not initialized at type-load time; resolved on first use so that OktaServices.Resolve()
        // is not triggered before app startup completes.
        private static ICredentialCoordinator? _coordinatorField;

        /// <summary>
        /// The credential coordinator used for managing credentials.
        /// </summary>
        internal static ICredentialCoordinator Coordinator
        {
            get => _coordinatorField ??= OktaServices.Resolve<ICredentialCoordinator>();
            set => _coordinatorField = value;
        }

        private readonly ITimeCoordinator _timeCoordinator = OktaServices.Resolve<ITimeCoordinator>();

        /// <summary>
        /// Gets the OAuth2 token associated with this credential.
        /// </summary>
        public Token Token { get; protected set; }

        /// <summary>
        /// Metadata associated with the token.
        /// </summary>
        private TokenMetadata metadata;

        /// <summary>
        /// Gets the OAuth2 client used for authentication.
        /// </summary>
        public OAuth2Client Client { get; protected set; }

        /// <summary>
        /// Gets the identifier of the credential (from the token).
        /// </summary>
        public string Id
        {
            get { return Token.Id; }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Credential"/> class.
        /// </summary>
        /// <param name="token">The OAuth2 token.</param>
        /// <param name="client">The OAuth2 client.</param>
        /// <param name="metadata">The token metadata.</param>
        public Credential(Token token, OAuth2Client client, TokenMetadata metadata)
        {
            this.Token = token;
            this.Client = client;
            this.metadata = metadata;
        }

        /// <summary>
        /// Stores a token and returns its associated credential.
        /// </summary>
        /// <param name="token">The token to store.</param>
        /// <param name="tags">Optional tags to associate with the token.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>The stored credential.</returns>
        public static async Task<Credential> StoreAsync(Token token, Dictionary<string, string>? tags = null, CancellationToken cancellationToken = default)
        {
            var credential = await Coordinator.StoreAsync(token, tags, cancellationToken);
            return credential;
        }

        /// <summary>
        /// Sets the specified credential as the default. Pass <c>null</c> to clear the default.
        /// </summary>
        /// <param name="credential">The credential to set as default, or <c>null</c> to clear the default.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        public static async Task SetDefaultAsync(Credential? credential, CancellationToken cancellationToken = default)
        {
            await Coordinator.SetDefaultAsync(credential, cancellationToken);
        }

        /// <summary>
        /// Gets all credential IDs.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>A list of all credential IDs.</returns>
        public static async Task<List<string>> AllIDsAsync(CancellationToken cancellationToken = default)
        {
            return await Coordinator.AllIdsAsync(cancellationToken);
        }

        /// <summary>
        /// Gets the default credential, if one is set.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>The default credential, or null if it doesn't exist.</returns>
        public static async Task<Credential?> GetDefaultAsync(CancellationToken cancellationToken = default)
        {
            return await Coordinator.GetDefaultAsync(cancellationToken);
        }

        /// <summary>
        /// Gets the credential for the specified ID, if it exists.
        /// </summary>
        /// <param name="id">The credential ID.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>The credential, or null if not found.</returns>
        public static async Task<Credential?> WithIdAsync(string id, CancellationToken cancellationToken = default)
        {
            return await Coordinator.WithAsync(id, cancellationToken);
        }

        /// <summary>
        /// Finds credentials matching the specified predicate on metadata.
        /// </summary>
        /// <param name="predicate">A function to filter metadata.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>A list of matching credentials.</returns>
        public static async Task<List<Credential>> FindAsync(Func<TokenMetadata, bool> predicate, CancellationToken cancellationToken = default)
        {
            return await Coordinator.FindAsync(predicate, cancellationToken);
        }

        /// <summary>
        /// Clears all credentials from storage.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        public static async Task ClearAsync(CancellationToken cancellationToken = default)
        {
            await Coordinator.ClearAsync(cancellationToken);
        }

        /// <summary>
        /// Gets the developer-assigned tags for this credential. Use <see cref="SetTagsAsync"/> to update.
        /// </summary>
        public Dictionary<string, string>? Tags => metadata.Tags;

        /// <summary>
        /// Updates the tags on this credential's token and persists the change to storage.
        /// </summary>
        /// <param name="tags">The new tags dictionary, or null to clear tags.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        public async Task SetTagsAsync(Dictionary<string, string>? tags, CancellationToken cancellationToken = default)
        {
            await Coordinator.UpdateTagsAsync(this, tags, cancellationToken);
            metadata = new TokenMetadata(Token, tags);
        }

        /// <summary>
        /// Refreshes the token associated with this credential.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        public async Task RefreshAsync(CancellationToken cancellationToken = default)
        {
            var oldToken = this.Token;
            var response = await Client.RefreshAsync(oldToken, this.Token.Scope ?? new List<string>(), cancellationToken);
            if (response.IsSuccess && response.Result is not null)
            {
                this.Token = response.Result;
            }
            else
            {
                throw new OAuth2Exception(string.IsNullOrWhiteSpace(response.ErrorMessage) ? "The server returned a success status but the response contained no token data." : response.ErrorMessage);
            }
        }

        /// <summary>
        /// Refreshes the token if needed, based on expiration and grace interval.
        /// </summary>
        /// <param name="gracePeriod">The number of seconds before expiration to consider the token as needing refresh.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        public async Task RefreshIfNeededAsync(int gracePeriod = 30, CancellationToken cancellationToken = default)
        {
            var remainingSeconds = (this.Token.ExpiresAt - _timeCoordinator.Now)?.TotalSeconds;
            if (remainingSeconds == null || remainingSeconds < gracePeriod)
            {
                await this.RefreshAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Removes this credential from storage without revoking the token.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        public async Task RemoveAsync(CancellationToken cancellationToken = default)
        {
            await Coordinator.RemoveAsync(this, cancellationToken);
        }

        /// <summary>
        /// Revokes the token associated with this credential.
        /// </summary>
        /// <param name="type">The type of token to revoke.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>A task representing the asynchronous revoke operation.</returns>
        public async Task RevokeAsync(TokenRevokeType type = TokenRevokeType.All, CancellationToken cancellationToken = default)
        {
            bool shouldRemove = type == TokenRevokeType.All ||
                (type == TokenRevokeType.Access && string.IsNullOrEmpty(Token.RefreshToken)) ||
                (type == TokenRevokeType.Refresh && !string.IsNullOrEmpty(Token.RefreshToken));

            await this.Client.RevokeAsync(this.Token, type, cancellationToken);

            if (shouldRemove)
            {
                await Coordinator.RemoveAsync(this, cancellationToken);
            }
        }

        /// <summary>
        /// Introspects the access token to determine if it is still active, automatically removing the credential from storage if inactive.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>The introspection response.</returns>
        public async Task<IntrospectResponse> IntrospectAsync(CancellationToken cancellationToken = default)
        {
            var response = await Client.IntrospectAsync(this.Token, TokenKind.AccessToken, cancellationToken);
            if (!response.IsSuccess || response.Result == null)
            {
                throw new OAuth2Exception(string.IsNullOrWhiteSpace(response.ErrorMessage) ? "An unexpected OAuth2 error occurred." : response.ErrorMessage);
            }

            if (!response.Result.Active)
            {
                await Coordinator.RemoveAsync(this, cancellationToken);
            }

            return response.Result;
        }

        private UserInfo? _userInfo;

        /// <summary>
        /// Retrieves user information from the UserInfo endpoint, returning a cached result if available.
        /// </summary>
        /// <param name="ignoreCache">Whether to bypass the cache and fetch fresh data from the server.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>The user information.</returns>
        public async Task<UserInfo> UserInfoAsync(bool ignoreCache = false, CancellationToken cancellationToken = default)
        {
            if (_userInfo != null && !ignoreCache)
            {
                return _userInfo;
            }

            var response = await Client.UserInfoAsync(this.Token, cancellationToken);
            if (!response.IsSuccess || response.Result == null)
            {
                throw new OAuth2Exception(string.IsNullOrWhiteSpace(response.ErrorMessage) ? "An unexpected OAuth2 error occurred." : response.ErrorMessage);
            }

            _userInfo = response.Result;
            return _userInfo;
        }

        /// <summary>
        /// Authorizes an outgoing HttpRequestMessage using this credential's token.
        /// </summary>
        /// <param name="request">The HttpRequestMessage to authorize.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        public async Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken = default)
        {
            await this.Token.AuthorizeAsync(request, cancellationToken);
        }
    }
}
