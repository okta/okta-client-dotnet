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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Okta.AuthFoundation.TokenManagement
{
    /// <summary>
    /// Defines the contract for token storage, providing methods to store, retrieve, and manage tokens and their metadata.
    /// </summary>
    public interface ITokenStorage
    {
        /// <summary>
        /// Occurs when the default token ID changes.
        /// </summary>
        event EventHandler<DefaultTokenChangedEventArgs>? DefaultTokenChanged;

        /// <summary>
        /// Checks if the storage is empty.
        /// </summary>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>True if storage is empty, false if not.</returns>
        Task<bool> IsEmptyAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets the default token identifier.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>The default token identifier, or <c>null</c> if no default is set.</returns>
        Task<string?> GetDefaultTokenIdAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Sets the default token identifier.
        /// </summary>
        /// <param name="id">The token identifier to set as default.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        Task SetDefaultTokenIdAsync(string? id, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets all token identifiers in storage.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>A list of all token IDs.</returns>
        Task<List<string>> AllIdsAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Adds a token and its optional metadata to storage.
        /// </summary>
        /// <param name="token">The token to add.</param>
        /// <param name="metadata">Optional metadata associated with the token.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        Task AddAsync(Token token, TokenMetadata? metadata, CancellationToken cancellationToken = default);

        /// <summary>
        /// Replaces the token with the specified identifier.
        /// </summary>
        /// <param name="id">The identifier of the token to replace.</param>
        /// <param name="token">The new token value.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        Task ReplaceAsync(string id, Token token, CancellationToken cancellationToken = default);

        /// <summary>
        /// Removes the token with the specified identifier from storage.
        /// </summary>
        /// <param name="id">The identifier of the token to remove.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        Task RemoveAsync(string id, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets the token with the specified identifier.
        /// </summary>
        /// <param name="id">The identifier of the token to retrieve.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>The token if found; otherwise, null.</returns>
        Task<Token?> GetAsync(string id, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets the metadata for the token with the specified identifier.
        /// </summary>
        /// <param name="id">The identifier of the token whose metadata to retrieve.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>The token metadata if found; otherwise, null.</returns>
        Task<TokenMetadata?> GetMetadataAsync(string id, CancellationToken cancellationToken = default);

        /// <summary>
        /// Sets the metadata for a token.
        /// </summary>
        /// <param name="metadata">The metadata to set.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        Task SetMetadataAsync(TokenMetadata metadata, CancellationToken cancellationToken = default);

        /// <summary>
        /// Clears all tokens and metadata from storage.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        Task ClearAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets a value indicating whether claims from the ID token (or JWT-encoded access token) are snapshotted into metadata when storing.
        /// </summary>
        /// <remarks>
        /// Defaults to <c>false</c>, since some implementations store metadata outside the encrypted payload.
        /// Claims-based credential querying requires this to be enabled.
        /// </remarks>
        bool IncludeClaims { get; }
    }
}
