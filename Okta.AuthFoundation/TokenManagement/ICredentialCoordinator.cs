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
    /// Defines the contract for a credential coordinator, which manages the lifecycle and retrieval of credentials.
    /// </summary>
    public interface ICredentialCoordinator : IDisposable
    {
        /// <summary>
        /// Gets the default credential, if any.
        /// </summary>
        /// <returns>The default <see cref="Credential"/>, or <c>null</c> if no default is set.</returns>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task<Credential?> GetDefaultAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Sets the default credential, or clears it when <c>null</c> is passed.
        /// </summary>
        /// <param name="credential">The credential to set as the default, or <c>null</c> to clear the default.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task SetDefaultAsync(Credential? credential, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets the token storage instance used by the coordinator.
        /// </summary>
        ITokenStorage TokenStorage { get; }

        /// <summary>
        /// Stores a token and its optional tags, returning the resulting credential.
        /// </summary>
        /// <param name="token">The token to store.</param>
        /// <param name="tags">Optional tags to associate with the credential.</param>
        /// <returns>The <see cref="Credential"/> created from the stored token.</returns>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task<Credential> StoreAsync(Token token, Dictionary<string, string>? tags = null, CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves a credential by its identifier.
        /// </summary>
        /// <param name="id">The identifier of the credential to retrieve.</param>
        /// <returns>The matching <see cref="Credential"/>, or <c>null</c> if not found.</returns>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task<Credential?> WithAsync(string id, CancellationToken cancellationToken = default);

        /// <summary>
        /// Finds credentials matching a predicate on their metadata.
        /// </summary>
        /// <param name="predicate">A function to test each credential's metadata for a condition.</param>
        /// <returns>A list of <see cref="Credential"/> instances whose metadata satisfies the predicate.</returns>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task<List<Credential>> FindAsync(Func<TokenMetadata, bool> predicate, CancellationToken cancellationToken = default);

        /// <summary>
        /// Removes the specified credential from storage.
        /// </summary>
        /// <param name="credential">The credential to remove.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task RemoveAsync(Credential credential, CancellationToken cancellationToken = default);

        /// <summary>
        /// Clears all credentials from storage.
        /// </summary>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task ClearAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets all credential IDs in storage.
        /// </summary>
        /// <returns>A list of all credential identifier strings currently in storage.</returns>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task<List<string>> AllIdsAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Updates the tags on the specified credential and persists the change.
        /// </summary>
        /// <param name="credential">The credential whose tags should be updated.</param>
        /// <param name="tags">The new set of tags to apply, or <c>null</c> to clear all tags.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task UpdateTagsAsync(Credential credential, Dictionary<string, string>? tags, CancellationToken cancellationToken = default);
    }
}
