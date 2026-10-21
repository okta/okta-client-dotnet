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
    /// Defines the contract for a credential data source, which provides credential creation and management operations.
    /// </summary>
    public interface ICredentialDataSource
    {
        /// <summary>
        /// Occurs when a credential is added to the data source.
        /// </summary>
        event EventHandler<CredentialAddedEventArgs>? CredentialAdded;

        /// <summary>
        /// Determines whether a credential exists for the specified token.
        /// </summary>
        /// <param name="token">The token to check for an associated credential.</param>
        /// <returns>True if a credential exists for the token; otherwise, false.</returns>
        bool Has(Token token);

        /// <summary>
        /// Gets or creates a credential for the specified token and optional metadata.
        /// </summary>
        /// <param name="token">The token for which to get or create a credential.</param>
        /// <param name="metadata">Optional metadata associated with the token.</param>
        /// <returns>The credential associated with the token.</returns>
        Credential For(Token token, TokenMetadata? metadata);

        /// <summary>
        /// Removes the specified credential from the data source.
        /// </summary>
        /// <param name="credential">The credential to remove.</param>
        void Remove(Credential credential);

        /// <summary>
        /// Removes the credential with the specified identifier from the data source.
        /// </summary>
        /// <param name="id">The identifier of the credential to remove.</param>
        void Remove(string id);

        /// <summary>
        /// Clears all credentials from the data source.
        /// </summary>
        void Clear();

        /// <summary>
        /// Gets the number of credentials in the data source.
        /// </summary>
        /// <returns>The number of credentials.</returns>
        int Size();
    }
}
