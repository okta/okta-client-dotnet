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

namespace Okta.AuthFoundation.TokenManagement
{
    /// <summary>
    /// Provides data for the <see cref="ITokenStorage.DefaultTokenChanged"/> event.
    /// </summary>
    public class DefaultTokenChangedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the previous default token ID, or null if there was no default.
        /// </summary>
        public string? OldDefaultTokenId { get; }

        /// <summary>
        /// Gets the new default token ID, or null if the default was cleared.
        /// </summary>
        public string? NewDefaultTokenId { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultTokenChangedEventArgs"/> class.
        /// </summary>
        /// <param name="oldDefaultTokenId">The previous default token ID.</param>
        /// <param name="newDefaultTokenId">The new default token ID.</param>
        public DefaultTokenChangedEventArgs(string? oldDefaultTokenId, string? newDefaultTokenId)
        {
            OldDefaultTokenId = oldDefaultTokenId;
            NewDefaultTokenId = newDefaultTokenId;
        }
    }
}
