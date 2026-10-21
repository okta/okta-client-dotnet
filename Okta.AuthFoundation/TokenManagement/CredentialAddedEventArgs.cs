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

namespace Okta.AuthFoundation.TokenManagement
{
    /// <summary>
    /// Provides data for the <see cref="ICredentialDataSource.CredentialAdded"/> event.
    /// </summary>
    public class CredentialAddedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the credential that was added.
        /// </summary>
        public Credential Credential { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="CredentialAddedEventArgs"/> class.
        /// </summary>
        /// <param name="credential">The credential that was added.</param>
        public CredentialAddedEventArgs(Credential credential)
        {
            Credential = credential;
        }
    }
}