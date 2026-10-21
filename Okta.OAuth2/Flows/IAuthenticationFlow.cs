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

using Okta.AuthFoundation.OAuth2;

namespace Okta.OAuth2.Flows
{
    /// <summary>
    /// Defines the interface for an authentication flow.
    /// </summary>
    public interface IAuthenticationFlow
    {
        /// <summary>
        /// Gets the OAuth2 client associated with the authentication flow.
        /// </summary>
        OAuth2Client Client { get; }

        /// <summary>
        /// Gets a value indicating whether authentication is in progress.
        /// </summary>
        bool IsAuthenticating { get; }

        /// <summary>
        /// Resets the authentication flow to its initial state.
        /// </summary>
        void Reset();
    }
}
