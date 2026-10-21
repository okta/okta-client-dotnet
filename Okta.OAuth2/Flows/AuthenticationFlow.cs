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
    /// Base class for authentication flows that provides common functionality.
    /// </summary>
    public abstract class AuthenticationFlow : IAuthenticationFlow
    {
        /// <inheritdoc />
        public OAuth2Client Client { get; protected set; }

        /// <inheritdoc />
        public bool IsAuthenticating { get; protected set; }

        /// <inheritdoc />
        public virtual void Reset()
        {
            IsAuthenticating = false;
        }

        /// <summary>
        /// Starts the authentication flow.
        /// </summary>
        /// <exception cref="FlowException">Thrown when a flow is already in progress.</exception>
        protected void StartFlow()
        {
            if (IsAuthenticating)
            {
                throw new FlowException("Flow already in progress.");
            }

            IsAuthenticating = true;
        }
    }
}
