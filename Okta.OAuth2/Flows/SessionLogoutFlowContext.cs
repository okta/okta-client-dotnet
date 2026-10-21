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

namespace Okta.OAuth2.Flows
{
    /// <summary>
    /// Represents the context for a session logout flow, containing the ID token and state parameter.
    /// </summary>
    public class SessionLogoutFlowContext
    {
        /// <summary>
        /// Gets the ID token to use as a hint for the logout request.
        /// </summary>
        public string IdToken { get; }

        /// <summary>
        /// Gets the state parameter for CSRF protection during logout.
        /// </summary>
        public string State { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SessionLogoutFlowContext"/> class.
        /// </summary>
        /// <param name="idToken">The ID token to use as a hint for the logout request.</param>
        /// <param name="state">The state parameter for CSRF protection.</param>
        public SessionLogoutFlowContext(string idToken, string state)
        {
            IdToken = idToken;
            State = state;
        }
    }
}
