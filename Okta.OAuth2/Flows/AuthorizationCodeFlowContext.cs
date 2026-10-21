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
    /// Holds the state required to resume an Authorization Code flow after the redirect.
    /// </summary>
    public class AuthorizationCodeFlowContext
    {
        /// <summary>
        /// Gets the redirect URI used when the authorization request was initiated.
        /// </summary>
        public Uri RedirectUri { get; init; }

        /// <summary>
        /// Gets the state parameter sent in the authorization request.
        /// </summary>
        public string State { get; init; }

        /// <summary>
        /// Gets the PKCE code verifier generated for the authorization request.
        /// </summary>
        public string Verifier { get; init; }

        /// <summary>
        /// Gets the PKCE challenge parameters sent in the authorization request.
        /// </summary>
        public Pkce? Pkce { get; init; }

        /// <summary>
        /// Gets the nonce value sent in the authorization request.
        /// </summary>
        public string? Nonce { get; init; }

        /// <summary>
        /// Gets the scopes requested in the authorization request.
        /// </summary>
        public IReadOnlyList<string>? Scope { get; init; }

        /// <summary>
        /// Gets the maximum authentication age requested in the authorization request.
        /// </summary>
        public int? MaxAge { get; init; }
    }
}
