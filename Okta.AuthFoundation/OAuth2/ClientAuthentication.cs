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

namespace Okta.AuthFoundation.OAuth2
{
    /// <summary>
    /// Defines the types of authentication a client may use when interacting with an authorization server.
    /// </summary>
    public enum ClientAuthentication
    {
        /// <summary>
        /// No client authentication; no additional credentials are sent.
        /// </summary>
        None,

        /// <summary>
        /// A shared client secret is used to authenticate the client.
        /// </summary>
        ClientSecret,

        /// <summary>
        /// A signed JWT bearer assertion (RFC 7523) is used to authenticate the client.
        /// The caller is responsible for producing the assertion.
        /// </summary>
        PrivateKeyJwt,
    }
}
