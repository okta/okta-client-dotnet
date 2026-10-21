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
    /// Specifies which token type to revoke.
    /// </summary>
    public enum TokenRevokeType
    {
        /// <summary>
        /// Revokes all tokens associated with the credential.
        /// </summary>
        All,

        /// <summary>
        /// Revokes the access token.
        /// </summary>
        Access,

        /// <summary>
        /// Revokes the refresh token.
        /// </summary>
        Refresh,

        /// <summary>
        /// Revokes the device secret.
        /// </summary>
        DeviceSecret,
    }
}
