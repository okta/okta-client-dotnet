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
using Okta.AuthFoundation.OAuth2;

namespace Okta.AuthFoundation.TokenManagement
{
    /// <summary>
    /// Provides data for the <see cref="OAuth2Client.TokenRefreshed"/> event.
    /// </summary>
    public class TokenRefreshedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the old token that was replaced.
        /// </summary>
        public Token OldToken { get; }

        /// <summary>
        /// Gets the new token that replaced the old one.
        /// </summary>
        public Token NewToken { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenRefreshedEventArgs"/> class.
        /// </summary>
        /// <param name="oldToken">The old token that was replaced.</param>
        /// <param name="newToken">The new token that replaced the old one.</param>
        public TokenRefreshedEventArgs(Token oldToken, Token newToken)
        {
            OldToken = oldToken;
            NewToken = newToken;
        }
    }
}