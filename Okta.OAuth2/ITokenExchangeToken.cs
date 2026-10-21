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

using Okta.AuthFoundation.TokenManagement;

namespace Okta.OAuth2
{
    /// <summary>Represents a token participating in a token exchange request.</summary>
    public interface ITokenExchangeToken
    {
        /// <summary>Gets the raw token string value.</summary>
        string Value { get; }

        /// <summary>Gets the URN identifying the token type.</summary>
        string TypeUrn { get; }

        internal static string KindToSuffix(TokenKind kind) => kind switch
        {
            TokenKind.AccessToken => "access_token",
            TokenKind.RefreshToken => "refresh_token",
            TokenKind.IdToken => "id_token",
            TokenKind.DeviceSecret => "device-secret",
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
    }
}
