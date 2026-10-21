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
    /// <summary>Represents a token to be exchanged in a token exchange flow.</summary>
    public sealed class TokenExchangeToken : ITokenExchangeToken
    {
        /// <summary>Gets the kind of token being exchanged.</summary>
        public TokenKind Kind { get; }

        /// <summary>Gets the raw token string value.</summary>
        public string Value { get; }

        /// <summary>Gets the URN identifying the token type for the exchange request.</summary>
        public string TypeUrn => _urnPrefix + ITokenExchangeToken.KindToSuffix(Kind);

        private readonly string _urnPrefix;

        private TokenExchangeToken(TokenKind kind, string value, string urnPrefix)
        {
            Kind = kind;
            Value = value;
            _urnPrefix = urnPrefix;
        }

        // DeviceSecret is an Okta-proprietary type (urn:x-oath: namespace) and cannot be
        // represented as a subject token, which requires the urn:ietf: namespace.
        /// <summary>Creates a subject token for use in a token exchange request.</summary>
        /// <param name="kind">The kind of token. <see cref="Okta.AuthFoundation.TokenManagement.TokenKind.DeviceSecret"/> is not valid for subject tokens.</param>
        /// <param name="value">The raw token string value.</param>
        /// <returns>A <see cref="TokenExchangeToken"/> configured as a subject token.</returns>
        public static TokenExchangeToken Subject(TokenKind kind, string value)
        {
            if (kind == TokenKind.DeviceSecret)
            {
                throw new ArgumentException("DeviceSecret is not valid as a subject token type. Use Actor instead.", nameof(kind));
            }

            return new TokenExchangeToken(kind, value, "urn:ietf:params:oauth:token-type:");
        }

        /// <summary>Creates an actor token for use in a token exchange request.</summary>
        /// <param name="kind">The kind of token.</param>
        /// <param name="value">The raw token string value.</param>
        /// <returns>A <see cref="TokenExchangeToken"/> configured as an actor token.</returns>
        public static TokenExchangeToken Actor(TokenKind kind, string value)
        {
            return new TokenExchangeToken(kind, value, "urn:x-oath:params:oauth:token-type:");
        }
    }
}
