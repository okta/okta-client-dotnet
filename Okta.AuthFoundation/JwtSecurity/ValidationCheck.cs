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

namespace Okta.AuthFoundation.JwtSecurity
{
    /// <summary>Identifies a specific JWT claim or property to validate.</summary>
    public enum ValidationCheck
    {
        /// <summary>Validates the issuer claim.</summary>
        Issuer,
        /// <summary>Validates the audience claim.</summary>
        Audience,
        /// <summary>Validates the token scheme.</summary>
        Scheme,
        /// <summary>Validates the signing algorithm.</summary>
        Algorithm,
        /// <summary>Validates the expiration time claim.</summary>
        ExpirationTime,
        /// <summary>Validates the issued-at time claim.</summary>
        IssuedAtTime,
        /// <summary>Validates the nonce claim.</summary>
        Nonce,
        /// <summary>Validates the maximum age of the authentication.</summary>
        MaxAge,
        /// <summary>Validates the subject claim.</summary>
        Subject,
        /// <summary>Validates the authentication context class reference claim.</summary>
        Acr,
    }
}
