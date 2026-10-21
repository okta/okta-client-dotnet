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

namespace Okta.AuthFoundation.Exceptions
{
    /// <summary>The exception thrown when an OAuth 2.0 authorization server returns an error response.</summary>
    public class OAuth2Exception : Exception
    {
        /// <summary>Gets or sets the OAuth 2.0 error code.</summary>
        public string? Error { get; set; }

        /// <summary>Gets or sets the human-readable description of the error.</summary>
        public string? ErrorDescription { get; set; }

        /// <summary>Gets or sets the URI of a page with more information about the error.</summary>
        public string? ErrorUri { get; set; }

        /// <summary>Initializes a new instance of <see cref="OAuth2Exception"/>.</summary>
        public OAuth2Exception()
        {
        }

        /// <summary>Initializes a new instance of <see cref="OAuth2Exception"/> with the specified message.</summary>
        /// <param name="message">The message that describes the error.</param>
        public OAuth2Exception(string message)
            : base(message)
        {
        }

        /// <summary>Initializes a new instance of <see cref="OAuth2Exception"/> with the specified message and inner exception.</summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public OAuth2Exception(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Initializes a new instance of <see cref="OAuth2Exception"/> with the OAuth 2.0 error fields.</summary>
        /// <param name="error">The OAuth 2.0 error code.</param>
        /// <param name="errorDescription">The human-readable description of the error.</param>
        /// <param name="errorUri">The URI of a page with more information about the error.</param>
        public OAuth2Exception(string error, string? errorDescription = null, string? errorUri = null)
            : base(error)
        {
            Error = error;
            ErrorDescription = errorDescription;
            ErrorUri = errorUri;
        }
    }
}
