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

using System.Text.Json.Serialization;

namespace Okta.AuthFoundation.OAuth2
{
    /// <summary>
    /// The response returned by the device authorization endpoint.
    /// </summary>
    public class DeviceAuthorizationResponse
    {
        /// <summary>
        /// Gets or sets the device verification code.
        /// </summary>
        [JsonPropertyName("device_code")]
        public string DeviceCode { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the end-user verification code displayed to the user.
        /// </summary>
        [JsonPropertyName("user_code")]
        public string UserCode { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the end-user verification URI on the authorization server.
        /// </summary>
        [JsonPropertyName("verification_uri")]
        public Uri VerificationUri { get; set; } = null!;

        /// <summary>
        /// Gets or sets the verification URI that includes the user code, enabling non-textual transmission.
        /// </summary>
        [JsonPropertyName("verification_uri_complete")]
        public Uri? VerificationUriComplete { get; set; }

        /// <summary>
        /// Gets or sets the lifetime in seconds of the device code and user code.
        /// </summary>
        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }

        /// <summary>
        /// Gets or sets the minimum number of seconds the client should wait between polling requests.
        /// </summary>
        [JsonPropertyName("interval")]
        public int Interval { get; set; } = 5;
    }
}
