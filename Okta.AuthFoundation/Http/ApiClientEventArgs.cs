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

using System.Net;

namespace Okta.AuthFoundation.Http
{
    /// <summary>
    /// Provides data for the <see cref="ApiClient.WillSend"/> event, raised before a request is sent.
    /// </summary>
    public class WillSendEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the HTTP request message that is about to be sent.
        /// </summary>
        public HttpRequestMessage Request { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="WillSendEventArgs"/> class.
        /// </summary>
        /// <param name="request">The HTTP request message that is about to be sent.</param>
        public WillSendEventArgs(HttpRequestMessage request)
        {
            Request = request ?? throw new ArgumentNullException(nameof(request));
        }
    }

    /// <summary>
    /// Provides data for the <see cref="ApiClient.DidSend"/> event, raised after a response is received.
    /// </summary>
    public class DidSendEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the HTTP request message that was sent.
        /// </summary>
        public HttpRequestMessage Request { get; }

        /// <summary>
        /// Gets the HTTP status code of the response.
        /// </summary>
        public HttpStatusCode StatusCode { get; }

        /// <summary>
        /// Gets a snapshot of the response headers.
        /// </summary>
        public IReadOnlyDictionary<string, IEnumerable<string>> ResponseHeaders { get; }

        /// <summary>
        /// Gets the request ID from the X-Request-Id response header, if present.
        /// </summary>
        public string? RequestId { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="DidSendEventArgs"/> class
        /// by capturing a snapshot of the response.
        /// </summary>
        /// <param name="request">The HTTP request message that was sent.</param>
        /// <param name="response">The HTTP response message to snapshot.</param>
        public DidSendEventArgs(HttpRequestMessage request, HttpResponseMessage response)
        {
            ArgumentNullException.ThrowIfNull(request);
            ArgumentNullException.ThrowIfNull(response);

            Request = request;
            StatusCode = response.StatusCode;
            ResponseHeaders = response.Headers
                .ToDictionary(h => h.Key, h => h.Value, StringComparer.OrdinalIgnoreCase);
            RequestId = response.Headers.TryGetValues("X-Request-Id", out var rid)
                ? rid.FirstOrDefault()
                : null;
        }
    }
}
