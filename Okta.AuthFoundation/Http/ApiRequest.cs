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

namespace Okta.AuthFoundation.Http
{
    /// <summary>
    /// Non-generic base class for HTTP API requests that inherits from <see cref="System.Net.Http.HttpRequestMessage"/> and provides additional convenience properties.
    /// </summary>
    public abstract class ApiRequest : HttpRequestMessage
    {
        /// <summary>
        /// Gets or sets the target URL for the API request, which also updates <see cref="System.Net.Http.HttpRequestMessage.RequestUri"/>.
        /// </summary>
        public Uri Url
        {
            get => RequestUri;
            set => RequestUri = value;
        }

        /// <summary>
        /// Gets or sets the query string parameters to append to the URL.
        /// </summary>
        public Dictionary<string, string>? Query { get; set; }

        /// <summary>
        /// Gets or sets a retry policy override for this specific request.
        /// When set, takes precedence over any registered <see cref="IApiRetryHandler"/> and the built-in default.
        /// </summary>
        public ApiRetry? Retry { get; set; }

        /// <summary>
        /// Provides the HTTP content for the request body.
        /// Override this method to supply custom body content.
        /// </summary>
        /// <returns>The HTTP content to send in the request body, or null if no body is required.</returns>
        public virtual HttpContent? Body()
        {
            return null;
        }

        /// <summary>
        /// Prepares the request for sending by applying query string parameters and body content to the underlying <see cref="System.Net.Http.HttpRequestMessage"/>.
        /// This is called automatically by <see cref="ApiRequest{T}.SendAsync"/>.
        /// </summary>
        public void Prepare()
        {
            if (Query != null && Query.Count > 0)
            {
                var uriBuilder = new UriBuilder(RequestUri);
                var queryString = string.Join("&", Query.Select(kvp =>
                    $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value)}"));
                uriBuilder.Query = queryString;
                RequestUri = uriBuilder.Uri;
            }

            if (Method != HttpMethod.Get && Method != HttpMethod.Head)
            {
                Content = Body();
            }
        }
    }

    /// <summary>
    /// Represents an abstract base class for making HTTP API requests.
    /// </summary>
    /// <typeparam name="T">The type of the expected response data.</typeparam>
    public abstract class ApiRequest<T> : ApiRequest
    {
        /// <summary>
        /// Sends the API request asynchronously using the specified <see cref="ApiClient"/>.
        /// </summary>
        /// <param name="client">The API client used to send the request.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>
        /// A task that represents the asynchronous operation. The task result contains an
        /// <see cref="ApiResponse{T}"/> with the deserialized response data.
        /// </returns>
        public async Task<ApiResponse<T>> SendAsync(ApiClient client, CancellationToken cancellationToken = default)
        {
            Prepare();
            return await client.SendAsync<T>(this, cancellationToken);
        }
    }
}
