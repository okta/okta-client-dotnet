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

namespace Okta.AuthFoundation.Http
{
    /// <summary>
    /// Listener for customizing <see cref="ApiClient"/> retry behavior on HTTP 429 responses.
    /// </summary>
    public interface IApiRetryHandler
    {
        /// <summary>
        /// Called when a 429 response is received to determine whether and how to retry.
        /// </summary>
        /// <param name="client">The client sending the request.</param>
        /// <param name="request">The original request message.</param>
        /// <param name="retryCount">The number of retries already attempted.</param>
        /// <param name="rateLimit">Rate-limit metadata from the 429 response, if available.</param>
        /// <returns>An <see cref="ApiRetry"/> to override the default policy, or <c>null</c> to defer to the next listener or the built-in default (3 retries).</returns>
        ApiRetry? ShouldRetry(ApiClient client, HttpRequestMessage request, int retryCount, ApiRateLimit? rateLimit);
    }
}
