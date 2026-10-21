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

using System.Net.Http.Headers;

namespace Okta.AuthFoundation.Http
{
    /// <summary>
    /// Rate-limit metadata extracted from an API response.
    /// </summary>
    public sealed class ApiRateLimit
    {
        /// <summary>
        /// Gets the maximum number of requests allowed in the current window.
        /// </summary>
        public int Limit { get; }

        /// <summary>
        /// Gets the number of requests remaining in the current window.
        /// </summary>
        public int Remaining { get; }

        /// <summary>
        /// Gets the time at which the rate-limit window resets.
        /// </summary>
        public DateTimeOffset Reset { get; }

        /// <summary>
        /// Gets the recommended delay before retrying, or <c>null</c> if no delay is recommended.
        /// Non-null when a retry delay is indicated by <c>Retry-After</c> or when <see cref="Remaining"/> is 0.
        /// </summary>
        public TimeSpan? Delay { get; }

        private ApiRateLimit(int limit, int remaining, DateTimeOffset reset, TimeSpan? delay)
        {
            Limit = limit;
            Remaining = remaining;
            Reset = reset;
            Delay = delay;
        }

        /// <summary>
        /// Attempts to parse rate-limit metadata from HTTP response headers.
        /// Returns <c>null</c> if the required headers are absent or malformed.
        /// </summary>
        internal static ApiRateLimit? TryParse(HttpResponseHeaders headers, DateTimeOffset responseDate)
        {
            // Check for Retry-After header first (RFC 7231, takes precedence)
            TimeSpan? delay = null;
            if (headers.RetryAfter?.Delta is { } delta)
            {
                delay = delta;
            }
            else if (headers.RetryAfter?.Date is { } retryDate)
            {
                var computed = retryDate - responseDate;
                delay = computed > TimeSpan.Zero ? computed : TimeSpan.Zero;
            }

            // Parse Okta rate-limit headers
            if (!TryGetIntHeader(headers, "X-Rate-Limit-Limit", out var limit) ||
                !TryGetIntHeader(headers, "X-Rate-Limit-Remaining", out var remaining) ||
                !TryGetLongHeader(headers, "X-Rate-Limit-Reset", out var resetEpoch))
            {
                return null;
            }

            var reset = DateTimeOffset.FromUnixTimeSeconds(resetEpoch);

            if (delay == null && remaining <= 0)
            {
                var computed = reset - responseDate;
                delay = computed > TimeSpan.FromSeconds(1) ? computed : TimeSpan.FromSeconds(1);
            }

            return new ApiRateLimit(limit, remaining, reset, delay);
        }

        private static bool TryGetIntHeader(HttpResponseHeaders headers, string name, out int value)
        {
            value = 0;
            return headers.TryGetValues(name, out var values) &&
                   int.TryParse(values.FirstOrDefault(), out value);
        }

        private static bool TryGetLongHeader(HttpResponseHeaders headers, string name, out long value)
        {
            value = 0;
            return headers.TryGetValues(name, out var values) &&
                   long.TryParse(values.FirstOrDefault(), out value);
        }
    }
}
