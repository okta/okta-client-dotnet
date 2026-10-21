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
    /// Represents a retry policy for API requests.
    /// </summary>
    public sealed class ApiRetry
    {
        /// <summary>
        /// Gets the maximum number of retry attempts, where 0 means no retries.
        /// </summary>
        public int MaximumCount { get; }

        private ApiRetry(int maximumCount)
        {
            MaximumCount = maximumCount;
        }

        /// <summary>
        /// The default retry policy: retry up to 3 times.
        /// </summary>
        public static readonly ApiRetry Default = new(3);

        /// <summary>
        /// A policy that disables retries entirely.
        /// </summary>
        public static readonly ApiRetry DoNotRetry = new(0);

        /// <summary>
        /// Creates a retry policy with a specific maximum count.
        /// </summary>
        /// <param name="maximumCount">The maximum number of retry attempts.</param>
        /// <returns>A new <see cref="ApiRetry"/> instance with the specified maximum count.</returns>
        public static ApiRetry Retry(int maximumCount) =>
            maximumCount >= 0 ? new(maximumCount) : throw new ArgumentOutOfRangeException(nameof(maximumCount));
    }
}
