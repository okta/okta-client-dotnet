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

namespace Okta.AuthFoundation
{
    /// <summary>
    /// Default <see cref="ITimeCoordinator"/> implementation. Returns
    /// <see cref="DateTime.UtcNow"/> adjusted by an offset that tracks the last observed
    /// server timestamp, so time-sensitive validations align with the authorization
    /// server's view of "now" rather than a device clock that may be wildly out of sync.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The offset is updated whenever <see cref="Observe(DateTimeOffset)"/> is called;
    /// the SDK invokes this on every HTTP response with a <c>Date</c> header, so the
    /// coordinator converges on the server's time after the first request.
    /// </para>
    /// <para>
    /// Each call to <see cref="Observe(DateTimeOffset)"/> replaces the previous offset
    /// entirely. When multiple
    /// <see cref="OAuth2.OAuth2Client"/> instances point to different authorization servers,
    /// every response from any of those servers updates this single offset. The effective
    /// clock adjustment is always the one computed from the most recent observation; the
    /// servers' timestamps are in contention with each other, not isolated per client.
    /// </para>
    /// </remarks>
    public class DefaultTimeCoordinator : ITimeCoordinator
    {
        private readonly object _lock = new();
        private TimeSpan _offset = TimeSpan.Zero;

        /// <summary>
        /// Gets the current clock offset between local UTC time and the last observed server time.
        /// </summary>
        public TimeSpan Offset
        {
            get
            {
                lock (_lock)
                {
                    return _offset;
                }
            }
        }

        /// <inheritdoc/>
        public DateTime Now => DateTime.UtcNow + Offset;

        /// <inheritdoc/>
        public DateTime Date(DateTime dateTime) => dateTime + Offset;

        /// <inheritdoc/>
        public void Observe(DateTimeOffset serverDate)
        {
            lock (_lock)
            {
                _offset = serverDate - DateTimeOffset.UtcNow;
            }
        }
    }
}
