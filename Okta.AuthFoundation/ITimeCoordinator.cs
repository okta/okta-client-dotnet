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
    /// Provides a single source of truth for "current time" across the SDK.
    /// </summary>
    /// <remarks>
    /// <para>
    /// End-user system clocks cannot be relied on. Devices drift, users adjust them manually
    /// for a variety of reasons (including changing the date to claim daily rewards in games),
    /// and portable devices roam across time zones. A clock that is wildly off affects every
    /// time-sensitive operation in the SDK: token expiration checks,
    /// <c>iat</c>/<c>auth_time</c>/<c>max_age</c> validation, token acquisition timestamps,
    /// proactive refresh decisions, rate limit header parsing, retry delay calculation, and
    /// device code expiry tracking.
    /// </para>
    /// <para>
    /// The SDK routes every "what time is it?" question through this abstraction so a single
    /// swap point governs the answer. The default implementation (<see cref="DefaultTimeCoordinator"/>)
    /// observes the <c>Date</c> header returned by the authorization server on each response
    /// and offsets the system clock accordingly, converging on the server's view of time.
    /// Consumers who need a different source (a network time service, a hardware-backed
    /// clock, a fixed test clock) can register their own via
    /// <see cref="OktaServices.AddSingleton{TService}(TService)"/> at app startup:
    /// </para>
    /// <code>
    /// OktaServices.AddSingleton&lt;ITimeCoordinator&gt;(new MyCustomTimeCoordinator());
    /// </code>
    /// <para>
    /// The coordinator is resolved as a process-wide singleton. All
    /// <see cref="OAuth2.OAuth2Client"/> instances in the process share the same time source.
    /// In deployments that communicate with more than one authorization server, every server's
    /// <c>Date</c> header feeds into the same offset: the most recently observed response
    /// determines the current adjustment. If those servers have divergent clocks, the offset at
    /// any point reflects whichever server responded last — not necessarily the one whose tokens
    /// are currently being validated. A custom <see cref="ITimeCoordinator"/> can be
    /// registered via <see cref="OktaServices.AddSingleton{TService}(TService)"/>.
    /// </para>
    /// </remarks>
    public interface ITimeCoordinator
    {
        /// <summary>
        /// Gets the coordinator's view of the current time, in UTC.
        /// This is the SDK's canonical answer to "what time is it now?"
        /// </summary>
        public DateTime Now { get; }

        /// <summary>
        /// Adjusts a UTC <see cref="DateTime"/> by the coordinator's current offset, returning
        /// a value in the same frame of reference as <see cref="Now"/>.
        /// </summary>
        /// <param name="dateTime">A UTC <see cref="DateTime"/> to adjust. Passing a local-time
        /// value will produce a result that is not comparable to <see cref="Now"/>.</param>
        /// <returns>The adjusted <see cref="DateTime"/>.</returns>
        public DateTime Date(DateTime dateTime);

        /// <summary>
        /// Notifies the coordinator of a trusted external timestamp (typically the
        /// <c>Date</c> header on an HTTP response from the authorization server). The
        /// default implementation uses this to compute the offset between the system clock
        /// and the trusted source. Custom implementations may ignore the observation if
        /// they source time from elsewhere.
        /// </summary>
        /// <param name="serverDate">The trusted timestamp being observed.</param>
        public void Observe(DateTimeOffset serverDate);
    }
}
