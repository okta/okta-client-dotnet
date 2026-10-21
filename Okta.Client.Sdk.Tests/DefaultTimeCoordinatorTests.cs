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

using Okta.AuthFoundation;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    public class DefaultTimeCoordinatorTests
    {
        [Fact]
        public void Now_BeforeAnyObservation_ReturnsSystemUtcNow()
        {
            var coordinator = new DefaultTimeCoordinator();

            var before = DateTime.UtcNow;
            var now = coordinator.Now;
            var after = DateTime.UtcNow;

            Assert.InRange(now, before, after);
        }

        [Fact]
        public void Offset_BeforeAnyObservation_IsZero()
        {
            var coordinator = new DefaultTimeCoordinator();

            Assert.Equal(TimeSpan.Zero, coordinator.Offset);
        }

        [Fact]
        public void Now_AfterObserve_PositiveOffset()
        {
            var coordinator = new DefaultTimeCoordinator();
            coordinator.Observe(DateTimeOffset.UtcNow.AddMinutes(5));

            var now = coordinator.Now;
            var expected = DateTime.UtcNow.AddMinutes(5);
            Assert.InRange(now, expected.AddSeconds(-1), expected.AddSeconds(1));
        }

        [Fact]
        public void Now_AfterObserve_NegativeOffset()
        {
            var coordinator = new DefaultTimeCoordinator();
            coordinator.Observe(DateTimeOffset.UtcNow.AddMinutes(-5));

            var now = coordinator.Now;
            var expected = DateTime.UtcNow.AddMinutes(-5);
            Assert.InRange(now, expected.AddSeconds(-1), expected.AddSeconds(1));
        }

        [Fact]
        public void Date_AppliesOffset()
        {
            var coordinator = new DefaultTimeCoordinator();
            coordinator.Observe(DateTimeOffset.UtcNow.AddMinutes(10));

            var input = new DateTime(2025, 1, 1, 12, 0, 0, DateTimeKind.Utc);
            var result = coordinator.Date(input);

            Assert.Equal(input + coordinator.Offset, result);
        }

        [Fact]
        public void Observe_UpdatesToLatestValue()
        {
            var coordinator = new DefaultTimeCoordinator();

            coordinator.Observe(DateTimeOffset.UtcNow.AddMinutes(5));
            coordinator.Observe(DateTimeOffset.UtcNow.AddMinutes(10));

            Assert.InRange(coordinator.Offset.TotalMinutes, 9.5, 10.5);
        }

        [Fact]
        public void Observe_IsThreadSafe()
        {
            var coordinator = new DefaultTimeCoordinator();
            var exceptions = new List<Exception>();

            Parallel.For(0, 1000, i =>
            {
                try
                {
                    coordinator.Observe(DateTimeOffset.UtcNow.AddSeconds(i));
                    _ = coordinator.Now;
                    _ = coordinator.Offset;
                }
                catch (Exception ex)
                {
                    lock (exceptions)
                    {
                        exceptions.Add(ex);
                    }
                }
            });

            Assert.Empty(exceptions);
        }
    }
}
