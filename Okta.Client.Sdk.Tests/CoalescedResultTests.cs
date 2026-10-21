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
    public class CoalescedResultTests
    {
        [Fact]
        public async Task PerformAsync_ExecutesOperation()
        {
            using var coalesced = new CoalescedResult<int>();
            int executionCount = 0;

            var result = await coalesced.PerformAsync(() =>
            {
                executionCount++;
                return Task.FromResult(42);
            });

            Assert.Equal(42, result);
            Assert.Equal(1, executionCount);
        }

        [Fact]
        public async Task PerformAsync_ExecutesEachSequentialCall()
        {
            using var coalesced = new CoalescedResult<int>();
            int executionCount = 0;

            var result1 = await coalesced.PerformAsync(() =>
            {
                executionCount++;
                return Task.FromResult(executionCount);
            });

            var result2 = await coalesced.PerformAsync(() =>
            {
                executionCount++;
                return Task.FromResult(executionCount);
            });

            Assert.Equal(1, result1);
            Assert.Equal(2, result2);
            Assert.Equal(2, executionCount);
        }

        [Fact]
        public async Task PerformAsync_CoalescesConcurrentRequests()
        {
            using var coalesced = new CoalescedResult<int>();
            int executionCount = 0;
            var operationStarted = new TaskCompletionSource<bool>();
            var operationComplete = new TaskCompletionSource<bool>();

            var tasks = new List<Task<int>>
            {
                coalesced.PerformAsync(async () =>
                {
                    Interlocked.Increment(ref executionCount);
                    operationStarted.SetResult(true);
                    await operationComplete.Task;
                    return 42;
                }),
            };

            await operationStarted.Task;

            for (int i = 0; i < 5; i++)
            {
                tasks.Add(coalesced.PerformAsync(() =>
                {
                    Interlocked.Increment(ref executionCount);
                    return Task.FromResult(100 + i);
                }));
            }

            operationComplete.SetResult(true);

            var results = await Task.WhenAll(tasks);

            Assert.Equal(1, executionCount);
            Assert.All(results, r => Assert.Equal(42, r));
        }

        [Fact]
        public async Task PerformAsync_PropagatesException_ToAllCallers()
        {
            using var coalesced = new CoalescedResult<int>();
            int executionCount = 0;
            var operationStarted = new TaskCompletionSource<bool>();
            var operationComplete = new TaskCompletionSource<bool>();

            var task1 = coalesced.PerformAsync(async () =>
            {
                Interlocked.Increment(ref executionCount);
                operationStarted.SetResult(true);
                await operationComplete.Task;
                throw new InvalidOperationException("Test exception");
#pragma warning disable CS0162
                return 0;
#pragma warning restore CS0162
            });

            await operationStarted.Task;

            var task2 = coalesced.PerformAsync(() =>
            {
                Interlocked.Increment(ref executionCount);
                return Task.FromResult(100);
            });

            operationComplete.SetResult(true);

            await Assert.ThrowsAsync<InvalidOperationException>(() => task1);
            await Assert.ThrowsAsync<InvalidOperationException>(() => task2);
            Assert.Equal(1, executionCount);
        }

        [Fact]
        public async Task PerformAsync_AllowsNewOperation_AfterException()
        {
            using var coalesced = new CoalescedResult<int>();
            int executionCount = 0;

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                coalesced.PerformAsync(() =>
                {
                    executionCount++;
                    throw new InvalidOperationException("Test exception");
#pragma warning disable CS0162
                    return Task.FromResult(0);
#pragma warning restore CS0162
                }));

            var result = await coalesced.PerformAsync(() =>
            {
                executionCount++;
                return Task.FromResult(42);
            });

            Assert.Equal(42, result);
            Assert.Equal(2, executionCount);
        }
    }
}
