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
    /// Coalesces concurrent async operations so only one "in-flight" task runs at a time.
    /// Optionally caches the successful result for the lifetime of the instance.
    /// Errors are always propagated to concurrent callers but are never cached.
    /// </summary>
    /// <typeparam name="T">The type of the result.</typeparam>
    internal class CoalescedResult<T> : IDisposable, IAsyncDisposable
    {
        private readonly SemaphoreSlim _lock = new(1, 1);
        private readonly bool _cacheResult;
        private Task<T>? _activeTask;
        private volatile bool _hasCachedValue;
        private T? _cachedValue;

        /// <summary>
        /// Creates a new <see cref="CoalescedResult{T}"/>.
        /// </summary>
        /// <param name="cacheResult">
        /// When <c>true</c>, the first successful result is cached and returned to all
        /// subsequent callers without re-executing the operation. Errors are never cached.
        /// When <c>false</c> (default), only concurrent in-flight calls are coalesced;
        /// after the operation completes, the next caller starts a fresh execution.
        /// </param>
        public CoalescedResult(bool cacheResult = false)
        {
            _cacheResult = cacheResult;
        }

        /// <summary>
        /// Perform the operation, await an in-flight result, or return the cached value.
        /// </summary>
        /// <param name="operation">The operation to perform if no cached or active task exists.</param>
        /// <returns>The result of the operation.</returns>
        public async Task<T> PerformAsync(Func<Task<T>> operation)
        {
            if (_hasCachedValue)
            {
                return _cachedValue!;
            }

            Task<T> taskToAwait;

            await _lock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (_hasCachedValue)
                {
                    return _cachedValue!;
                }

                if (_activeTask is not null)
                {
                    taskToAwait = _activeTask;
                }
                else
                {
                    _activeTask = ExecuteAsync(operation);
                    taskToAwait = _activeTask;
                }
            }
            finally
            {
                _lock.Release();
            }

            return await taskToAwait.ConfigureAwait(false);
        }

        private async Task<T> ExecuteAsync(Func<Task<T>> operation)
        {
            T result;
            try
            {
                result = await operation().ConfigureAwait(false);
            }
            catch
            {
                await _lock.WaitAsync().ConfigureAwait(false);
                try
                {
                    _activeTask = null;
                }
                finally
                {
                    _lock.Release();
                }

                throw;
            }

            await _lock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (_cacheResult)
                {
                    _cachedValue = result;
                    _hasCachedValue = true;
                }

                _activeTask = null;
            }
            finally
            {
                _lock.Release();
            }

            return result;
        }

        public void Dispose()
        {
            _lock.Dispose();
            GC.SuppressFinalize(this);
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            GC.SuppressFinalize(this);
            return ValueTask.CompletedTask;
        }
    }
}
