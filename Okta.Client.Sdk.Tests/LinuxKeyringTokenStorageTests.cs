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

using Okta.AuthFoundation.TokenManagement;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    /// <summary>
    /// Tests for <see cref="LinuxKeyringTokenStorage"/>. Tests run only when a D-Bus session
    /// bus is reachable (see <see cref="KeyringFactAttribute"/>); otherwise they skip cleanly.
    /// </summary>
    public class LinuxKeyringTokenStorageTests : IDisposable
    {
        private readonly LinuxKeyringTokenStorage _storage = new();

        public void Dispose()
        {
            _storage.Dispose();
            GC.SuppressFinalize(this);
        }

        [KeyringFact]
        public async Task AddAndGet_RoundTripsToken()
        {
            await _storage.ClearAsync();

            var token = TestHelpers.CreateToken(id: "kr1", accessToken: "kr-secret");
            var metadata = TestHelpers.CreateTokenMetadata(token, new Dictionary<string, string> { ["env"] = "test" });
            await _storage.AddAsync(token, metadata);

            var retrieved = await _storage.GetAsync("kr1");
            Assert.NotNull(retrieved);
            Assert.Equal("kr-secret", retrieved.AccessToken);

            await _storage.ClearAsync();
        }

        [KeyringFact]
        public async Task AddAndGet_RoundTripsMetadata()
        {
            await _storage.ClearAsync();

            var token = TestHelpers.CreateToken(id: "km1");
            var tags = new Dictionary<string, string> { ["env"] = "test", ["region"] = "us" };
            var metadata = TestHelpers.CreateTokenMetadata(token, tags);
            await _storage.AddAsync(token, metadata);

            var retrieved = await _storage.GetMetadataAsync("km1");
            Assert.NotNull(retrieved);
            Assert.Equal(tags, retrieved.Tags);

            await _storage.ClearAsync();
        }

        [KeyringFact]
        public async Task ClearAsync_RemovesAllTokens()
        {
            var t1 = TestHelpers.CreateToken(id: "kc1");
            await _storage.AddAsync(t1, TestHelpers.CreateTokenMetadata(t1));

            await _storage.ClearAsync();

            Assert.True(await _storage.IsEmptyAsync());
            Assert.Empty(await _storage.AllIdsAsync());
        }

        [KeyringFact]
        public async Task DefaultTokenId_RoundTrips()
        {
            await _storage.ClearAsync();

            var token = TestHelpers.CreateToken(id: "kd1");
            await _storage.AddAsync(token, TestHelpers.CreateTokenMetadata(token));

            Assert.Equal("kd1", await _storage.GetDefaultTokenIdAsync());

            await _storage.ClearAsync();
        }

        [KeyringFact]
        public async Task AddAsync_ThrowsOnDuplicateId()
        {
            await _storage.ClearAsync();

            var token = TestHelpers.CreateToken(id: "kdup1");
            var metadata = TestHelpers.CreateTokenMetadata(token);
            await _storage.AddAsync(token, metadata);

            await Assert.ThrowsAsync<InvalidOperationException>(() => _storage.AddAsync(token, metadata));

            await _storage.ClearAsync();
        }

        [KeyringFact]
        public async Task RemoveAsync_ThrowsOnNonexistentId()
        {
            await Assert.ThrowsAsync<KeyNotFoundException>(() => _storage.RemoveAsync("ghost-keyring"));
        }

        [KeyringFact]
        public void IncludeClaims_DefaultsToFalse()
        {
            Assert.False(_storage.IncludeClaims);
        }

        [KeyringFact]
        public async Task IncludeClaims_Default_DoesNotPersistClaims()
        {
            await _storage.ClearAsync();

            var idToken = TestHelpers.CreateIdToken(subject: "user-123");
            var token = TestHelpers.CreateToken(id: "kr-claims-default", idToken: idToken);
            var metadata = new TokenMetadata(token);
            Assert.NotNull(metadata.Claims);

            await _storage.AddAsync(token, metadata);

            var stored = await _storage.GetMetadataAsync("kr-claims-default");
            Assert.Null(stored!.Claims);

            await _storage.ClearAsync();
        }

        [KeyringFact]
        public async Task IncludeClaims_True_PersistsClaims()
        {
            using var storage = new LinuxKeyringTokenStorage(includeClaims: true);
            await storage.ClearAsync();

            var idToken = TestHelpers.CreateIdToken(subject: "user-123");
            var token = TestHelpers.CreateToken(id: "kr-claims-on", idToken: idToken);
            await storage.AddAsync(token, new TokenMetadata(token));

            var stored = await storage.GetMetadataAsync("kr-claims-on");
            Assert.NotNull(stored!.Claims);
            Assert.Equal("user-123", stored.Claims!["sub"].GetString());

            await storage.ClearAsync();
        }
    }
}
