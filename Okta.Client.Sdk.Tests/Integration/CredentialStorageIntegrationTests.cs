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
using Okta.AuthFoundation.TokenManagement;
using Xunit;

namespace Okta.Client.Sdk.Tests.Integration
{
    [Trait("Category", "Integration")]
    public class CredentialStorageIntegrationTests : IntegrationTestBase
    {
        [IntegrationFact]
        public async Task StoreAsync_PersistsToDisk_RoundTrip()
        {
            var token = await ObtainTokenAsync();
            var storage = CreateTempStorage();
            var coordinator = new CredentialCoordinator(storage);
            var credential = await coordinator.StoreAsync(token);

            var storage2 = CreateTempStorage();
            var retrieved = await storage2.GetAsync(token.Id);

            Assert.NotNull(retrieved);
            Assert.Equal(token.AccessToken, retrieved.AccessToken);
        }

        [IntegrationFact]
        public async Task StoreAsync_FirstToken_BecomesDefault()
        {
            var token = await ObtainTokenAsync();
            var storage = CreateTempStorage();
            var coordinator = new CredentialCoordinator(storage);

            var credential = await coordinator.StoreAsync(token);
            var defaultCredential = await coordinator.GetDefaultAsync();

            Assert.NotNull(defaultCredential);
            Assert.Equal(credential.Id, defaultCredential.Id);
        }

        [IntegrationFact]
        public async Task MultipleCredentials_AllIDs()
        {
            var token1 = await ObtainTokenAsync();
            var token2 = await ObtainTokenAsync();
            var storage = CreateTempStorage();
            var coordinator = new CredentialCoordinator(storage);

            await coordinator.StoreAsync(token1);
            await coordinator.StoreAsync(token2);

            var ids = await coordinator.AllIdsAsync();
            Assert.Equal(2, ids.Count);
            Assert.Contains(token1.Id, ids);
            Assert.Contains(token2.Id, ids);
        }

        [IntegrationFact]
        public async Task FindAsync_ByTag()
        {
            var token = await ObtainTokenAsync();
            var storage = CreateTempStorage();
            var coordinator = new CredentialCoordinator(storage);
            var tags = new Dictionary<string, string> { ["env"] = "test", ["purpose"] = "integration" };

            await coordinator.StoreAsync(token, tags);

            var results = await coordinator.FindAsync(m =>
                m.Tags != null && m.Tags.TryGetValue("env", out var v) && v == "test");

            Assert.Single(results);
            Assert.Equal(token.Id, results[0].Id);
        }

        [IntegrationFact]
        public async Task SetMetadataAsync_TagsPersist()
        {
            var token = await ObtainTokenAsync();
            var storage = CreateTempStorage();
            var coordinator = new CredentialCoordinator(storage);
            await coordinator.StoreAsync(token);

            var tags = new Dictionary<string, string> { ["key"] = "value" };
            var updatedMetadata = new TokenMetadata(token, tags);
            await storage.SetMetadataAsync(updatedMetadata);

            var storage2 = CreateTempStorage();
            var metadata = await storage2.GetMetadataAsync(token.Id);
            Assert.NotNull(metadata?.Tags);
            Assert.Equal("value", metadata.Tags["key"]);
        }

        [IntegrationFact]
        public async Task RemoveAsync_RemovesTarget()
        {
            var token1 = await ObtainTokenAsync();
            var token2 = await ObtainTokenAsync();
            var storage = CreateTempStorage();
            var coordinator = new CredentialCoordinator(storage);

            var cred1 = await coordinator.StoreAsync(token1);
            await coordinator.StoreAsync(token2);

            await coordinator.RemoveAsync(cred1);

            var ids = await coordinator.AllIdsAsync();
            Assert.Single(ids);
            Assert.Equal(token2.Id, ids[0]);
        }

        [IntegrationFact]
        public async Task ClearAsync_RemovesAll()
        {
            var token1 = await ObtainTokenAsync();
            var token2 = await ObtainTokenAsync();
            var storage = CreateTempStorage();
            var coordinator = new CredentialCoordinator(storage);

            await coordinator.StoreAsync(token1);
            await coordinator.StoreAsync(token2);

            await coordinator.ClearAsync();

            var ids = await coordinator.AllIdsAsync();
            Assert.Empty(ids);
        }
    }
}
