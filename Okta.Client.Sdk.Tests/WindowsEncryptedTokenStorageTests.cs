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

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Okta.AuthFoundation.TokenManagement;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    public class WindowsEncryptedTokenStorageTests : IDisposable
    {
        private readonly string _tempFile;
        private readonly WindowsEncryptedTokenStorage? _storage;

        public WindowsEncryptedTokenStorageTests()
        {
            _tempFile = Path.Combine(Path.GetTempPath(), $"okta-enc-test-{Guid.NewGuid()}.json");
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _storage = new WindowsEncryptedTokenStorage(_tempFile);
            }
        }

        public void Dispose()
        {
            try
            {
                File.Delete(_tempFile);
            }
            catch
            {
            }

            try
            {
                File.Delete(_tempFile + ".bak");
            }
            catch
            {
            }

            try
            {
                File.Delete(_tempFile + ".tmp");
            }
            catch
            {
            }

            GC.SuppressFinalize(this);
        }

        [WindowsFact]
        public async Task AddAndGet_RoundTripsTokenToDisk()
        {
            var token = TestHelpers.CreateToken(id: "rt1", accessToken: "at-value", refreshToken: "rt-value");
            var metadata = TestHelpers.CreateTokenMetadata(token, new Dictionary<string, string> { ["web"] = "web" });

            await _storage!.AddAsync(token, metadata);

            var storage2 = new WindowsEncryptedTokenStorage(_tempFile);
            var retrieved = await storage2.GetAsync("rt1");

            Assert.NotNull(retrieved);
            Assert.Equal("at-value", retrieved.AccessToken);
            Assert.Equal("rt-value", retrieved.RefreshToken);
            Assert.Equal("rt1", retrieved.Id);
        }

        [WindowsFact]
        public async Task AddAndGet_RoundTripsMetadataToDisk()
        {
            var token = TestHelpers.CreateToken(id: "m1");
            var tags = new Dictionary<string, string> { ["mobile"] = "mobile", ["ios"] = "ios" };
            var metadata = TestHelpers.CreateTokenMetadata(token, tags);

            await _storage!.AddAsync(token, metadata);

            var storage2 = new WindowsEncryptedTokenStorage(_tempFile);
            var retrieved = await storage2.GetMetadataAsync("m1");

            Assert.NotNull(retrieved);
            Assert.Equal("m1", retrieved.Id);
            Assert.Equal(tags, retrieved.Tags);
        }

        [WindowsFact]
        public async Task ReplaceAsync_PersistsUpdatedToken()
        {
            var token = TestHelpers.CreateToken(id: "r1", accessToken: "old");
            var metadata = TestHelpers.CreateTokenMetadata(token);
            await _storage!.AddAsync(token, metadata);

            var updated = TestHelpers.CreateToken(id: "r1", accessToken: "new");
            await _storage.ReplaceAsync("r1", updated);

            var storage2 = new WindowsEncryptedTokenStorage(_tempFile);
            var retrieved = await storage2.GetAsync("r1");
            Assert.Equal("new", retrieved!.AccessToken);

            var retrievedMeta = await storage2.GetMetadataAsync("r1");
            Assert.NotNull(retrievedMeta);
        }

        [WindowsFact]
        public async Task RemoveAsync_PersistsDeletion()
        {
            var token = TestHelpers.CreateToken(id: "d1");
            var metadata = TestHelpers.CreateTokenMetadata(token);
            await _storage!.AddAsync(token, metadata);

            await _storage.RemoveAsync("d1");

            var storage2 = new WindowsEncryptedTokenStorage(_tempFile);
            Assert.Null(await storage2.GetAsync("d1"));
        }

        [WindowsFact]
        public async Task DefaultTokenId_PersistsAcrossInstances()
        {
            await _storage!.SetDefaultTokenIdAsync("def1");

            var storage2 = new WindowsEncryptedTokenStorage(_tempFile);
            Assert.Equal("def1", await storage2.GetDefaultTokenIdAsync());
        }

        [WindowsFact]
        public async Task ClearAsync_RemovesAllContent()
        {
            var token = TestHelpers.CreateToken(id: "c1");
            var metadata = TestHelpers.CreateTokenMetadata(token);
            await _storage!.AddAsync(token, metadata);
            await _storage.SetDefaultTokenIdAsync("c1");

            await _storage.ClearAsync();

            Assert.True(await _storage.IsEmptyAsync());
            Assert.Null(await _storage.GetDefaultTokenIdAsync());

            var storage2 = new WindowsEncryptedTokenStorage(_tempFile);
            Assert.True(await storage2.IsEmptyAsync());
        }

        [WindowsFact]
        public async Task IsEmpty_ReturnsTrueForNewFile()
        {
            Assert.True(await _storage!.IsEmptyAsync());
        }

        [WindowsFact]
        public async Task AddAsync_ThrowsOnDuplicateId()
        {
            var token = TestHelpers.CreateToken(id: "dup1");
            var metadata = TestHelpers.CreateTokenMetadata(token);
            await _storage!.AddAsync(token, metadata);

            await Assert.ThrowsAsync<InvalidOperationException>(() => _storage.AddAsync(token, metadata));
        }

        [WindowsFact]
        public async Task RemoveAsync_ThrowsOnNonexistentId()
        {
            await Assert.ThrowsAsync<KeyNotFoundException>(() => _storage!.RemoveAsync("ghost"));
        }

        [WindowsFact]
        public async Task RemoveAsync_ClearsDefaultId_WhenDefaultIsRemoved()
        {
            var token = TestHelpers.CreateToken(id: "def-rm");
            var metadata = TestHelpers.CreateTokenMetadata(token);
            await _storage!.AddAsync(token, metadata);
            await _storage.SetDefaultTokenIdAsync("def-rm");

            await _storage.RemoveAsync("def-rm");

            Assert.Null(await _storage.GetDefaultTokenIdAsync());
        }

        [WindowsFact]
        public void Constructor_ThrowsForInvalidPath()
        {
            Assert.ThrowsAny<ArgumentException>(() => new WindowsEncryptedTokenStorage(string.Empty));
            Assert.ThrowsAny<ArgumentException>(() => new WindowsEncryptedTokenStorage(" "));
            Assert.ThrowsAny<ArgumentException>(() => new WindowsEncryptedTokenStorage(null!));
        }

        [WindowsFact]
        public async Task AllIdsAsync_ReturnsAllStoredIds()
        {
            var t1 = TestHelpers.CreateToken(id: "a1");
            var t2 = TestHelpers.CreateToken(id: "a2");
            await _storage!.AddAsync(t1, TestHelpers.CreateTokenMetadata(t1));
            await _storage.AddAsync(t2, TestHelpers.CreateTokenMetadata(t2));

            var ids = await _storage.AllIdsAsync();

            Assert.Equal(2, ids.Count);
            Assert.Contains("a1", ids);
            Assert.Contains("a2", ids);
        }

        [WindowsFact]
        public async Task Load_TreatsCorruptedJsonAsEmpty()
        {
            File.WriteAllText(_tempFile, "{ this is not valid json!!!");

            var storage = new WindowsEncryptedTokenStorage(_tempFile);

            Assert.True(await storage.IsEmptyAsync());
        }

        [WindowsFact]
        public async Task Load_CorruptedFile_IsOverwrittenOnNextFlush()
        {
            File.WriteAllText(_tempFile, "CORRUPTED");

            var storage = new WindowsEncryptedTokenStorage(_tempFile);
            Assert.True(await storage.IsEmptyAsync());

            var token = TestHelpers.CreateToken(id: "recovered");
            await storage.AddAsync(token, TestHelpers.CreateTokenMetadata(token));

            // Fresh instance should read the valid data
            var storage2 = new WindowsEncryptedTokenStorage(_tempFile);
            var retrieved = await storage2.GetAsync("recovered");
            Assert.NotNull(retrieved);
            Assert.Equal("recovered", retrieved.Id);
        }

        [WindowsFact]
        public async Task Flush_CreatesBackupFile()
        {
            var token = TestHelpers.CreateToken(id: "bak-test");
            await _storage!.AddAsync(token, TestHelpers.CreateTokenMetadata(token));

            // Second write triggers File.Replace which creates the .bak
            var token2 = TestHelpers.CreateToken(id: "bak-test-2");
            await _storage.AddAsync(token2, TestHelpers.CreateTokenMetadata(token2));

            Assert.True(File.Exists(_tempFile + ".bak"));
        }

        [WindowsFact]
        public async Task Flush_AtomicWrite_ProducesValidJson()
        {
            for (int i = 0; i < 5; i++)
            {
                var token = TestHelpers.CreateToken(id: $"atomic-{i}");
                await _storage!.AddAsync(token, TestHelpers.CreateTokenMetadata(token));
            }

            var storage2 = new WindowsEncryptedTokenStorage(_tempFile);
            var ids = await storage2.AllIdsAsync();
            Assert.Equal(5, ids.Count);
        }

        [WindowsFact]
        public async Task TokenData_IsEncryptedOnDisk()
        {
            var token = TestHelpers.CreateToken(id: "enc1", accessToken: "super-secret-access-token");
            await _storage!.AddAsync(token, TestHelpers.CreateTokenMetadata(token));

            // Read the raw file contents - the access token should NOT appear in plaintext
            var rawContent = File.ReadAllText(_tempFile);
            Assert.DoesNotContain("super-secret-access-token", rawContent);
        }

        [WindowsFact]
        public async Task Metadata_IsNotEncryptedOnDisk()
        {
            var token = TestHelpers.CreateToken(id: "meta-vis");
            var metadata = TestHelpers.CreateTokenMetadata(token, new Dictionary<string, string> { ["visible-tag"] = "visible-tag" });
            await _storage!.AddAsync(token, metadata);

            // Metadata should be readable without decryption
            var rawContent = File.ReadAllText(_tempFile);
            Assert.Contains("visible-tag", rawContent);
        }

        [WindowsFact]
        public async Task DifferentEntropy_CannotDecrypt()
        {
            var entropy1 = new byte[] { 1, 2, 3, 4 };
            var entropy2 = new byte[] { 5, 6, 7, 8 };

            var storage1 = new WindowsEncryptedTokenStorage(_tempFile, optionalEntropy: entropy1);
            var token = TestHelpers.CreateToken(id: "ent1", accessToken: "secret");
            await storage1.AddAsync(token, TestHelpers.CreateTokenMetadata(token));

            var storage2 = new WindowsEncryptedTokenStorage(_tempFile, optionalEntropy: entropy2);
            await Assert.ThrowsAsync<CryptographicException>(() => storage2.GetAsync("ent1"));
        }

        [WindowsFact]
        public async Task SecondToken_DoesNotChangeDefault()
        {
            var t1 = TestHelpers.CreateToken(id: "first");
            var t2 = TestHelpers.CreateToken(id: "second");
            await _storage!.AddAsync(t1, TestHelpers.CreateTokenMetadata(t1));
            await _storage.AddAsync(t2, TestHelpers.CreateTokenMetadata(t2));

            Assert.Equal("first", await _storage.GetDefaultTokenIdAsync());
        }

        [WindowsFact]
        public async Task DefaultTokenChanged_FiresOnChange()
        {
            string? capturedOld = "not-set";
            string? capturedNew = "not-set";

            _storage!.DefaultTokenChanged += (_, e) =>
            {
                capturedOld = e.OldDefaultTokenId;
                capturedNew = e.NewDefaultTokenId;
            };

            await _storage.SetDefaultTokenIdAsync("tok1");

            Assert.Null(capturedOld);
            Assert.Equal("tok1", capturedNew);
        }

        [WindowsFact]
        public async Task AddAsync_ThrowsOnMismatchedIds()
        {
            var token = TestHelpers.CreateToken(id: "tok1");
            var metadata = new TokenMetadata { Id = "different-id" };

            await Assert.ThrowsAsync<ArgumentException>(() => _storage!.AddAsync(token, metadata));
        }

        [WindowsFact]
        public async Task ReplaceAsync_ThrowsOnMismatchedId()
        {
            var token = TestHelpers.CreateToken(id: "r1");
            await _storage!.AddAsync(token, TestHelpers.CreateTokenMetadata(token));

            var replacement = TestHelpers.CreateToken(id: "r2");
            await Assert.ThrowsAsync<ArgumentException>(() => _storage.ReplaceAsync("r1", replacement));
        }

        [WindowsFact]
        public async Task ReplaceAsync_ThrowsOnNonexistentId()
        {
            var token = TestHelpers.CreateToken(id: "ghost");
            await Assert.ThrowsAsync<KeyNotFoundException>(() => _storage!.ReplaceAsync("ghost", token));
        }

        [WindowsFact]
        public async Task SetMetadataAsync_ThrowsOnNonexistentId()
        {
            var metadata = new TokenMetadata { Id = "ghost" };
            await Assert.ThrowsAsync<KeyNotFoundException>(() => _storage!.SetMetadataAsync(metadata));
        }

        [WindowsFact]
        public async Task SetMetadataAsync_ThrowsOnNullMetadata()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => _storage!.SetMetadataAsync(null!));
        }

        [WindowsFact]
        public async Task SetMetadataAsync_ThrowsOnEmptyId()
        {
            var metadata = new TokenMetadata { Id = string.Empty };
            await Assert.ThrowsAsync<ArgumentException>(() => _storage!.SetMetadataAsync(metadata));
        }

        [WindowsFact]
        public async Task SetMetadataAsync_UpdatesMetadata()
        {
            var token = TestHelpers.CreateToken(id: "sm1");
            await _storage!.AddAsync(token, TestHelpers.CreateTokenMetadata(token, new Dictionary<string, string> { ["old-tag"] = "old-tag" }));

            var newTags = new Dictionary<string, string> { ["new-tag"] = "new-tag" };
            var updatedMetadata = TestHelpers.CreateTokenMetadata(token, newTags);
            await _storage.SetMetadataAsync(updatedMetadata);

            var retrieved = await _storage.GetMetadataAsync("sm1");
            Assert.NotNull(retrieved);
            Assert.Equal(newTags, retrieved.Tags);
        }

        [WindowsFact]
        public void IncludeClaims_DefaultsToFalse()
        {
            Assert.False(_storage!.IncludeClaims);
        }

        [WindowsFact]
        public async Task IncludeClaims_Default_DoesNotPersistClaims()
        {
            var idToken = TestHelpers.CreateIdToken(subject: "user-123");
            var token = TestHelpers.CreateToken(id: "claims-default", idToken: idToken);
            var metadata = new TokenMetadata(token);
            Assert.NotNull(metadata.Claims);

            await _storage!.AddAsync(token, metadata);

            // The caller's metadata is untouched.
            Assert.NotNull(metadata.Claims);

            var stored = await _storage.GetMetadataAsync("claims-default");
            Assert.Null(stored!.Claims);

            // Metadata is not encrypted, so check the file contents too.
            Assert.DoesNotContain("user-123", await File.ReadAllTextAsync(_tempFile));
        }

        [WindowsFact]
        public async Task IncludeClaims_True_PersistsClaims()
        {
            var storage = new WindowsEncryptedTokenStorage(_tempFile, includeClaims: true);
            var idToken = TestHelpers.CreateIdToken(subject: "user-123");
            var token = TestHelpers.CreateToken(id: "claims-on", idToken: idToken);

            await storage.AddAsync(token, new TokenMetadata(token));

            var storage2 = new WindowsEncryptedTokenStorage(_tempFile, includeClaims: true);
            var stored = await storage2.GetMetadataAsync("claims-on");
            Assert.NotNull(stored!.Claims);
            Assert.Equal("user-123", stored.Claims!["sub"].GetString());
        }
    }
}
