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
    public class LinuxFileKeyTokenStorageTests : IDisposable
    {
        private readonly string _tempDir;
        private readonly string _tempFile;
        private readonly string _tempKeyFile;
        private readonly LinuxFileKeyTokenStorage? _storage;

        public LinuxFileKeyTokenStorageTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), $"okta-linux-enc-test-{Guid.NewGuid()}");
            Directory.CreateDirectory(_tempDir);
            _tempFile = Path.Combine(_tempDir, "tokens.encrypted.json");
            _tempKeyFile = Path.Combine(_tempDir, "encryption.key");
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                _storage = new LinuxFileKeyTokenStorage(_tempFile, _tempKeyFile);
            }
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(_tempDir, recursive: true);
            }
            catch
            {
            }

            GC.SuppressFinalize(this);
        }

        [LinuxFact]
        public async Task AddAndGet_RoundTripsTokenToDisk()
        {
            var token = TestHelpers.CreateToken(id: "rt1", accessToken: "at-value", refreshToken: "rt-value");
            var metadata = TestHelpers.CreateTokenMetadata(token, new Dictionary<string, string> { ["web"] = "web" });

            await _storage!.AddAsync(token, metadata);

            var storage2 = new LinuxFileKeyTokenStorage(_tempFile, _tempKeyFile);
            var retrieved = await storage2.GetAsync("rt1");

            Assert.NotNull(retrieved);
            Assert.Equal("at-value", retrieved.AccessToken);
            Assert.Equal("rt-value", retrieved.RefreshToken);
            Assert.Equal("rt1", retrieved.Id);
        }

        [LinuxFact]
        public async Task AddAndGet_RoundTripsMetadataToDisk()
        {
            var token = TestHelpers.CreateToken(id: "m1");
            var tags = new Dictionary<string, string> { ["mobile"] = "mobile", ["ios"] = "ios" };
            var metadata = TestHelpers.CreateTokenMetadata(token, tags);

            await _storage!.AddAsync(token, metadata);

            var storage2 = new LinuxFileKeyTokenStorage(_tempFile, _tempKeyFile);
            var retrieved = await storage2.GetMetadataAsync("m1");

            Assert.NotNull(retrieved);
            Assert.Equal("m1", retrieved.Id);
            Assert.Equal(tags, retrieved.Tags);
        }

        [LinuxFact]
        public async Task ReplaceAsync_PersistsUpdatedToken()
        {
            var token = TestHelpers.CreateToken(id: "r1", accessToken: "old");
            var metadata = TestHelpers.CreateTokenMetadata(token);
            await _storage!.AddAsync(token, metadata);

            var updated = TestHelpers.CreateToken(id: "r1", accessToken: "new");
            await _storage.ReplaceAsync("r1", updated);

            var storage2 = new LinuxFileKeyTokenStorage(_tempFile, _tempKeyFile);
            var retrieved = await storage2.GetAsync("r1");
            Assert.Equal("new", retrieved!.AccessToken);

            var retrievedMeta = await storage2.GetMetadataAsync("r1");
            Assert.NotNull(retrievedMeta);
        }

        [LinuxFact]
        public async Task RemoveAsync_PersistsDeletion()
        {
            var token = TestHelpers.CreateToken(id: "d1");
            var metadata = TestHelpers.CreateTokenMetadata(token);
            await _storage!.AddAsync(token, metadata);

            await _storage.RemoveAsync("d1");

            var storage2 = new LinuxFileKeyTokenStorage(_tempFile, _tempKeyFile);
            Assert.Null(await storage2.GetAsync("d1"));
        }

        [LinuxFact]
        public async Task DefaultTokenId_PersistsAcrossInstances()
        {
            await _storage!.SetDefaultTokenIdAsync("def1");

            var storage2 = new LinuxFileKeyTokenStorage(_tempFile, _tempKeyFile);
            Assert.Equal("def1", await storage2.GetDefaultTokenIdAsync());
        }

        [LinuxFact]
        public async Task ClearAsync_RemovesAllContent()
        {
            var token = TestHelpers.CreateToken(id: "c1");
            var metadata = TestHelpers.CreateTokenMetadata(token);
            await _storage!.AddAsync(token, metadata);
            await _storage.SetDefaultTokenIdAsync("c1");

            await _storage.ClearAsync();

            Assert.True(await _storage.IsEmptyAsync());
            Assert.Null(await _storage.GetDefaultTokenIdAsync());

            var storage2 = new LinuxFileKeyTokenStorage(_tempFile, _tempKeyFile);
            Assert.True(await storage2.IsEmptyAsync());
        }

        [LinuxFact]
        public async Task IsEmpty_ReturnsTrueForNewFile()
        {
            Assert.True(await _storage!.IsEmptyAsync());
        }

        [LinuxFact]
        public async Task AddAsync_ThrowsOnDuplicateId()
        {
            var token = TestHelpers.CreateToken(id: "dup1");
            var metadata = TestHelpers.CreateTokenMetadata(token);
            await _storage!.AddAsync(token, metadata);

            await Assert.ThrowsAsync<InvalidOperationException>(() => _storage.AddAsync(token, metadata));
        }

        [LinuxFact]
        public async Task RemoveAsync_ThrowsOnNonexistentId()
        {
            await Assert.ThrowsAsync<KeyNotFoundException>(() => _storage!.RemoveAsync("ghost"));
        }

        [LinuxFact]
        public async Task RemoveAsync_ClearsDefaultId_WhenDefaultIsRemoved()
        {
            var token = TestHelpers.CreateToken(id: "def-rm");
            var metadata = TestHelpers.CreateTokenMetadata(token);
            await _storage!.AddAsync(token, metadata);
            await _storage.SetDefaultTokenIdAsync("def-rm");

            await _storage.RemoveAsync("def-rm");

            Assert.Null(await _storage.GetDefaultTokenIdAsync());
        }

        [LinuxFact]
        public void Constructor_ThrowsForInvalidPath()
        {
            Assert.ThrowsAny<ArgumentException>(() => new LinuxFileKeyTokenStorage(string.Empty, _tempKeyFile));
            Assert.ThrowsAny<ArgumentException>(() => new LinuxFileKeyTokenStorage(" ", _tempKeyFile));
            Assert.ThrowsAny<ArgumentException>(() => new LinuxFileKeyTokenStorage(null!, _tempKeyFile));
            Assert.ThrowsAny<ArgumentException>(() => new LinuxFileKeyTokenStorage(_tempFile, string.Empty));
            Assert.ThrowsAny<ArgumentException>(() => new LinuxFileKeyTokenStorage(_tempFile, " "));
            Assert.ThrowsAny<ArgumentException>(() => new LinuxFileKeyTokenStorage(_tempFile, (string)null!));
        }

        [LinuxFact]
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

        [LinuxFact]
        public async Task Load_TreatsCorruptedJsonAsEmpty()
        {
            File.WriteAllText(_tempFile, "{ this is not valid json!!!");

            var storage = new LinuxFileKeyTokenStorage(_tempFile, _tempKeyFile);

            Assert.True(await storage.IsEmptyAsync());
        }

        [LinuxFact]
        public async Task Load_CorruptedFile_IsOverwrittenOnNextFlush()
        {
            File.WriteAllText(_tempFile, "CORRUPTED");

            var storage = new LinuxFileKeyTokenStorage(_tempFile, _tempKeyFile);
            Assert.True(await storage.IsEmptyAsync());

            var token = TestHelpers.CreateToken(id: "recovered");
            await storage.AddAsync(token, TestHelpers.CreateTokenMetadata(token));

            var storage2 = new LinuxFileKeyTokenStorage(_tempFile, _tempKeyFile);
            var retrieved = await storage2.GetAsync("recovered");
            Assert.NotNull(retrieved);
            Assert.Equal("recovered", retrieved.Id);
        }

        [LinuxFact]
        public async Task Flush_CreatesBackupFile()
        {
            var token = TestHelpers.CreateToken(id: "bak-test");
            await _storage!.AddAsync(token, TestHelpers.CreateTokenMetadata(token));

            var token2 = TestHelpers.CreateToken(id: "bak-test-2");
            await _storage.AddAsync(token2, TestHelpers.CreateTokenMetadata(token2));

            Assert.True(File.Exists(_tempFile + ".bak"));
        }

        [LinuxFact]
        public async Task Flush_AtomicWrite_ProducesValidJson()
        {
            for (int i = 0; i < 5; i++)
            {
                var token = TestHelpers.CreateToken(id: $"atomic-{i}");
                await _storage!.AddAsync(token, TestHelpers.CreateTokenMetadata(token));
            }

            var storage2 = new LinuxFileKeyTokenStorage(_tempFile, _tempKeyFile);
            var ids = await storage2.AllIdsAsync();
            Assert.Equal(5, ids.Count);
        }

        [LinuxFact]
        public async Task TokenData_IsEncryptedOnDisk()
        {
            var token = TestHelpers.CreateToken(id: "enc1", accessToken: "super-secret-access-token");
            await _storage!.AddAsync(token, TestHelpers.CreateTokenMetadata(token));

            var rawContent = File.ReadAllText(_tempFile);
            Assert.DoesNotContain("super-secret-access-token", rawContent);
        }

        [LinuxFact]
        public async Task Metadata_IsNotEncryptedOnDisk()
        {
            var token = TestHelpers.CreateToken(id: "meta-vis");
            var metadata = TestHelpers.CreateTokenMetadata(token, new Dictionary<string, string> { ["visible-tag"] = "visible-tag" });
            await _storage!.AddAsync(token, metadata);

            var rawContent = File.ReadAllText(_tempFile);
            Assert.Contains("visible-tag", rawContent);
        }

        [LinuxFact]
        public async Task DifferentKey_CannotDecrypt()
        {
            var token = TestHelpers.CreateToken(id: "key1", accessToken: "secret");
            await _storage!.AddAsync(token, TestHelpers.CreateTokenMetadata(token));

            var altKeyFile = Path.Combine(_tempDir, "alt-encryption.key");
            var storage2 = new LinuxFileKeyTokenStorage(_tempFile, altKeyFile);
            await Assert.ThrowsAnyAsync<CryptographicException>(() => storage2.GetAsync("key1"));
        }

        [LinuxFact]
        public async Task SecondToken_DoesNotChangeDefault()
        {
            var t1 = TestHelpers.CreateToken(id: "first");
            var t2 = TestHelpers.CreateToken(id: "second");
            await _storage!.AddAsync(t1, TestHelpers.CreateTokenMetadata(t1));
            await _storage.AddAsync(t2, TestHelpers.CreateTokenMetadata(t2));

            Assert.Equal("first", await _storage.GetDefaultTokenIdAsync());
        }

        [LinuxFact]
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

        [LinuxFact]
        public async Task AddAsync_ThrowsOnMismatchedIds()
        {
            var token = TestHelpers.CreateToken(id: "tok1");
            var metadata = new TokenMetadata { Id = "different-id" };

            await Assert.ThrowsAsync<ArgumentException>(() => _storage!.AddAsync(token, metadata));
        }

        [LinuxFact]
        public async Task ReplaceAsync_ThrowsOnMismatchedId()
        {
            var token = TestHelpers.CreateToken(id: "r1");
            await _storage!.AddAsync(token, TestHelpers.CreateTokenMetadata(token));

            var replacement = TestHelpers.CreateToken(id: "r2");
            await Assert.ThrowsAsync<ArgumentException>(() => _storage.ReplaceAsync("r1", replacement));
        }

        [LinuxFact]
        public async Task ReplaceAsync_ThrowsOnNonexistentId()
        {
            var token = TestHelpers.CreateToken(id: "ghost");
            await Assert.ThrowsAsync<KeyNotFoundException>(() => _storage!.ReplaceAsync("ghost", token));
        }

        [LinuxFact]
        public async Task SetMetadataAsync_ThrowsOnNonexistentId()
        {
            var metadata = new TokenMetadata { Id = "ghost" };
            await Assert.ThrowsAsync<KeyNotFoundException>(() => _storage!.SetMetadataAsync(metadata));
        }

        [LinuxFact]
        public async Task SetMetadataAsync_ThrowsOnNullMetadata()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => _storage!.SetMetadataAsync(null!));
        }

        [LinuxFact]
        public async Task SetMetadataAsync_ThrowsOnEmptyId()
        {
            var metadata = new TokenMetadata { Id = string.Empty };
            await Assert.ThrowsAsync<ArgumentException>(() => _storage!.SetMetadataAsync(metadata));
        }

        [LinuxFact]
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

        [LinuxFact]
        public async Task KeyFile_IsCreatedOnFirstUse()
        {
            Assert.False(File.Exists(_tempKeyFile));

            var token = TestHelpers.CreateToken(id: "key-create");
            await _storage!.AddAsync(token, TestHelpers.CreateTokenMetadata(token));

            Assert.True(File.Exists(_tempKeyFile));
            Assert.Equal(32, File.ReadAllBytes(_tempKeyFile).Length);
        }

        [LinuxFact]
        public async Task KeyFile_HasRestrictedPermissions()
        {
            var token = TestHelpers.CreateToken(id: "perms");
            await _storage!.AddAsync(token, TestHelpers.CreateTokenMetadata(token));

            var mode = File.GetUnixFileMode(_tempKeyFile);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
        }

        [LinuxFact]
        public async Task TokenFile_HasRestrictedPermissions()
        {
            var token = TestHelpers.CreateToken(id: "file-perms");
            await _storage!.AddAsync(token, TestHelpers.CreateTokenMetadata(token));

            var mode = File.GetUnixFileMode(_tempFile);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
        }

        [LinuxFact]
        public async Task BackupFile_HasRestrictedPermissions()
        {
            var token = TestHelpers.CreateToken(id: "bak-perms-1");
            await _storage!.AddAsync(token, TestHelpers.CreateTokenMetadata(token));

            var token2 = TestHelpers.CreateToken(id: "bak-perms-2");
            await _storage.AddAsync(token2, TestHelpers.CreateTokenMetadata(token2));

            var backupPath = _tempFile + ".bak";
            Assert.True(File.Exists(backupPath));
            var mode = File.GetUnixFileMode(backupPath);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
        }

        [LinuxFact]
        public async Task CustomKeyProvider_EncryptsAndDecryptsTokens()
        {
            var key = RandomNumberGenerator.GetBytes(32);
            var storage = new LinuxFileKeyTokenStorage(_tempFile, () => key);

            var token = TestHelpers.CreateToken(id: "custom-key", accessToken: "secret-value");
            await storage.AddAsync(token, TestHelpers.CreateTokenMetadata(token));

            var storage2 = new LinuxFileKeyTokenStorage(_tempFile, () => key);
            var retrieved = await storage2.GetAsync("custom-key");
            Assert.NotNull(retrieved);
            Assert.Equal("secret-value", retrieved.AccessToken);
        }

        [LinuxFact]
        public async Task CustomKeyProvider_WrongKey_ThrowsCryptographicException()
        {
            var key1 = RandomNumberGenerator.GetBytes(32);
            var key2 = RandomNumberGenerator.GetBytes(32);

            var storage1 = new LinuxFileKeyTokenStorage(_tempFile, () => key1);
            var token = TestHelpers.CreateToken(id: "ck-wrong", accessToken: "secret");
            await storage1.AddAsync(token, TestHelpers.CreateTokenMetadata(token));

            var storage2 = new LinuxFileKeyTokenStorage(_tempFile, () => key2);
            await Assert.ThrowsAnyAsync<CryptographicException>(() => storage2.GetAsync("ck-wrong"));
        }

        [LinuxFact]
        public void CustomKeyProvider_WrongKeySize_ThrowsCryptographicException()
        {
            var badKey = new byte[16]; // 128-bit, not 256-bit
            var storage = new LinuxFileKeyTokenStorage(_tempFile, () => badKey);
            var token = TestHelpers.CreateToken(id: "bad-size");
            Assert.ThrowsAny<CryptographicException>(() =>
                storage.AddAsync(token, TestHelpers.CreateTokenMetadata(token)).GetAwaiter().GetResult());
        }

        [LinuxFact]
        public async Task IncludeClaims_False_StripsClaimsFromMetadata()
        {
            var storage = new LinuxFileKeyTokenStorage(_tempFile, _tempKeyFile, includeClaims: false);

            var idToken = TestHelpers.CreateIdToken();
            var token = TestHelpers.CreateToken(id: "no-claims", idToken: idToken);
            var metadata = new TokenMetadata(token, new Dictionary<string, string> { ["tag"] = "tag1" });

            await storage.AddAsync(token, metadata);

            var retrieved = await storage.GetMetadataAsync("no-claims");
            Assert.NotNull(retrieved);
            Assert.Null(retrieved.Claims);
            Assert.Equal("no-claims", retrieved.Id);
            Assert.NotNull(retrieved.Tags);
            Assert.Equal("tag1", retrieved.Tags!["tag"]);
        }

        [LinuxFact]
        public async Task AddAsync_FirstToken_FiresDefaultTokenChangedEvent()
        {
            string? capturedOld = "not-set";
            string? capturedNew = "not-set";

            _storage!.DefaultTokenChanged += (_, e) =>
            {
                capturedOld = e.OldDefaultTokenId;
                capturedNew = e.NewDefaultTokenId;
            };

            var token = TestHelpers.CreateToken(id: "first-auto");
            await _storage.AddAsync(token, TestHelpers.CreateTokenMetadata(token));

            Assert.Null(capturedOld);
            Assert.Equal("first-auto", capturedNew);
        }

        [LinuxFact]
        public async Task SetDefaultTokenIdAsync_SameId_DoesNotFireEvent()
        {
            var token = TestHelpers.CreateToken(id: "stable");
            await _storage!.AddAsync(token, TestHelpers.CreateTokenMetadata(token));
            await _storage.SetDefaultTokenIdAsync("stable");

            int eventCount = 0;
            _storage.DefaultTokenChanged += (_, _) => eventCount++;

            await _storage.SetDefaultTokenIdAsync("stable");

            Assert.Equal(0, eventCount);
        }

        [LinuxFact]
        public async Task ClearAsync_WithDefault_FiresDefaultTokenChangedEvent()
        {
            var token = TestHelpers.CreateToken(id: "will-be-cleared");
            await _storage!.AddAsync(token, TestHelpers.CreateTokenMetadata(token));

            string? capturedOld = "not-set";
            string? capturedNew = "not-set";
            _storage.DefaultTokenChanged += (_, e) =>
            {
                capturedOld = e.OldDefaultTokenId;
                capturedNew = e.NewDefaultTokenId;
            };

            await _storage.ClearAsync();

            Assert.Equal("will-be-cleared", capturedOld);
            Assert.Null(capturedNew);
        }

        [LinuxFact]
        public void KeyFile_Truncated_ThrowsCryptographicException()
        {
            File.WriteAllBytes(_tempKeyFile, new byte[16]); // 128-bit, not 256-bit

            var storage = new LinuxFileKeyTokenStorage(_tempFile, _tempKeyFile);
            var token = TestHelpers.CreateToken(id: "truncated-key");
            Assert.ThrowsAny<CryptographicException>(() =>
                storage.AddAsync(token, TestHelpers.CreateTokenMetadata(token)).GetAwaiter().GetResult());
        }

        [LinuxFact]
        public async Task IncludeClaims_False_StripsClaimsBeforePersisting()
        {
            var storage = new LinuxFileKeyTokenStorage(_tempFile, _tempKeyFile, includeClaims: false);
            var idToken = TestHelpers.CreateIdToken(subject: "user-123");
            var token = TestHelpers.CreateToken(idToken: idToken);
            var metadata = new TokenMetadata(token);

            await storage.AddAsync(token, metadata);

            // In-memory metadata passed in is untouched
            Assert.NotNull(metadata.Claims);

            // What storage persisted has claims stripped
            var storage2 = new LinuxFileKeyTokenStorage(_tempFile, _tempKeyFile, includeClaims: false);
            var stored = await storage2.GetMetadataAsync(token.Id);
            Assert.Null(stored!.Claims);
        }

        [LinuxFact]
        public void IncludeClaims_DefaultsToFalse()
        {
            Assert.False(new LinuxFileKeyTokenStorage(_tempFile, _tempKeyFile).IncludeClaims);
        }

        [LinuxFact]
        public async Task IncludeClaims_Default_DoesNotPersistClaims()
        {
            var idToken = TestHelpers.CreateIdToken(subject: "user-123");
            var token = TestHelpers.CreateToken(idToken: idToken);
            var metadata = new TokenMetadata(token);
            Assert.NotNull(metadata.Claims);

            await _storage!.AddAsync(token, metadata);

            var stored = await _storage.GetMetadataAsync(token.Id);
            Assert.Null(stored!.Claims);
        }

        [LinuxFact]
        public async Task IncludeClaims_True_PersistsClaims()
        {
            var storage = new LinuxFileKeyTokenStorage(_tempFile, _tempKeyFile, includeClaims: true);
            var idToken = TestHelpers.CreateIdToken(subject: "user-123");
            var token = TestHelpers.CreateToken(idToken: idToken);

            await storage.AddAsync(token, new TokenMetadata(token));

            var storage2 = new LinuxFileKeyTokenStorage(_tempFile, _tempKeyFile, includeClaims: true);
            var stored = await storage2.GetMetadataAsync(token.Id);
            Assert.NotNull(stored!.Claims);
            Assert.Equal("user-123", stored.Claims!["sub"].GetString());
        }
    }
}
