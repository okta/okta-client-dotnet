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

using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DBus.Services.Secrets;

namespace Okta.AuthFoundation.TokenManagement
{
    /// <summary>
    /// Persists tokens to the D-Bus Secret Service (GNOME Keyring, KDE Wallet, or any compatible implementation), with encryption at rest handled by the keyring daemon.
    /// </summary>
    /// <remarks>
    /// Requires a running D-Bus session bus and a compatible keyring daemon. Throws on
    /// headless systems (containers, servers, CI) where no keyring daemon is available.
    /// Use <see cref="LinuxFileKeyTokenStorage"/> or provide a custom
    /// <see cref="ITokenStorage"/> if a desktop session cannot be assumed.
    /// </remarks>
    [SupportedOSPlatform("linux")]
    public class LinuxKeyringTokenStorage : ITokenStorage, IDisposable
    {
        private const string AppAttribute = "okta_sdk_app";
        private const string AppName = "OktaSdk";
        private const string TypeAttribute = "okta_sdk_type";
        private const string IdAttribute = "okta_sdk_id";
        private const string TokenItemType = "token";
        private const string ManifestItemType = "manifest";
        private const string ContentType = "text/plain; charset=utf-8";
        private const string CollectionLabel = "OktaSdk";
        private const string CollectionAlias = "default";

        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        private readonly SemaphoreSlim _lock = new(1, 1);
        private Collection? _collection;

        /// <inheritdoc/>
        public bool IncludeClaims { get; }

        /// <inheritdoc/>
        public event EventHandler<DefaultTokenChangedEventArgs>? DefaultTokenChanged;

        /// <summary>
        /// Initializes a new instance.
        /// </summary>
        /// <param name="includeClaims">Whether to snapshot claims into metadata. See <see cref="ITokenStorage.IncludeClaims"/>.</param>
        public LinuxKeyringTokenStorage(bool includeClaims = false)
        {
            if (!OperatingSystem.IsLinux())
            {
                throw new PlatformNotSupportedException($"{nameof(LinuxKeyringTokenStorage)} requires Linux.");
            }

            IncludeClaims = includeClaims;
        }

        /// <inheritdoc/>
        public async Task<bool> IsEmptyAsync(CancellationToken cancellationToken = default)
        {
            var ids = await AllIdsAsync(cancellationToken).ConfigureAwait(false);
            return ids.Count == 0;
        }

        /// <inheritdoc/>
        public async Task<List<string>> AllIdsAsync(CancellationToken cancellationToken = default)
        {
            await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var collection = await GetOrCreateCollectionAsync().ConfigureAwait(false);
                var manifest = await LoadManifestAsync(collection).ConfigureAwait(false);
                return new List<string>(manifest.Ids);
            }
            catch
            {
                _collection = null;
                throw;
            }
            finally
            {
                _lock.Release();
            }
        }

        /// <inheritdoc/>
        public async Task AddAsync(Token token, TokenMetadata? metadata, CancellationToken cancellationToken = default)
        {
            if (metadata != null && token.Id != metadata.Id)
            {
                throw new ArgumentException($"Token ID '{token.Id}' and Metadata ID '{metadata.Id}' do not match.");
            }

            DefaultTokenChangedEventArgs? change = null;
            await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var collection = await GetOrCreateCollectionAsync().ConfigureAwait(false);
                var manifest = await LoadManifestAsync(collection).ConfigureAwait(false);

                if (manifest.Ids.Contains(token.Id))
                {
                    throw new InvalidOperationException($"Token with the same ID '{token.Id}' already exists.");
                }

                var bundle = new TokenBundle(token, metadata != null ? StripClaimsIfNeeded(metadata) : null);
                await WriteTokenItemAsync(collection, token.Id, bundle).ConfigureAwait(false);

                bool isFirst = manifest.Ids.Count == 0;
                manifest.Ids.Add(token.Id);
                if (isFirst)
                {
                    change = new DefaultTokenChangedEventArgs(manifest.DefaultId, token.Id);
                    manifest.DefaultId = token.Id;
                }

                await SaveManifestAsync(collection, manifest).ConfigureAwait(false);
            }
            catch
            {
                _collection = null;
                throw;
            }
            finally
            {
                _lock.Release();
            }

            if (change != null)
            {
                DefaultTokenChanged?.Invoke(this, change);
            }
        }

        /// <inheritdoc/>
        public async Task ReplaceAsync(string id, Token token, CancellationToken cancellationToken = default)
        {
            if (token.Id != id)
            {
                throw new ArgumentException($"Token ID '{token.Id}' does not match the storage key '{id}'.");
            }

            await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var collection = await GetOrCreateCollectionAsync().ConfigureAwait(false);
                var manifest = await LoadManifestAsync(collection).ConfigureAwait(false);

                if (!manifest.Ids.Contains(id))
                {
                    throw new KeyNotFoundException($"Token with ID '{id}' does not exist.");
                }

                var existing = await LoadTokenBundleAsync(collection, id).ConfigureAwait(false)
                    ?? throw new KeyNotFoundException($"Token with ID '{id}' does not exist.");
                var bundle = new TokenBundle(token, existing.Metadata);
                await WriteTokenItemAsync(collection, id, bundle).ConfigureAwait(false);
            }
            catch
            {
                _collection = null;
                throw;
            }
            finally
            {
                _lock.Release();
            }
        }

        /// <inheritdoc/>
        public async Task RemoveAsync(string id, CancellationToken cancellationToken = default)
        {
            DefaultTokenChangedEventArgs? change = null;
            await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var collection = await GetOrCreateCollectionAsync().ConfigureAwait(false);
                var manifest = await LoadManifestAsync(collection).ConfigureAwait(false);

                if (!manifest.Ids.Remove(id))
                {
                    throw new KeyNotFoundException($"Token with the specified ID '{id}' does not exist.");
                }

                if (manifest.DefaultId == id)
                {
                    change = new DefaultTokenChangedEventArgs(id, null);
                    manifest.DefaultId = null;
                }

                // Save manifest before deleting: if delete fails, the item is
                // unreferenced but still in the keyring (harmless orphan) rather
                // than the manifest listing an item that no longer exists.
                await SaveManifestAsync(collection, manifest).ConfigureAwait(false);
                await DeleteTokenItemAsync(collection, id).ConfigureAwait(false);
            }
            catch
            {
                _collection = null;
                throw;
            }
            finally
            {
                _lock.Release();
            }

            if (change != null)
            {
                DefaultTokenChanged?.Invoke(this, change);
            }
        }

        /// <inheritdoc/>
        public async Task<Token?> GetAsync(string id, CancellationToken cancellationToken = default)
        {
            await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var collection = await GetOrCreateCollectionAsync().ConfigureAwait(false);
                var bundle = await LoadTokenBundleAsync(collection, id).ConfigureAwait(false);
                return bundle?.Token;
            }
            catch
            {
                _collection = null;
                throw;
            }
            finally
            {
                _lock.Release();
            }
        }

        /// <inheritdoc/>
        public async Task<TokenMetadata?> GetMetadataAsync(string id, CancellationToken cancellationToken = default)
        {
            await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var collection = await GetOrCreateCollectionAsync().ConfigureAwait(false);
                var bundle = await LoadTokenBundleAsync(collection, id).ConfigureAwait(false);
                return CopyMetadata(bundle?.Metadata);
            }
            catch
            {
                _collection = null;
                throw;
            }
            finally
            {
                _lock.Release();
            }
        }

        /// <inheritdoc/>
        public async Task SetMetadataAsync(TokenMetadata metadata, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(metadata);
            if (string.IsNullOrWhiteSpace(metadata.Id))
            {
                throw new ArgumentException("metadata ID not found", nameof(metadata));
            }

            await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var collection = await GetOrCreateCollectionAsync().ConfigureAwait(false);
                var manifest = await LoadManifestAsync(collection).ConfigureAwait(false);

                if (!manifest.Ids.Contains(metadata.Id))
                {
                    throw new KeyNotFoundException($"Token with the specified ID '{metadata.Id}' does not exist.");
                }

                var existing = await LoadTokenBundleAsync(collection, metadata.Id).ConfigureAwait(false)
                    ?? throw new KeyNotFoundException($"Token with the specified ID '{metadata.Id}' does not exist.");

                var bundle = new TokenBundle(existing.Token, StripClaimsIfNeeded(metadata));
                await WriteTokenItemAsync(collection, metadata.Id, bundle).ConfigureAwait(false);
            }
            catch
            {
                _collection = null;
                throw;
            }
            finally
            {
                _lock.Release();
            }
        }

        /// <inheritdoc/>
        public async Task ClearAsync(CancellationToken cancellationToken = default)
        {
            DefaultTokenChangedEventArgs? change = null;
            await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var collection = await GetOrCreateCollectionAsync().ConfigureAwait(false);
                var manifest = await LoadManifestAsync(collection).ConfigureAwait(false);

                if (manifest.DefaultId != null)
                {
                    change = new DefaultTokenChangedEventArgs(manifest.DefaultId, null);
                }

                // Save empty manifest before deleting items: if a delete fails,
                // the orphaned items are unreferenced rather than the manifest
                // listing items that no longer exist.
                var idsToDelete = new List<string>(manifest.Ids);
                await SaveManifestAsync(collection, new Manifest()).ConfigureAwait(false);

                foreach (var id in idsToDelete)
                {
                    try
                    {
                        await DeleteTokenItemAsync(collection, id).ConfigureAwait(false);
                    }
                    catch
                    { /* best-effort; item may already be gone */
                    }
                }
            }
            catch
            {
                _collection = null;
                throw;
            }
            finally
            {
                _lock.Release();
            }

            if (change != null)
            {
                DefaultTokenChanged?.Invoke(this, change);
            }
        }

        /// <inheritdoc/>
        public async Task<string?> GetDefaultTokenIdAsync(CancellationToken cancellationToken = default)
        {
            await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var collection = await GetOrCreateCollectionAsync().ConfigureAwait(false);
                var manifest = await LoadManifestAsync(collection).ConfigureAwait(false);
                return manifest.DefaultId;
            }
            catch
            {
                _collection = null;
                throw;
            }
            finally
            {
                _lock.Release();
            }
        }

        /// <inheritdoc/>
        public async Task SetDefaultTokenIdAsync(string? id, CancellationToken cancellationToken = default)
        {
            DefaultTokenChangedEventArgs? change = null;
            await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var collection = await GetOrCreateCollectionAsync().ConfigureAwait(false);
                var manifest = await LoadManifestAsync(collection).ConfigureAwait(false);

                if (manifest.DefaultId != id)
                {
                    change = new DefaultTokenChangedEventArgs(manifest.DefaultId, id);
                    manifest.DefaultId = id;
                    await SaveManifestAsync(collection, manifest).ConfigureAwait(false);
                }
            }
            catch
            {
                _collection = null;
                throw;
            }
            finally
            {
                _lock.Release();
            }

            if (change != null)
            {
                DefaultTokenChanged?.Invoke(this, change);
            }
        }

        private static async Task WriteTokenItemAsync(Collection collection, string id, TokenBundle bundle)
        {
            var attrs = new Dictionary<string, string>
            {
                [AppAttribute] = AppName,
                [TypeAttribute] = TokenItemType,
                [IdAttribute] = id,
            };
            var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(bundle, _jsonOptions));
            await collection.CreateItemAsync($"OktaSdk Token {id}", attrs, bytes, ContentType, replace: true).ConfigureAwait(false);
        }

        private static async Task<TokenBundle?> LoadTokenBundleAsync(Collection collection, string id)
        {
            var attrs = new Dictionary<string, string>
            {
                [AppAttribute] = AppName,
                [TypeAttribute] = TokenItemType,
                [IdAttribute] = id,
            };
            var items = await collection.SearchItemsAsync(attrs).ConfigureAwait(false);
            if (items == null || items.Length == 0)
            {
                return null;
            }

            var bytes = await items[0].GetSecretAsync().ConfigureAwait(false);
            if (bytes == null || bytes.Length == 0)
            {
                return null;
            }

            return JsonSerializer.Deserialize<TokenBundle>(bytes, _jsonOptions);
        }

        private static async Task DeleteTokenItemAsync(Collection collection, string id)
        {
            var attrs = new Dictionary<string, string>
            {
                [AppAttribute] = AppName,
                [TypeAttribute] = TokenItemType,
                [IdAttribute] = id,
            };
            var items = await collection.SearchItemsAsync(attrs).ConfigureAwait(false);
            if (items != null)
            {
                foreach (var item in items)
                {
                    await item.DeleteAsync().ConfigureAwait(false);
                }
            }
        }

        private static TokenMetadata? CopyMetadata(TokenMetadata? source)
        {
            if (source is null)
            {
                return null;
            }

            return new TokenMetadata
            {
                Issuer = source.Issuer,
                Scope = source.Scope is null ? null : new List<string>(source.Scope),
                ClientId = source.ClientId,
                Id = source.Id,
                Tags = source.Tags is null ? null : new Dictionary<string, string>(source.Tags),
                Claims = source.Claims is null ? null : new Dictionary<string, JsonElement>(source.Claims),
            };
        }

        private static async Task<Manifest> LoadManifestAsync(Collection collection)
        {
            var attrs = new Dictionary<string, string> { [AppAttribute] = AppName, [TypeAttribute] = ManifestItemType };
            var items = await collection.SearchItemsAsync(attrs).ConfigureAwait(false);
            Manifest manifest;
            if (items == null || items.Length == 0)
            {
                manifest = new Manifest();
            }
            else
            {
                var bytes = await items[0].GetSecretAsync().ConfigureAwait(false);
                manifest = (bytes == null || bytes.Length == 0)
                    ? new Manifest()
                    : (JsonSerializer.Deserialize<Manifest>(bytes, _jsonOptions) ?? new Manifest());
            }

            return manifest;
        }

        private static async Task SaveManifestAsync(Collection collection, Manifest manifest)
        {
            var attrs = new Dictionary<string, string> { [AppAttribute] = AppName, [TypeAttribute] = ManifestItemType };
            var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(manifest, _jsonOptions));
            await collection.CreateItemAsync("OktaSdk Manifest", attrs, bytes, ContentType, replace: true).ConfigureAwait(false);
        }

        private async Task<Collection> GetOrCreateCollectionAsync()
        {
            if (_collection != null)
            {
                return _collection;
            }

            var service = await SecretService.ConnectAsync(EncryptionType.Dh).ConfigureAwait(false);
            var collection = await service.GetDefaultCollectionAsync().ConfigureAwait(false);
            if (collection == null)
            {
                collection = await service.CreateCollectionAsync(CollectionLabel, CollectionAlias).ConfigureAwait(false);
            }

            _collection = collection;
            return _collection;
        }

        // Always returns a deep copy. Caller may mutate either the input or the result
        // without affecting subsequent operations on the same instance.
        private TokenMetadata StripClaimsIfNeeded(TokenMetadata metadata)
        {
            var copy = CopyMetadata(metadata)!;
            if (!IncludeClaims)
            {
                copy.Claims = null;
            }

            return copy;
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            _lock.Dispose();
            GC.SuppressFinalize(this);
        }

        private sealed class Manifest
        {
            [JsonPropertyName("ids")]
            public List<string> Ids { get; set; } = new();

            [JsonPropertyName("default_id")]
            public string? DefaultId { get; set; }
        }

        private sealed class TokenBundle
        {
            [JsonPropertyName("token")]
            public Token? Token { get; set; }

            [JsonPropertyName("metadata")]
            public TokenMetadata? Metadata { get; set; }

            public TokenBundle()
            {
            }

            public TokenBundle(Token? token, TokenMetadata? metadata)
            {
                Token = token;
                Metadata = metadata;
            }
        }
    }
}
