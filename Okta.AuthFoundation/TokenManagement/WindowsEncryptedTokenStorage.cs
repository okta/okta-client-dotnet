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
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace Okta.AuthFoundation.TokenManagement
{
    /// <summary>
    /// Persists tokens and metadata to a JSON file on disk using Windows DPAPI encryption.
    /// Each token entry's sensitive data (the serialized <see cref="Token"/>) is encrypted
    /// using <see cref="ProtectedData"/> (Windows DPAPI) before being written to disk.
    /// Metadata is stored unencrypted to allow querying without decryption. The claims snapshot is
    /// omitted from stored metadata unless <see cref="ITokenStorage.IncludeClaims"/> is enabled.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This implementation is Windows-only. DPAPI encrypts data using the current user's
    /// credentials, meaning the encrypted file can only be read by the same Windows user
    /// account that created it.
    /// </para>
    /// <para>
    /// Default file location is <c>{LocalApplicationData}/OktaSdk/tokens.encrypted.json</c>.
    /// </para>
    /// <para>
    /// The <see cref="System.Security.Cryptography.DataProtectionScope"/> can be configured at construction time:
    /// <list type="bullet">
    ///   <item><description><see cref="System.Security.Cryptography.DataProtectionScope.CurrentUser"/> (default) - only the current user can decrypt.</description></item>
    ///   <item><description><see cref="System.Security.Cryptography.DataProtectionScope.LocalMachine"/> - any user on the machine can decrypt.</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    [SupportedOSPlatform("windows")]
    public class WindowsEncryptedTokenStorage : ITokenStorage
    {
        private readonly string _filePath;
        private readonly DataProtectionScope _scope;
        private readonly byte[]? _optionalEntropy;
        private readonly object _lock = new();
        private readonly ILogger<WindowsEncryptedTokenStorage> _logger = OktaServices.Resolve<ILogger<WindowsEncryptedTokenStorage>>();
        private EncryptedStorageData? _cache;

        /// <inheritdoc/>
        public bool IncludeClaims { get; }

        /// <inheritdoc/>
        public event EventHandler<DefaultTokenChangedEventArgs>? DefaultTokenChanged;

        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        /// <summary>
        /// Initializes a new instance using the default file path and <see cref="DataProtectionScope.CurrentUser"/>.
        /// </summary>
        /// <param name="includeClaims">Whether to snapshot claims into metadata. See <see cref="ITokenStorage.IncludeClaims"/>.</param>
        public WindowsEncryptedTokenStorage(bool includeClaims = false)
            : this(GetDefaultFilePath(), includeClaims: includeClaims)
        {
        }

        /// <summary>
        /// Initializes a new instance using a custom file path.
        /// </summary>
        /// <param name="filePath">The full path to the encrypted JSON storage file.</param>
        /// <param name="scope">The DPAPI protection scope. Defaults to <see cref="System.Security.Cryptography.DataProtectionScope.CurrentUser"/>.</param>
        /// <param name="optionalEntropy">Optional additional entropy for DPAPI encryption. Must be the same value for encrypt and decrypt.</param>
        /// <param name="includeClaims">Whether to snapshot claims into metadata. See <see cref="ITokenStorage.IncludeClaims"/>.</param>
        public WindowsEncryptedTokenStorage(string filePath, DataProtectionScope scope = DataProtectionScope.CurrentUser, byte[]? optionalEntropy = null, bool includeClaims = false)
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException(
                    $"{nameof(WindowsEncryptedTokenStorage)} requires Windows (DPAPI).");
            }

            ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
            _filePath = filePath;
            _scope = scope;
            _optionalEntropy = optionalEntropy is not null ? (byte[])optionalEntropy.Clone() : null;
            IncludeClaims = includeClaims;
        }

        /// <inheritdoc/>
        public Task<bool> IsEmptyAsync(CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                var data = Load();
                return Task.FromResult(data.Entries.Count == 0);
            }
        }

        /// <inheritdoc/>
        public Task<List<string>> AllIdsAsync(CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                var data = Load();
                return Task.FromResult(data.Entries.Keys.ToList());
            }
        }

        /// <inheritdoc/>
        public Task AddAsync(Token token, TokenMetadata? metadata, CancellationToken cancellationToken = default)
        {
            DefaultTokenChangedEventArgs? args = null;
            lock (_lock)
            {
                if (metadata != null && token.Id != metadata.Id)
                {
                    throw new ArgumentException($"Token ID '{token.Id}' and Metadata ID '{metadata.Id}' do not match.");
                }

                var data = Load();
                if (data.Entries.ContainsKey(token.Id))
                {
                    throw new InvalidOperationException($"Token with the same ID '{token.Id}' already exists.");
                }

                bool isFirst = data.Entries.Count == 0;

                data.Entries[token.Id] = new EncryptedStorageEntry
                {
                    EncryptedToken = Encrypt(token),
                    Metadata = metadata != null ? StripClaimsIfNeeded(metadata) : null,
                };

                if (isFirst)
                {
                    args = SetDefaultTokenIdInternal(data, token.Id);
                }

                Flush(data);
            }

            if (args != null)
            {
                DefaultTokenChanged?.Invoke(this, args);
            }

            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public Task ReplaceAsync(string id, Token token, CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                var data = Load();
                if (!data.Entries.TryGetValue(id, out var entry))
                {
                    throw new KeyNotFoundException($"Token with ID '{id}' does not exist.");
                }

                if (token.Id != id)
                {
                    throw new ArgumentException($"Token ID '{token.Id}' does not match the storage key '{id}'.");
                }

                entry.EncryptedToken = Encrypt(token);
                Flush(data);
                return Task.CompletedTask;
            }
        }

        /// <inheritdoc/>
        public Task RemoveAsync(string id, CancellationToken cancellationToken = default)
        {
            DefaultTokenChangedEventArgs? args = null;
            lock (_lock)
            {
                var data = Load();
                if (!data.Entries.Remove(id))
                {
                    throw new KeyNotFoundException($"Token with the specified ID '{id}' does not exist.");
                }

                if (data.DefaultTokenId == id)
                {
                    args = SetDefaultTokenIdInternal(data, null);
                }

                Flush(data);
            }

            if (args != null)
            {
                DefaultTokenChanged?.Invoke(this, args);
            }

            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public Task<Token?> GetAsync(string id, CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                var data = Load();
                if (data.Entries.TryGetValue(id, out var entry) && entry.EncryptedToken != null)
                {
                    return Task.FromResult<Token?>(Decrypt(entry.EncryptedToken));
                }

                return Task.FromResult<Token?>(null);
            }
        }

        /// <inheritdoc/>
        public Task<TokenMetadata?> GetMetadataAsync(string id, CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                var data = Load();
                var metadata = data.Entries.TryGetValue(id, out var entry) ? entry.Metadata : null;
                return Task.FromResult(CopyMetadata(metadata));
            }
        }

        /// <inheritdoc/>
        public Task SetMetadataAsync(TokenMetadata metadata, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(metadata);
            if (string.IsNullOrWhiteSpace(metadata.Id))
            {
                throw new ArgumentException("metadata ID not found", nameof(metadata));
            }

            lock (_lock)
            {
                var data = Load();
                if (!data.Entries.TryGetValue(metadata.Id, out var entry))
                {
                    throw new KeyNotFoundException($"Token with the specified ID '{metadata.Id}' does not exist.");
                }

                entry.Metadata = StripClaimsIfNeeded(metadata);
                Flush(data);
                return Task.CompletedTask;
            }
        }

        /// <inheritdoc/>
        public Task ClearAsync(CancellationToken cancellationToken = default)
        {
            DefaultTokenChangedEventArgs? args;
            lock (_lock)
            {
                var data = Load();
                args = SetDefaultTokenIdInternal(data, null);
                Flush(new EncryptedStorageData());
            }

            if (args != null)
            {
                DefaultTokenChanged?.Invoke(this, args);
            }

            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public Task<string?> GetDefaultTokenIdAsync(CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                var data = Load();
                return Task.FromResult(data.DefaultTokenId);
            }
        }

        /// <inheritdoc/>
        public Task SetDefaultTokenIdAsync(string? id, CancellationToken cancellationToken = default)
        {
            DefaultTokenChangedEventArgs? args;
            lock (_lock)
            {
                var data = Load();
                args = SetDefaultTokenIdInternal(data, id);
                Flush(data);
            }

            if (args != null)
            {
                DefaultTokenChanged?.Invoke(this, args);
            }

            return Task.CompletedTask;
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

        private static string GetDefaultFilePath()
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            return Path.Combine(appData, "OktaSdk", "tokens.encrypted.json");
        }

        private static DefaultTokenChangedEventArgs? SetDefaultTokenIdInternal(EncryptedStorageData data, string? id)
        {
            var oldId = data.DefaultTokenId;
            if (oldId == id)
            {
                return null;
            }

            data.DefaultTokenId = id;
            return new DefaultTokenChangedEventArgs(oldId, id);
        }

        private string Encrypt(Token token)
        {
            var json = JsonSerializer.Serialize(token, _jsonOptions);
            var plainBytes = Encoding.UTF8.GetBytes(json);
            var encryptedBytes = ProtectedData.Protect(plainBytes, _optionalEntropy, _scope);
            return Convert.ToBase64String(encryptedBytes);
        }

        private Token Decrypt(string encryptedBase64)
        {
            var encryptedBytes = Convert.FromBase64String(encryptedBase64);
            var plainBytes = ProtectedData.Unprotect(encryptedBytes, _optionalEntropy, _scope);
            var json = Encoding.UTF8.GetString(plainBytes);
            return JsonSerializer.Deserialize<Token>(json, _jsonOptions)
                ?? throw new InvalidOperationException("Failed to deserialize decrypted token.");
        }

        private EncryptedStorageData Load()
        {
            if (_cache is not null)
            {
                return _cache;
            }

            if (!File.Exists(_filePath))
            {
                _cache = new EncryptedStorageData();
                return _cache;
            }

            try
            {
                using var stream = new FileStream(_filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                _cache = JsonSerializer.Deserialize<EncryptedStorageData>(stream, _jsonOptions) ?? new EncryptedStorageData();
            }
            catch (Exception ex) when (ex is JsonException or IOException)
            {
                OnReadError(ex);
                _cache = new EncryptedStorageData();
            }

            return _cache;
        }

        /// <summary>
        /// Called when the storage file cannot be read due to corruption or an I/O error.
        /// </summary>
        /// <param name="ex">The exception that caused the read failure.</param>
        protected virtual void OnReadError(Exception ex)
        {
            _logger.LogWarning(ex, "Encrypted token storage file '{FilePath}' is corrupted or unreadable. Treating as empty; the file will be overwritten on the next write.", _filePath);
        }

        private void Flush(EncryptedStorageData data)
        {
            var directory = Path.GetDirectoryName(_filePath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var tempPath = _filePath + ".tmp";
            var backupPath = _filePath + ".bak";

            using (var stream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                JsonSerializer.Serialize(stream, data, _jsonOptions);
            }

            if (File.Exists(_filePath))
            {
                File.Replace(tempPath, _filePath, backupPath);
            }
            else
            {
                File.Move(tempPath, _filePath);
            }

            _cache = data;
        }

        // Always returns a deep copy. Caller may mutate either the input or the result
        // without affecting the in-memory cache.
        private TokenMetadata StripClaimsIfNeeded(TokenMetadata metadata)
        {
            var copy = CopyMetadata(metadata)!;
            if (!IncludeClaims)
            {
                copy.Claims = null;
            }

            return copy;
        }

        internal sealed class EncryptedStorageData
        {
            [JsonPropertyName("default_token_id")]
            public string? DefaultTokenId { get; set; }

            [JsonPropertyName("entries")]
            public Dictionary<string, EncryptedStorageEntry> Entries { get; set; } = new();
        }

        internal sealed class EncryptedStorageEntry
        {
            [JsonPropertyName("encrypted_token")]
            public string? EncryptedToken { get; set; }

            [JsonPropertyName("metadata")]
            public TokenMetadata? Metadata { get; set; }
        }
    }
}
