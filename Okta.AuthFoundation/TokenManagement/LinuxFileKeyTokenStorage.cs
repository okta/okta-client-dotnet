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
    /// Persists tokens and metadata to a JSON file on disk with AES-256-GCM encryption.
    /// Each token entry's sensitive data (the serialized <see cref="Token"/>) is encrypted
    /// using a 256-bit AES key. Metadata is stored unencrypted to allow querying without decryption.
    /// The claims snapshot is omitted from stored metadata unless
    /// <see cref="ITokenStorage.IncludeClaims"/> is enabled.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This implementation is Linux-only.
    /// </para>
    /// <para>
    /// <b>Default key storage (file-based):</b> A randomly generated 256-bit key is written to
    /// <c>~/.local/share/OktaSdk/encryption.key</c> with Unix permissions 0600 (owner read/write only).
    /// This protects tokens from other user accounts on the same machine, but does <b>not</b> protect
    /// against the root user or a process running as the same user. This is the same security model
    /// as SSH private keys stored in <c>~/.ssh/</c>.
    /// </para>
    /// <para>
    /// <b>Custom key provider:</b> For stronger protection, use the
    /// <see cref="LinuxFileKeyTokenStorage(string, Func{byte[]}, bool)"/> constructor to supply a
    /// <c>keyProvider</c> delegate backed by a hardware security module (HSM), a cloud KMS
    /// (AWS KMS, Azure Key Vault, GCP Cloud KMS, HashiCorp Vault), or a system keyring via libsecret.
    /// The delegate must return a 32-byte (256-bit) key and will be called once per instance.
    /// </para>
    /// <para>
    /// Default file locations:
    /// <list type="bullet">
    ///   <item><description>Token storage: <c>~/.local/share/OktaSdk/tokens.encrypted.json</c></description></item>
    ///   <item><description>Encryption key: <c>~/.local/share/OktaSdk/encryption.key</c></description></item>
    /// </list>
    /// </para>
    /// </remarks>
    [SupportedOSPlatform("linux")]
    public class LinuxFileKeyTokenStorage : ITokenStorage
    {
        private const int KeySizeBytes = 32;   // AES-256
        private const int NonceSizeBytes = 12;  // AES-GCM standard
        private const int TagSizeBytes = 16;    // 128-bit tag

        private readonly string _filePath;
        private readonly Func<byte[]> _keyProvider;
        private readonly object _lock = new();
        private readonly ILogger<LinuxFileKeyTokenStorage> _logger = OktaServices.Resolve<ILogger<LinuxFileKeyTokenStorage>>();
        private EncryptedStorageData? _cache;
        private byte[]? _key;

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
        /// Initializes a new instance using the default file paths and file-based key storage.
        /// </summary>
        /// <param name="includeClaims">Whether to snapshot claims into metadata. See <see cref="ITokenStorage.IncludeClaims"/>.</param>
        public LinuxFileKeyTokenStorage(bool includeClaims = false)
            : this(GetDefaultFilePath(), GetDefaultKeyFilePath(), includeClaims)
        {
        }

        /// <summary>
        /// Initializes a new instance using custom file paths and file-based key storage.
        /// The encryption key is generated on first use and persisted at <paramref name="keyFilePath"/>
        /// with permissions 0600.
        /// </summary>
        /// <param name="filePath">The full path to the encrypted JSON storage file.</param>
        /// <param name="keyFilePath">The full path where the encryption key is stored.</param>
        /// <param name="includeClaims">Whether to snapshot claims into metadata. See <see cref="ITokenStorage.IncludeClaims"/>.</param>
        public LinuxFileKeyTokenStorage(string filePath, string keyFilePath, bool includeClaims = false)
            : this(filePath, CreateFileKeyProvider(keyFilePath), includeClaims)
        {
        }

        /// <summary>
        /// Initializes a new instance using a custom key provider.
        /// Use this overload to supply a key from a hardware security module (HSM), cloud KMS,
        /// or system keyring instead of the default file-based key storage.
        /// </summary>
        /// <param name="filePath">The full path to the encrypted JSON storage file.</param>
        /// <param name="keyProvider">
        /// A delegate that returns the 32-byte (256-bit) AES key. Called once per instance;
        /// the result is cached for the lifetime of the instance.
        /// </param>
        /// <param name="includeClaims">Whether to snapshot claims into metadata. See <see cref="ITokenStorage.IncludeClaims"/>.</param>
        public LinuxFileKeyTokenStorage(string filePath, Func<byte[]> keyProvider, bool includeClaims = false)
        {
            if (!OperatingSystem.IsLinux())
            {
                throw new PlatformNotSupportedException(
                    $"{nameof(LinuxFileKeyTokenStorage)} requires Linux.");
            }

            ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
            ArgumentNullException.ThrowIfNull(keyProvider);
            _filePath = filePath;
            _keyProvider = keyProvider;
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

        private static Func<byte[]> CreateFileKeyProvider(string keyFilePath)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(keyFilePath);

            return () =>
            {
                var directory = Path.GetDirectoryName(keyFilePath);
                if (!string.IsNullOrEmpty(directory))
                {
                    Directory.CreateDirectory(directory);
                    File.SetUnixFileMode(
                        directory,
                        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute); // 0700
                }

                try
                {
                    // CreateNew is atomic: if the file already exists, it throws IOException,
                    // eliminating the TOCTOU race between File.Exists and File.WriteAllBytes.
                    // UnixCreateMode sets permissions at creation time, avoiding a window where
                    // the file is world-readable before SetUnixFileMode can be called.
                    var options = new FileStreamOptions
                    {
                        Mode = FileMode.CreateNew,
                        Access = FileAccess.Write,
                        Share = FileShare.None,
                        UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite, // 0600
                    };
                    using var stream = new FileStream(keyFilePath, options);
                    var newKey = RandomNumberGenerator.GetBytes(KeySizeBytes);
                    stream.Write(newKey);
                    stream.Flush();
                    return newKey;
                }
                catch (IOException) when (File.Exists(keyFilePath))
                {
                    // Another process created the key file first — read it instead.
                    // The guard ensures we only swallow "file already exists" IOExceptions,
                    // not disk-full, read-only filesystem, or other I/O failures.
                }

                var existingKey = File.ReadAllBytes(keyFilePath);

                // Enforce 0600 regardless of how the file was originally created.
                File.SetUnixFileMode(keyFilePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                return existingKey;
            };
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

        private static string GetDefaultKeyFilePath()
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            return Path.Combine(appData, "OktaSdk", "encryption.key");
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
            var key = LoadOrCreateKey();
            var json = JsonSerializer.Serialize(token, _jsonOptions);
            var plaintext = Encoding.UTF8.GetBytes(json);

            var nonce = new byte[NonceSizeBytes];
            RandomNumberGenerator.Fill(nonce);

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[TagSizeBytes];

            using var aes = new AesGcm(key, TagSizeBytes);
            aes.Encrypt(nonce, plaintext, ciphertext, tag);

            // Format: nonce(12) || ciphertext || tag(16)
            var result = new byte[NonceSizeBytes + ciphertext.Length + TagSizeBytes];
            nonce.CopyTo(result, 0);
            ciphertext.CopyTo(result, NonceSizeBytes);
            tag.CopyTo(result, NonceSizeBytes + ciphertext.Length);

            return Convert.ToBase64String(result);
        }

        private Token Decrypt(string encryptedBase64)
        {
            var key = LoadOrCreateKey();
            byte[] combined;
            try
            {
                combined = Convert.FromBase64String(encryptedBase64);
            }
            catch (FormatException ex)
            {
                throw new CryptographicException("Encrypted token data is corrupted.", ex);
            }

            if (combined.Length < NonceSizeBytes + TagSizeBytes)
            {
                throw new CryptographicException("Encrypted data is too short.");
            }

            var nonce = combined.AsSpan(0, NonceSizeBytes);
            var ciphertextLength = combined.Length - NonceSizeBytes - TagSizeBytes;
            var ciphertext = combined.AsSpan(NonceSizeBytes, ciphertextLength);
            var tag = combined.AsSpan(NonceSizeBytes + ciphertextLength, TagSizeBytes);

            var plaintext = new byte[ciphertextLength];

            using var aes = new AesGcm(key, TagSizeBytes);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);

            var json = Encoding.UTF8.GetString(plaintext);
            return JsonSerializer.Deserialize<Token>(json, _jsonOptions)
                ?? throw new InvalidOperationException("Failed to deserialize decrypted token.");
        }

        private byte[] LoadOrCreateKey()
        {
            if (_key is not null)
            {
                return _key;
            }

            _key = _keyProvider();

            if (_key.Length != KeySizeBytes)
            {
                throw new CryptographicException(
                    $"Key provider returned {_key.Length} bytes; expected {KeySizeBytes}.");
            }

            return _key;
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
        /// Called when the storage file cannot be read or deserialized.
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
                File.SetUnixFileMode(
                    directory,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute); // 0700
            }

            var tempPath = _filePath + ".tmp";
            var backupPath = _filePath + ".bak";

            var tempOptions = new FileStreamOptions
            {
                Mode = FileMode.Create,
                Access = FileAccess.Write,
                Share = FileShare.None,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite, // 0600
            };
            using (var stream = new FileStream(tempPath, tempOptions))
            {
                JsonSerializer.Serialize(stream, data, _jsonOptions);
            }

            if (File.Exists(_filePath))
            {
                File.Replace(tempPath, _filePath, backupPath);
                File.SetUnixFileMode(backupPath, UnixFileMode.UserRead | UnixFileMode.UserWrite); // 0600
            }
            else
            {
                File.Move(tempPath, _filePath);
            }

            // File.Replace preserves the destination's existing permissions, so re-flushes
            // won't tighten loose perms unless we explicitly set them here.
            File.SetUnixFileMode(_filePath, UnixFileMode.UserRead | UnixFileMode.UserWrite); // 0600

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
