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

using Microsoft.Extensions.Logging;

namespace Okta.AuthFoundation.TokenManagement
{
    /// <summary>
    /// Default implementation of <see cref="ICredentialCoordinator"/> that manages credential lifecycle against a token storage backend.
    /// </summary>
    public class CredentialCoordinator : ICredentialCoordinator, IDisposable
    {
        private readonly ILogger<CredentialCoordinator> _logger = OktaServices.Resolve<ILogger<CredentialCoordinator>>();

        /// <inheritdoc/>
        public ITokenStorage TokenStorage { get; private set; }

        private ICredentialDataSource _credentialDataSource;

        /// <summary>
        /// Gets or sets the credential data source used to create and track <see cref="Credential"/> instances.
        /// </summary>
        public ICredentialDataSource CredentialDataSource
        {
            get => _credentialDataSource;
            protected set
            {
                if (_credentialDataSource != null)
                {
                    _credentialDataSource.CredentialAdded -= OnCredentialAdded;
                }

                _credentialDataSource = value;

                // Subscribe to CredentialAdded event
                if (_credentialDataSource != null)
                {
                    _credentialDataSource.CredentialAdded += OnCredentialAdded;
                }
            }
        }

        // keep track of event handlers so we can unsubscribe if needed, preventing memory leaks
        private readonly Dictionary<string, EventHandler<TokenRefreshedEventArgs>> _tokenRefreshedHandlers = new();

        private void OnCredentialAdded(object? sender, CredentialAddedEventArgs e)
        {
            EventHandler<TokenRefreshedEventArgs> handler = async (s, args) =>
            {
                try
                {
                    await TokenStorage.ReplaceAsync(args.OldToken.Id, args.NewToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to persist refreshed token to storage.");
                }
            };

            e.Credential.Client.TokenRefreshed += handler;
            _tokenRefreshedHandlers[e.Credential.Id] = handler;
        }

        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(1, 1);

        private Credential? _defaultCredential;

        /// <summary>
        /// Initializes a new instance of <see cref="CredentialCoordinator"/> with optional storage and data source overrides.
        /// </summary>
        /// <param name="tokenStorage">The token storage to use, or <c>null</c> to resolve from <see cref="Okta.AuthFoundation.OktaServices"/>.</param>
        /// <param name="credentialDataSource">The credential data source to use, or <c>null</c> to resolve from <see cref="Okta.AuthFoundation.OktaServices"/>.</param>
        public CredentialCoordinator(ITokenStorage? tokenStorage = null, ICredentialDataSource? credentialDataSource = null)
        {
            this.CredentialDataSource = credentialDataSource ?? OktaServices.Resolve<ICredentialDataSource>();
            this.TokenStorage = tokenStorage ?? OktaServices.Resolve<ITokenStorage>();
            this.TokenStorage.DefaultTokenChanged += OnDefaultTokenChanged;
        }

        private void OnDefaultTokenChanged(object? sender, DefaultTokenChangedEventArgs e)
        {
            _defaultCredential = null;
        }

        /// <inheritdoc/>
        public async Task<Credential> StoreAsync(Token token, Dictionary<string, string>? tags = null, CancellationToken cancellationToken = default)
        {
            await _semaphore.WaitAsync(cancellationToken);
            try
            {
                TokenMetadata metadata = new TokenMetadata(token, tags);
                await this.TokenStorage.AddAsync(token, metadata, cancellationToken);
                Credential credential = this.CredentialDataSource.For(token, metadata);

                var currentDefaultId = await this.TokenStorage.GetDefaultTokenIdAsync(cancellationToken);
                bool hasValidDefault = currentDefaultId != null
                    && await this.TokenStorage.GetAsync(currentDefaultId, cancellationToken) != null;
                if (!hasValidDefault)
                {
                    await this.TokenStorage.SetDefaultTokenIdAsync(token.Id, cancellationToken);
                }

                return credential;
            }
            finally
            {
                _semaphore.Release();
            }
        }

        /// <inheritdoc/>
        public async Task<Credential?> WithAsync(string id, CancellationToken cancellationToken = default)
        {
            await _semaphore.WaitAsync(cancellationToken);
            try
            {
                return await this.WithInternalAsync(id);
            }
            finally
            {
                _semaphore.Release();
            }
        }

        // unguarded internal implementation of WithAsync to avoid deadlocks
        private async Task<Credential?> WithInternalAsync(string id)
        {
            Token? token = await this.TokenStorage.GetAsync(id);
            TokenMetadata? metadata = await this.TokenStorage.GetMetadataAsync(id);

            if (token != null)
            {
                Credential credential = this.CredentialDataSource.For(token, metadata);
                return credential;
            }

            return null;
        }

        /// <inheritdoc/>
        public async Task<List<Credential>> FindAsync(Func<TokenMetadata, bool> predicate, CancellationToken cancellationToken = default)
        {
            await _semaphore.WaitAsync(cancellationToken);
            try
            {
                var ids = await this.AllIdsInternalAsync();
                var results = new List<Credential>();
                foreach (var id in ids)
                {
                    var metadata = await this.TokenStorage.GetMetadataAsync(id, cancellationToken);
                    if (metadata != null && predicate(metadata))
                    {
                        var credential = await this.WithInternalAsync(metadata.Id);
                        if (credential != null)
                        {
                            results.Add(credential);
                        }
                    }
                }

                return results;
            }
            finally
            {
                _semaphore.Release();
            }
        }

        /// <inheritdoc/>
        public async Task RemoveAsync(Credential credential, CancellationToken cancellationToken = default)
        {
            await _semaphore.WaitAsync(cancellationToken);
            try
            {
                await this.TokenStorage.RemoveAsync(credential.Id, cancellationToken);
                this.CredentialDataSource.Remove(credential);
                if (_defaultCredential != null && _defaultCredential.Id == credential.Id)
                {
                    _defaultCredential = null;
                    await this.TokenStorage.SetDefaultTokenIdAsync(null, cancellationToken);
                }

                if (_tokenRefreshedHandlers.TryGetValue(credential.Id, out var handler))
                {
                    credential.Client.TokenRefreshed -= handler;
                    _tokenRefreshedHandlers.Remove(credential.Id);
                }
            }
            finally
            {
                _semaphore.Release();
            }
        }

        /// <inheritdoc/>
        public async Task ClearAsync(CancellationToken cancellationToken = default)
        {
            await _semaphore.WaitAsync(cancellationToken);
            try
            {
                foreach (var (credentialId, handler) in _tokenRefreshedHandlers)
                {
                    var credential = await this.WithInternalAsync(credentialId);
                    if (credential != null)
                    {
                        credential.Client.TokenRefreshed -= handler;
                    }
                }

                _tokenRefreshedHandlers.Clear();
                this.CredentialDataSource.Clear();
                await this.TokenStorage.ClearAsync(cancellationToken);

                _defaultCredential = null;
            }
            finally
            {
                _semaphore.Release();
            }
        }

        /// <inheritdoc/>
        public async Task<List<string>> AllIdsAsync(CancellationToken cancellationToken = default)
        {
            await _semaphore.WaitAsync(cancellationToken);
            try
            {
                return await this.AllIdsInternalAsync();
            }
            finally
            {
                _semaphore.Release();
            }
        }

        // unguarded internal implementation of AllIdsAsync to avoid deadlocks
        private async Task<List<string>> AllIdsInternalAsync()
        {
            return await this.TokenStorage.AllIdsAsync();
        }

        /// <inheritdoc/>
        public async Task<Credential?> GetDefaultAsync(CancellationToken cancellationToken = default)
        {
            await _semaphore.WaitAsync(cancellationToken);
            try
            {
                if (_defaultCredential != null)
                {
                    return _defaultCredential;
                }

                var defaultId = await this.TokenStorage.GetDefaultTokenIdAsync(cancellationToken);
                if (defaultId != null)
                {
                    var credential = await this.WithInternalAsync(defaultId);
                    _defaultCredential = credential;
                    return credential;
                }

                return null;
            }
            finally
            {
                _semaphore.Release();
            }
        }

        /// <inheritdoc/>
        public async Task SetDefaultAsync(Credential? credential, CancellationToken cancellationToken = default)
        {
            await _semaphore.WaitAsync(cancellationToken);
            try
            {
                await TokenStorage.SetDefaultTokenIdAsync(credential?.Id, cancellationToken);
                _defaultCredential = credential;
            }
            finally
            {
                _semaphore.Release();
            }
        }

        /// <inheritdoc/>
        public async Task UpdateTagsAsync(Credential credential, Dictionary<string, string>? tags, CancellationToken cancellationToken = default)
        {
            await _semaphore.WaitAsync(cancellationToken);
            try
            {
                var newToken = credential.Token;
                await this.TokenStorage.ReplaceAsync(newToken.Id, newToken, cancellationToken);
                var newMetadata = new TokenMetadata(newToken, tags);
                await this.TokenStorage.SetMetadataAsync(newMetadata, cancellationToken);
            }
            finally
            {
                _semaphore.Release();
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            _semaphore.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
