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

using System;
using System.Collections.Concurrent;
using Okta.AuthFoundation.OAuth2;

namespace Okta.AuthFoundation.TokenManagement
{
    /// <summary>
    /// Basic in-memory implementation of <see cref="ICredentialDataSource"/>.
    /// </summary>
    public class DefaultCredentialDataSource : ICredentialDataSource
    {
        /// <summary>
        /// Gets the dictionary storing credentials by their ID.
        /// </summary>
        protected ConcurrentDictionary<string, Credential> Credentials { get; } = new ConcurrentDictionary<string, Credential>();

        /// <summary>
        /// Creates an OAuth2 client for the specified issuer, client ID, scope, and authentication.
        /// </summary>
        /// <param name="issuer">The issuer URI.</param>
        /// <param name="clientId">The client ID.</param>
        /// <param name="scope">The list of scopes.</param>
        /// <param name="authentication">The resolved client authentication method.</param>
        /// <returns>A new <see cref="Okta.AuthFoundation.OAuth2.OAuth2Client"/> instance.</returns>
        protected static OAuth2Client CreateOAuth2Client(Uri issuer, string clientId, List<string> scope, IClientAuthentication authentication)
        {
            var configuration = new OAuth2ClientConfiguration(issuer, clientId, scope, authentication);
            return new OAuth2Client(configuration);
        }

        /// <summary>
        /// Creates a credential for the specified token and metadata.
        /// </summary>
        /// <param name="token">The token to create a credential for.</param>
        /// <param name="metadata">Optional metadata associated with the token.</param>
        /// <returns>A new <see cref="Credential"/> instance.</returns>
        protected static Credential CreateCredential(Token token, TokenMetadata? metadata)
        {
            var context = token.Context;
            Uri issuer = context?.Issuer ?? metadata?.Issuer
                ?? throw new InvalidOperationException("Cannot create credential: no issuer found.");
            string clientId = context?.ClientId ?? metadata?.ClientId
                ?? throw new InvalidOperationException("Cannot create credential: no client ID found.");
            List<string> scope = context?.Scope ?? metadata?.Scope ?? new List<string>();
            var authentication = OktaServices.ResolveClientAuthentication(clientId, context?.AuthenticationMethod);

            var client = CreateOAuth2Client(issuer, clientId, scope, authentication);
            return new Credential(token, client, metadata);
        }

        /// <summary>
        /// Occurs when a new credential is added to the data source.
        /// </summary>
        public event EventHandler<CredentialAddedEventArgs>? CredentialAdded;

        /// <inheritdoc/>
        public bool Has(Token token)
        {
            return Credentials.ContainsKey(token.Id);
        }

        /// <inheritdoc/>
        public Credential For(Token token, TokenMetadata? metadata)
        {
            if (Credentials.TryGetValue(token.Id, out var existing))
            {
                return existing;
            }

            var newCredential = CreateCredential(token, metadata);
            var stored = Credentials.GetOrAdd(token.Id, newCredential);
            if (ReferenceEquals(stored, newCredential))
            {
                CredentialAdded?.Invoke(this, new CredentialAddedEventArgs(stored));
            }

            return stored;
        }

        /// <inheritdoc/>
        public void Remove(Credential credential)
        {
            this.Remove(credential.Id);
        }

        /// <inheritdoc/>
        public void Remove(string id)
        {
            Credentials.TryRemove(id, out _);
        }

        /// <inheritdoc/>
        public void Clear()
        {
            Credentials.Clear();
        }

        /// <inheritdoc/>
        public int Size()
        {
            return Credentials.Count;
        }
    }
}
