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
using System.Collections.Generic;
using Okta.AuthFoundation.TokenManagement;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    public class CredentialDataSourceTests
    {
        private readonly DefaultCredentialDataSource _dataSource;
        private readonly Token _token;
        private readonly TokenMetadata _metadata;

        public CredentialDataSourceTests()
        {
            _dataSource = new DefaultCredentialDataSource();
            _token = TestHelpers.CreateToken();
            _metadata = TestHelpers.CreateTokenMetadata(_token);
        }

        [Fact]
        public void CredentialFor_ReturnsCredential()
        {
            var credential = _dataSource.For(_token, _metadata);

            Assert.NotNull(credential);
        }

        [Fact]
        public void HasCredential_ReturnsTrue_AfterAdding()
        {
            _dataSource.For(_token, _metadata);

            Assert.True(_dataSource.Has(_token));
        }

        [Fact]
        public void HasCredential_ReturnsFalse_ForUnknownToken()
        {
            var unknownToken = TestHelpers.CreateToken();

            Assert.False(_dataSource.Has(unknownToken));
        }

        [Fact]
        public void Remove_ByCredential_RemovesCredential()
        {
            var credential = _dataSource.For(_token, _metadata);

            _dataSource.Remove(credential);

            Assert.False(_dataSource.Has(_token));
        }

        [Fact]
        public void Remove_ById_RemovesCredential()
        {
            var tokenWithId = TestHelpers.CreateToken(id: "id1");
            var metadataWithId = TestHelpers.CreateTokenMetadata(tokenWithId);

            _dataSource.For(tokenWithId, metadataWithId);
            _dataSource.Remove("id1");

            Assert.False(_dataSource.Has(tokenWithId));
        }

        [Fact]
        public void Clear_RemovesAllCredentials()
        {
            var token1 = TestHelpers.CreateToken();
            var token2 = TestHelpers.CreateToken(id: "id2");

            _dataSource.For(token1, TestHelpers.CreateTokenMetadata(token1));
            _dataSource.For(token2, TestHelpers.CreateTokenMetadata(token2, new Dictionary<string, string> { ["tag2"] = "tag2" }));
            _dataSource.Clear();

            Assert.False(_dataSource.Has(token1));
            Assert.False(_dataSource.Has(token2));
        }

        [Fact]
        public void Size_ReturnsCorrectCount()
        {
            var token1 = TestHelpers.CreateToken();
            var token2 = TestHelpers.CreateToken(id: "id2");

            _dataSource.For(token1, TestHelpers.CreateTokenMetadata(token1));
            _dataSource.For(token2, TestHelpers.CreateTokenMetadata(token2, new Dictionary<string, string> { ["tag2"] = "tag2" }));

            Assert.Equal(2, _dataSource.Size());
        }

        [Fact]
        public void For_RaisesCredentialAddedEvent_WhenNewCredentialCreated()
        {
            CredentialAddedEventArgs? eventArgs = null;
            _dataSource.CredentialAdded += (sender, args) => eventArgs = args;

            var credential = _dataSource.For(_token, _metadata);

            Assert.NotNull(eventArgs);
            Assert.Same(credential, eventArgs.Credential);
        }

        [Fact]
        public void For_DoesNotRaiseEvent_WhenCredentialAlreadyExists()
        {
            // First call creates the credential
            _dataSource.For(_token, _metadata);

            int eventCount = 0;
            _dataSource.CredentialAdded += (sender, args) => eventCount++;

            // Second call should return existing credential without raising event
            _dataSource.For(_token, _metadata);

            Assert.Equal(0, eventCount);
        }
    }
}
