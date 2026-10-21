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
using Okta.AuthFoundation.OAuth2;
using Okta.AuthFoundation.TokenManagement;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    // Verifies that IClientAuthentication is rebound when credentials are reloaded
    // from storage. ResolveClientAuthentication mutates global state, so these tests
    // run sequentially and reset between cases.
    [Collection("OktaServicesReset")]
    public class ClientAuthenticationStorageTests : IDisposable
    {
        public ClientAuthenticationStorageTests() => OktaServices.Reset();

        public void Dispose()
        {
            OktaServices.Reset();
            GC.SuppressFinalize(this);
        }

        private static TokenContext ContextWith(string? authenticationMethod) =>
            new TokenContext(
                TestHelpers.ExampleUri,
                new List<string> { "openid" },
                TestHelpers.DefaultClientId,
                authenticationMethod);

        private static Token TokenWith(TokenContext context) =>
            new Token(context)
            {
                Id = TestHelpers.DefaultId,
                TokenType = TestHelpers.DefaultTokenType,
                AccessToken = TestHelpers.DefaultAccessToken,
                ExpiresIn = TestHelpers.DefaultExpiresIn,
            };

        [Fact]
        public void Reload_WithNullAuthenticationMethod_UsesNoneAuthentication()
        {
            // Tokens stored before the field was added have a null AuthenticationMethod.
            var dataSource = new DefaultCredentialDataSource();
            var token = TokenWith(ContextWith(authenticationMethod: null));

            var credential = dataSource.For(token, metadata: null);

            Assert.Equal(ClientAuthentication.None, credential.Client.Configuration.Authentication.Method);
        }

        [Fact]
        public void Reload_WithNoneAuthenticationMethod_UsesNoneAuthentication()
        {
            var dataSource = new DefaultCredentialDataSource();
            var token = TokenWith(ContextWith(authenticationMethod: ClientAuthentication.None.ToString()));

            var credential = dataSource.For(token, metadata: null);

            Assert.Equal(ClientAuthentication.None, credential.Client.Configuration.Authentication.Method);
        }

        [Fact]
        public void Reload_WithClientSecretMethod_NoFactoryRegistered_Throws()
        {
            var dataSource = new DefaultCredentialDataSource();
            var token = TokenWith(ContextWith(ClientAuthentication.ClientSecret.ToString()));

            var ex = Assert.Throws<InvalidOperationException>(() => dataSource.For(token, metadata: null));
            Assert.Contains("ClientSecret", ex.Message);
            Assert.Contains("ConfigureClientAuthentication", ex.Message);
        }

        [Fact]
        public void Reload_WithPrivateKeyJwtMethod_NoFactoryRegistered_Throws()
        {
            var dataSource = new DefaultCredentialDataSource();
            var token = TokenWith(ContextWith(ClientAuthentication.PrivateKeyJwt.ToString()));

            var ex = Assert.Throws<InvalidOperationException>(() => dataSource.For(token, metadata: null));
            Assert.Contains("PrivateKeyJwt", ex.Message);
        }

        [Fact]
        public void Reload_WithClientSecretMethod_FactoryRegistered_UsesFactoryResult()
        {
            int factoryCalls = 0;
            var expectedAuth = new ClientSecretAuthentication("secret-from-vault");
            OktaServices.ConfigureClientAuthentication((clientId, method) =>
            {
                factoryCalls++;
                Assert.Equal(TestHelpers.DefaultClientId, clientId);
                Assert.Equal(ClientAuthentication.ClientSecret.ToString(), method);
                return expectedAuth;
            });

            var dataSource = new DefaultCredentialDataSource();
            var token = TokenWith(ContextWith(ClientAuthentication.ClientSecret.ToString()));

            var credential = dataSource.For(token, metadata: null);

            Assert.Equal(1, factoryCalls);
            Assert.Same(expectedAuth, credential.Client.Configuration.Authentication);
        }

        [Fact]
        public void Reload_WithPrivateKeyJwtMethod_FactoryRegistered_UsesFactoryResult()
        {
            var expectedAuth = new PrivateKeyJwtAuthentication(_ => "signed.jwt.assertion");
            OktaServices.ConfigureClientAuthentication((_, _) => expectedAuth);

            var dataSource = new DefaultCredentialDataSource();
            var token = TokenWith(ContextWith(ClientAuthentication.PrivateKeyJwt.ToString()));

            var credential = dataSource.For(token, metadata: null);

            Assert.Same(expectedAuth, credential.Client.Configuration.Authentication);
        }

        [Fact]
        public void Reload_WithNoneMethod_DoesNotCallFactory()
        {
            int factoryCalls = 0;
            OktaServices.ConfigureClientAuthentication((_, _) =>
            {
                factoryCalls++;
                return new NoneClientAuthentication();
            });

            var dataSource = new DefaultCredentialDataSource();
            var token = TokenWith(ContextWith(ClientAuthentication.None.ToString()));

            dataSource.For(token, metadata: null);

            Assert.Equal(0, factoryCalls);
        }

        [Fact]
        public void ConfigureClientAuthentication_NullFactory_Throws()
        {
            Assert.Throws<ArgumentNullException>(() =>
                OktaServices.ConfigureClientAuthentication(null!));
        }

        [Fact]
        public void TokenContext_RecordsAuthenticationMethodFromConfiguration()
        {
            // The authentication method is captured in TokenContext when OAuth2Client.ExchangeAsync
            // mints a new token. This test pins the recording side directly.
            var ctx = new TokenContext(
                TestHelpers.ExampleUri,
                new List<string> { "openid" },
                TestHelpers.DefaultClientId,
                ClientAuthentication.PrivateKeyJwt.ToString());

            Assert.Equal("PrivateKeyJwt", ctx.AuthenticationMethod);
        }
    }
}
