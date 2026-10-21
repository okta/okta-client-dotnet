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

using System.Net;
using Okta.AuthFoundation;
using Okta.AuthFoundation.OAuth2;
using Okta.AuthFoundation.TokenManagement;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    public class NetworkStackTests : IDisposable
    {
        public NetworkStackTests()
        {
            OktaServices.Reset();
        }

        public void Dispose()
        {
            OktaServices.Reset();
            GC.SuppressFinalize(this);
        }

        [Fact]
        public async Task OAuth2Client_WithNoHttpClient_UsesConfiguredHandler()
        {
            bool handlerInvoked = false;
            OktaServices.ConfigureHttpMessageHandler(() => new TestHttpMessageHandler((req, ct) =>
            {
                handlerInvoked = true;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            }));

            var client = new OAuth2Client(TestHelpers.CreateOAuth2ClientConfiguration());
            await client.Client.GetAsync(TestHelpers.ExampleUri);

            Assert.True(handlerInvoked);
        }

        [Fact]
        public async Task OAuth2Client_WithExplicitHttpClient_BypassesConfiguredHandler()
        {
            bool configuredHandlerInvoked = false;
            OktaServices.ConfigureHttpMessageHandler(() => new TestHttpMessageHandler((req, ct) =>
            {
                configuredHandlerInvoked = true;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            }));

            bool explicitHandlerInvoked = false;
            var explicitClient = new HttpClient(new TestHttpMessageHandler((req, ct) =>
            {
                explicitHandlerInvoked = true;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            }));

            var client = new OAuth2Client(TestHelpers.CreateOAuth2ClientConfiguration(), explicitClient);
            await client.Client.GetAsync(TestHelpers.ExampleUri);

            Assert.False(configuredHandlerInvoked);
            Assert.True(explicitHandlerInvoked);
        }

        [Fact]
        public async Task CredentialDataSource_WithConfiguredHandler_UsesHandlerForAutoCreatedCredential()
        {
            bool handlerInvoked = false;
            OktaServices.ConfigureHttpMessageHandler(() => new TestHttpMessageHandler((req, ct) =>
            {
                handlerInvoked = true;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            }));

            var token = TestHelpers.CreateToken();
            var metadata = TestHelpers.CreateTokenMetadata(token);
            var dataSource = new DefaultCredentialDataSource();

            var credential = dataSource.For(token, metadata);
            await credential.Client.Client.GetAsync(TestHelpers.ExampleUri);

            Assert.True(handlerInvoked);
        }
    }
}
