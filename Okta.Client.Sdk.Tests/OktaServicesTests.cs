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

using NSubstitute;
using Okta.AuthFoundation;
using Okta.AuthFoundation.JwtSecurity;
using Okta.AuthFoundation.TokenManagement;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    public class OktaServicesTests : IDisposable
    {
        public OktaServicesTests()
        {
            OktaServices.Reset();
        }

        public void Dispose()
        {
            OktaServices.Reset();
            GC.SuppressFinalize(this);
        }

        [Fact]
        public void Resolve_ITimeCoordinator_ReturnsDefaultTimeCoordinator()
        {
            var service = OktaServices.Resolve<ITimeCoordinator>();
            Assert.IsType<DefaultTimeCoordinator>(service);
        }

        [WindowsFact]
        public void Resolve_ITokenStorage_ReturnsWindowsEncryptedTokenStorage()
        {
            var service = OktaServices.Resolve<ITokenStorage>();
            Assert.IsType<WindowsEncryptedTokenStorage>(service);
        }

        [LinuxFact]
        public void Resolve_ITokenStorage_ReturnsLinuxStorage()
        {
            var service = OktaServices.Resolve<ITokenStorage>();
            Assert.True(service is LinuxKeyringTokenStorage or LinuxFileKeyTokenStorage);
        }

        [Fact]
        public void Resolve_ICredentialDataSource_ReturnsDefaultCredentialDataSource()
        {
            var service = OktaServices.Resolve<ICredentialDataSource>();
            Assert.IsType<DefaultCredentialDataSource>(service);
        }

        [Fact]
        public void Resolve_ICredentialCoordinator_ReturnsCredentialCoordinator()
        {
            var service = OktaServices.Resolve<ICredentialCoordinator>();
            Assert.IsType<CredentialCoordinator>(service);
        }

        [Fact]
        public void Resolve_IIdTokenValidator_ReturnsDefaultIdTokenValidator()
        {
            var service = OktaServices.Resolve<IIdTokenValidator>();
            Assert.IsType<DefaultIdTokenValidator>(service);
        }

        [Fact]
        public void Resolve_IJwkValidator_ReturnsDefaultJwkValidator()
        {
            var service = OktaServices.Resolve<IJwkValidator>();
            Assert.IsType<DefaultJwkValidator>(service);
        }

        [Fact]
        public void Resolve_ITokenHashValidator_ReturnsDefaultTokenHashValidator()
        {
            var service = OktaServices.Resolve<ITokenHashValidator>();
            Assert.IsType<DefaultTokenHashValidator>(service);
        }

        [Fact]
        public void AddSingleton_Instance_OverridesDefault()
        {
            var custom = Substitute.For<ITokenStorage>();

            OktaServices.AddSingleton(custom);

            var resolved = OktaServices.Resolve<ITokenStorage>();
            Assert.Same(custom, resolved);
        }

        [Fact]
        public void AddSingleton_Factory_OverridesDefault()
        {
            var custom = Substitute.For<IIdTokenValidator>();

            OktaServices.AddSingleton<IIdTokenValidator>(() => custom);

            var resolved = OktaServices.Resolve<IIdTokenValidator>();
            Assert.Same(custom, resolved);
        }

        [Fact]
        public void Resolve_Singleton_ReturnsSameInstance()
        {
            var first = OktaServices.Resolve<ITimeCoordinator>();
            var second = OktaServices.Resolve<ITimeCoordinator>();

            Assert.Same(first, second);
        }

        [Fact]
        public void Resolve_Singleton_FactoryCalledOnlyOnce()
        {
            int callCount = 0;
            var custom = Substitute.For<IJwkValidator>();

            OktaServices.AddSingleton<IJwkValidator>(() =>
            {
                callCount++;
                return custom;
            });

            OktaServices.Resolve<IJwkValidator>();
            OktaServices.Resolve<IJwkValidator>();
            OktaServices.Resolve<IJwkValidator>();

            Assert.Equal(1, callCount);
        }

        [WindowsFact]
        public void Reset_RestoresDefaults_AfterCustomRegistration()
        {
            var custom = Substitute.For<ITokenStorage>();
            OktaServices.AddSingleton(custom);

            Assert.Same(custom, OktaServices.Resolve<ITokenStorage>());

            OktaServices.Reset();

            var resolved = OktaServices.Resolve<ITokenStorage>();
            Assert.IsType<WindowsEncryptedTokenStorage>(resolved);
            Assert.NotSame(custom, resolved);
        }

        [Fact]
        public void Resolve_UnregisteredType_ThrowsInvalidOperationException()
        {
            Assert.Throws<InvalidOperationException>(() =>
                OktaServices.Resolve<IDisposable>());
        }

        // HttpClient / IHttpClientFactory tests
        [Fact]
        public void Resolve_IHttpClientFactory_IsRegistered()
        {
            var factory = OktaServices.Resolve<IHttpClientFactory>();
            Assert.NotNull(factory);
        }

        [Fact]
        public void AddTransient_Factory_ReturnsNewInstanceEachTime()
        {
            int callCount = 0;

            OktaServices.AddTransient<HttpClient>(() =>
            {
                callCount++;
                return new HttpClient();
            });

            OktaServices.Resolve<HttpClient>();
            OktaServices.Resolve<HttpClient>();
            OktaServices.Resolve<HttpClient>();

            Assert.Equal(3, callCount);
        }

        [Fact]
        public async Task ConfigureHttpMessageHandler_UsedByFactory()
        {
            bool handlerInvoked = false;
            OktaServices.ConfigureHttpMessageHandler(() => new TestHttpMessageHandler((req, ct) =>
            {
                handlerInvoked = true;
                return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
            }));

            var client = OktaServices.Resolve<IHttpClientFactory>().CreateClient(OktaServices.HttpClientName);
            await client.GetAsync("https://example.com");

            Assert.True(handlerInvoked);
        }

        [Fact]
        public void AddTransient_OverridesSingleton()
        {
            OktaServices.AddTransient<ITimeCoordinator>(() => new DefaultTimeCoordinator());

            var first = OktaServices.Resolve<ITimeCoordinator>();
            var second = OktaServices.Resolve<ITimeCoordinator>();

            Assert.NotSame(first, second);
        }
    }
}
