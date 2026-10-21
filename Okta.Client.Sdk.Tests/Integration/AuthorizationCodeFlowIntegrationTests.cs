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

using Okta.AuthFoundation.Exceptions;
using Okta.AuthFoundation.OAuth2;
using Okta.OAuth2.Flows;
using Xunit;

namespace Okta.Client.Sdk.Tests.Integration
{
    [Trait("Category", "Integration")]
    public class AuthorizationCodeFlowIntegrationTests : IntegrationTestBase
    {
        private const string RedirectUri = "http://localhost:18080/callback";

        [IntegrationFact]
        public async Task StartAsync_GeneratesValidAuthorizeUrl()
        {
            var flow = new AuthorizationCodeFlow(Client, RedirectUri);

            var url = await flow.StartAsync();

            Assert.NotNull(url);
            var query = System.Web.HttpUtility.ParseQueryString(url.Query);
            Assert.Equal(ClientId, query["client_id"]);
            Assert.Equal("code", query["response_type"]);
            Assert.Equal(RedirectUri, query["redirect_uri"]);
            Assert.NotNull(query["state"]);
            Assert.NotNull(query["nonce"]);
            Assert.NotNull(query["scope"]);
        }

        [IntegrationFact]
        public async Task StartAsync_PkceParametersPresent()
        {
            var flow = new AuthorizationCodeFlow(Client, RedirectUri);

            var url = await flow.StartAsync();

            var query = System.Web.HttpUtility.ParseQueryString(url.Query);
            Assert.NotNull(query["code_challenge"]);
            Assert.Equal("S256", query["code_challenge_method"]);
        }

        [IntegrationFact]
        public async Task ResumeAsync_InvalidState_Throws()
        {
            var flow = new AuthorizationCodeFlow(Client, RedirectUri);
            await flow.StartAsync();

            var fakeCallback = $"{RedirectUri}?code=fakecode&state=wrong-state";

            await Assert.ThrowsAsync<OAuth2Exception>(() => flow.ResumeAsync(fakeCallback));
        }

        [IntegrationFact]
        public async Task ResumeAsync_ErrorCallback_Throws()
        {
            var flow = new AuthorizationCodeFlow(Client, RedirectUri);
            await flow.StartAsync();

            var errorCallback = $"{RedirectUri}?error=access_denied&error_description=User+denied+access";

            var ex = await Assert.ThrowsAsync<OAuth2Exception>(() => flow.ResumeAsync(errorCallback));
            Assert.Contains("access_denied", ex.Message);
        }

        [IntegrationFact]
        public async Task ResumeAsync_MissingCode_Throws()
        {
            var flow = new AuthorizationCodeFlow(Client, RedirectUri);
            await flow.StartAsync();

            var incompleteCallback = $"{RedirectUri}?state=some-state";

            await Assert.ThrowsAsync<OAuth2Exception>(() => flow.ResumeAsync(incompleteCallback));
        }
    }
}
