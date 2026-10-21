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

using Microsoft.Playwright;
using Okta.AuthFoundation;
using Okta.AuthFoundation.Claims;
using Okta.AuthFoundation.TokenManagement;
using Okta.OAuth2;
using Okta.OAuth2.Flows;
using Xunit;

namespace Okta.Client.Sdk.E2ETests;

[Trait("Category", "E2E")]
public class WebRedirectSignInTests : E2ETestBase
{
    [E2EFact]
    public async Task SignIn_AuthorizationCodeFlow_ReturnsValidTokens()
    {
        var flow = new AuthorizationCodeFlow(Client, RedirectUri);
        var authorizeUrl = await flow.StartAsync();

        var callbackUri = await CaptureCallbackAsync(authorizeUrl);

        var response = await flow.ResumeAsync(callbackUri);

        Assert.True(response.IsSuccess);
        Assert.NotNull(response.Result);
        Assert.False(string.IsNullOrEmpty(response.Result.AccessToken));
        Assert.NotNull(response.Result.IdToken);
        Assert.False(string.IsNullOrEmpty(response.Result.RefreshToken));
        Assert.Contains("openid", response.Result.Scope!);
    }

    [E2EFact]
    public async Task SignIn_IdTokenContainsExpectedClaims()
    {
        var token = await PerformSignInAsync();

        Assert.NotNull(token.IdToken);
        Assert.NotNull(token.IdToken.Subject());
        var email = token.IdToken.Email();
        Assert.NotNull(email);
        Assert.Equal(TestUsername, email);
    }

    [E2EFact]
    public async Task TokenRefresh_AfterSignIn_ReturnsNewAccessToken()
    {
        var token = await PerformSignInAsync();
        var credential = await Credential.StoreAsync(token);
        var originalAccessToken = credential.Token.AccessToken;

        await credential.RefreshAsync();

        Assert.NotEqual(originalAccessToken, credential.Token.AccessToken);
        Assert.False(string.IsNullOrEmpty(credential.Token.AccessToken));
    }

    [E2EFact]
    public async Task TokenIntrospect_AfterSignIn_ShowsActive()
    {
        var token = await PerformSignInAsync();
        var credential = await Credential.StoreAsync(token);

        var introspection = await credential.IntrospectAsync();

        Assert.True(introspection.Active);
        Assert.False(string.IsNullOrEmpty(introspection.Sub));
    }

    [E2EFact]
    public async Task TokenRevoke_AfterSignIn_IntrospectionShowsInactive()
    {
        var token = await PerformSignInAsync();
        var credential = await Credential.StoreAsync(token);

        await credential.RevokeAsync(TokenRevokeType.Access);

        var introspection = await credential.IntrospectAsync();
        Assert.False(introspection.Active);
    }

    [E2EFact]
    public async Task UserInfo_AfterSignIn_ReturnsUserDetails()
    {
        var token = await PerformSignInAsync();
        var credential = await Credential.StoreAsync(token);

        var userInfo = await credential.UserInfoAsync();

        Assert.False(string.IsNullOrEmpty(userInfo.Subject()));
        Assert.Equal(TestUsername, userInfo.Email());
    }

    [E2EFact]
    public async Task SessionLogout_AfterSignIn_CompletesSuccessfully()
    {
        var token = await PerformSignInAsync();
        Assert.NotNull(token.IdToken);

        var logoutFlow = new SessionLogoutFlow(Client, new Uri(RedirectUri));
        var state = Crypto.GenerateRandomString();
        var context = new SessionLogoutFlowContext(token.IdToken.EncodedToken, state);

        var logoutUrl = await logoutFlow.StartAsync(context);
        Assert.NotNull(logoutUrl);

        // Navigate to the logout URL. Okta either redirects back to post_logout_redirect_uri
        // (if registered in the app) or shows its own signed-out page.
        await Page.GotoAsync(logoutUrl.ToString(), new()
        {
            Timeout = 30_000,
            WaitUntil = WaitUntilState.DOMContentLoaded,
        });

        // Verify the browser landed on either our callback URI or Okta's domain.
        var currentUrl = Page.Url;
        Assert.True(
            currentUrl.StartsWith(RedirectUri, StringComparison.OrdinalIgnoreCase) ||
            currentUrl.Contains(Issuer.Host, StringComparison.OrdinalIgnoreCase),
            $"Unexpected URL after logout: {currentUrl}");
    }

    private async Task<Token> PerformSignInAsync()
    {
        var flow = new AuthorizationCodeFlow(Client, RedirectUri);
        var authorizeUrl = await flow.StartAsync();

        var callbackUri = await CaptureCallbackAsync(authorizeUrl);
        var response = await flow.ResumeAsync(callbackUri);

        Assert.True(response.IsSuccess, $"Sign-in failed: {response.ErrorMessage}");
        return response.Result!;
    }
}
