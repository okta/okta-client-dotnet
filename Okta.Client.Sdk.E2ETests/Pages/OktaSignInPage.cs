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

namespace Okta.Client.Sdk.E2ETests.Pages;

public class OktaSignInPage
{
    private readonly IPage _page;

    private ILocator UsernameInput => _page.Locator("input[name='identifier']");

    private ILocator PasswordInput => _page.Locator(
        "input[name='credentials.passcode'], input[name='passcode'], input[type='password']");

    private ILocator SubmitButton => _page.Locator("input[type='submit'], button[type='submit']");

    private ILocator SelectPasswordAuthenticator => _page.Locator("a[aria-label='Select Password.']");

    public OktaSignInPage(IPage page)
    {
        _page = page;
    }

    public async Task SignInAsync(string username, string password)
    {
        // Step 1: Enter username (identifier-first)
        await UsernameInput.WaitForAsync(new() { Timeout = 30_000 });
        await UsernameInput.FillAsync(username);
        await SubmitButton.First.ClickAsync();

        // Step 2: If authenticator selection appears, choose password
        try
        {
            await SelectPasswordAuthenticator.WaitForAsync(new() { Timeout = 5_000 });
            await SelectPasswordAuthenticator.ClickAsync();
        }
        catch (TimeoutException)
        {
            // No authenticator selection - password field should appear directly
        }

        // Step 3: Enter password
        await PasswordInput.First.WaitForAsync(new() { Timeout = 10_000 });
        await PasswordInput.First.FillAsync(password);
        await SubmitButton.First.ClickAsync();
    }
}
