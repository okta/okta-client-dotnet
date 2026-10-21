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
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Playwright;
using Okta.AuthFoundation.OAuth2;
using Okta.Client.Sdk.E2ETests.Pages;
using Xunit;

namespace Okta.Client.Sdk.E2ETests;

public abstract class E2ETestBase : IAsyncLifetime
{
    private static readonly string[] BrowserArgs = new[] { "--no-sandbox", "--disable-dev-shm-usage" };

    protected IConfiguration Configuration { get; private set; } = null!;

    protected Uri Issuer { get; private set; } = null!;

    protected string ClientId { get; private set; } = null!;

    protected string RedirectUri { get; private set; } = null!;

    protected List<string> Scopes { get; private set; } = null!;

    protected string TestUsername { get; private set; } = null!;

    protected string TestPassword { get; private set; } = null!;

    protected OAuth2ClientConfiguration ClientConfig { get; private set; } = null!;

    protected OAuth2Client Client { get; private set; } = null!;

    private IPlaywright _playwright = null!;
    private IBrowser _browser = null!;

    protected IBrowserContext BrowserContext { get; private set; } = null!;

    protected IPage Page { get; private set; } = null!;

    protected OktaSignInPage SignInPage { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        LoadConfiguration();

        _playwright = await Playwright.CreateAsync();

        var headless = !string.Equals(
            Environment.GetEnvironmentVariable("HEADED"), "true", StringComparison.OrdinalIgnoreCase);

        // Use BROWSER_CHANNEL env var to override (e.g., "chrome", "msedge", or empty for bundled Chromium)
        var channel = Environment.GetEnvironmentVariable("BROWSER_CHANNEL") ?? "msedge";

        _browser = await _playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
        {
            Headless = headless,
            Channel = string.IsNullOrEmpty(channel) ? null : channel,
            Args = BrowserArgs,
        });

        BrowserContext = await _browser.NewContextAsync();
        Page = await BrowserContext.NewPageAsync();
        SignInPage = new OktaSignInPage(Page);
    }

    public async Task DisposeAsync()
    {
        if (BrowserContext != null)
        {
            await BrowserContext.DisposeAsync();
        }

        if (_browser != null)
        {
            await _browser.DisposeAsync();
        }

        _playwright?.Dispose();
    }

    private void LoadConfiguration()
    {
        var configPath = FindConfigPathOrDefault()
            ?? throw new InvalidOperationException("config/okta-native.json not found.");
        var configDir = Path.GetDirectoryName(configPath)!;
        var credentialsPath = Path.Combine(configDir, "test-credentials.json");

        var builder = new ConfigurationBuilder()
            .AddJsonFile(configPath, optional: false);

        if (File.Exists(credentialsPath))
        {
            builder.AddJsonFile(credentialsPath, optional: true);
        }

        // Allow env vars to override config file values
        var envUsername = Environment.GetEnvironmentVariable("E2E_USERNAME");
        var envPassword = Environment.GetEnvironmentVariable("E2E_PASSWORD");

        Configuration = builder.Build();

        Issuer = new Uri(Configuration["IssuerUrl"]!);
        ClientId = Configuration["ClientId"]!;
        RedirectUri = Configuration["RedirectUri"] ?? "http://localhost:18080/callback";
        Scopes = Configuration.GetSection("Scopes").Get<List<string>>()
                 ?? new List<string> { "openid", "profile", "email", "offline_access" };

        var testUserSection = Configuration.GetSection("TestUser");
        TestUsername = envUsername ?? testUserSection["Username"]!;
        TestPassword = envPassword ?? testUserSection["Password"]!;

        ClientConfig = new OAuth2ClientConfiguration(Issuer, ClientId, Scopes);
        Client = new OAuth2Client(ClientConfig);
    }

    protected async Task<string> CaptureCallbackAsync(Uri authorizeUrl, CancellationToken cancellationToken = default)
    {
        var redirectUriParsed = new Uri(RedirectUri);
        var listenerPrefix = $"{redirectUriParsed.Scheme}://{redirectUriParsed.Host}:{redirectUriParsed.Port}/";

        using var listener = new HttpListener();
        listener.Prefixes.Add(listenerPrefix);
        listener.Start();

        try
        {
            await Page.GotoAsync(authorizeUrl.ToString(), new() { Timeout = 30_000 });
            await Page.WaitForLoadStateAsync(LoadState.DOMContentLoaded);
            await SignInPage.SignInAsync(TestUsername, TestPassword);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(60));

            var context = await listener.GetContextAsync().WaitAsync(cts.Token);
            var callbackUri = context.Request.Url?.ToString()
                ?? throw new InvalidOperationException("No callback URL received.");

            await SendResponseAsync(context, "Test Complete", "You can close this window.");
            return callbackUri;
        }
        finally
        {
            listener.Stop();
        }
    }

    protected async Task<string> CaptureLogoutCallbackAsync(Uri logoutUrl, CancellationToken cancellationToken = default)
    {
        var redirectUriParsed = new Uri(RedirectUri);
        var listenerPrefix = $"{redirectUriParsed.Scheme}://{redirectUriParsed.Host}:{redirectUriParsed.Port}/";

        using var listener = new HttpListener();
        listener.Prefixes.Add(listenerPrefix);
        listener.Start();

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(30));

            // GotoAsync navigates to Okta which redirects the browser to our listener.
            // Don't await yet: the browser is blocked waiting for our response, so
            // GotoAsync can't complete until we serve the request via GetContextAsync.
            var gotoTask = Page.GotoAsync(logoutUrl.ToString(), new() { Timeout = 30_000 });

            var context = await listener.GetContextAsync().WaitAsync(cts.Token);
            var callbackUri = context.Request.Url?.ToString()
                ?? throw new InvalidOperationException("No logout callback URL received.");

            await SendResponseAsync(context, "Logout Complete", "You can close this window.");

            try
            {
                await gotoTask;
            }
            catch (Exception)
            {
            }

            return callbackUri;
        }
        finally
        {
            listener.Stop();
        }
    }

    private static async Task SendResponseAsync(HttpListenerContext context, string title, string message)
    {
        var html = $"<html><body><h1>{title}</h1><p>{message}</p></body></html>";
        var buffer = Encoding.UTF8.GetBytes(html);
        context.Response.ContentType = "text/html";
        context.Response.ContentLength64 = buffer.Length;
        await context.Response.OutputStream.WriteAsync(buffer);
        context.Response.Close();
    }

    public static string? FindConfigPathOrDefault()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var configPath = Path.Combine(dir.FullName, "config", "okta-native.json");
            if (File.Exists(configPath))
            {
                return configPath;
            }

            dir = dir.Parent;
        }

        return null;
    }
}
