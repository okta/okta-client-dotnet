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

using Okta.AuthFoundation.OAuth2;
using Xunit;

namespace Okta.Client.Sdk.Tests;

public class ClientAuthenticationTests
{
    private const string ClientId = "test-client";

    private static HttpRequestMessage CreateRequest(Uri? uri = null)
        => new(HttpMethod.Post, uri ?? new Uri("https://example.okta.com/oauth2/v1/token"));

    // ── NoneClientAuthentication ─────────────────────────────────────────────
    [Fact]
    public void NoneClientAuthentication_Method_IsNone()
    {
        Assert.Equal(ClientAuthentication.None, new NoneClientAuthentication().Method);
    }

    [Fact]
    public void NoneClientAuthentication_AddsNoParameters()
    {
        var parameters = new Dictionary<string, string>();
        new NoneClientAuthentication().AddAuthentication(CreateRequest(), ClientId, parameters);
        Assert.Empty(parameters);
    }

    // ── ClientSecretAuthentication ───────────────────────────────────────────
    [Fact]
    public void ClientSecretAuthentication_Method_IsClientSecret()
    {
        Assert.Equal(ClientAuthentication.ClientSecret, new ClientSecretAuthentication("secret").Method);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ClientSecretAuthentication_InvalidSecret_Throws(string? secret)
    {
        Assert.ThrowsAny<ArgumentException>(() => new ClientSecretAuthentication(secret!));
    }

    [Fact]
    public void ClientSecretAuthentication_AddsOnlyClientSecret()
    {
        var parameters = new Dictionary<string, string>();
        new ClientSecretAuthentication("super-secret").AddAuthentication(CreateRequest(), ClientId, parameters);

        Assert.Equal("super-secret", parameters["client_secret"]);
        Assert.Single(parameters);
        Assert.DoesNotContain("client_id", parameters.Keys);
    }

    // ── PrivateKeyJwtAuthentication (factory) ────────────────────────────────
    [Fact]
    public void PrivateKeyJwtAuthentication_Method_IsPrivateKeyJwt()
    {
        Assert.Equal(ClientAuthentication.PrivateKeyJwt, new PrivateKeyJwtAuthentication(_ => "assertion").Method);
    }

    [Fact]
    public void PrivateKeyJwtAuthentication_NullFactory_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new PrivateKeyJwtAuthentication((Func<Uri, string>)null!));
    }

    [Fact]
    public void PrivateKeyJwtAuthentication_Factory_AddsAssertionParameters()
    {
        var parameters = new Dictionary<string, string>();
        new PrivateKeyJwtAuthentication(_ => "factory.built.assertion")
            .AddAuthentication(CreateRequest(), ClientId, parameters);

        Assert.Equal("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", parameters["client_assertion_type"]);
        Assert.Equal("factory.built.assertion", parameters["client_assertion"]);
        Assert.DoesNotContain("client_id", parameters.Keys);
    }

    [Fact]
    public void PrivateKeyJwtAuthentication_Factory_ReceivesRequestUri()
    {
        var tokenEndpoint = new Uri("https://example.okta.com/oauth2/v1/token");
        Uri? receivedAudience = null;
        new PrivateKeyJwtAuthentication(audience =>
        {
            receivedAudience = audience;
            return "assertion";
        })
            .AddAuthentication(CreateRequest(tokenEndpoint), ClientId, new Dictionary<string, string>());

        Assert.Equal(tokenEndpoint, receivedAudience);
    }

    [Fact]
    public void PrivateKeyJwtAuthentication_Factory_InvokedOnEachCall()
    {
        var callCount = 0;
        var auth = new PrivateKeyJwtAuthentication(_ => $"assertion-{++callCount}");

        var params1 = new Dictionary<string, string>();
        var params2 = new Dictionary<string, string>();
        auth.AddAuthentication(CreateRequest(), ClientId, params1);
        auth.AddAuthentication(CreateRequest(), ClientId, params2);

        Assert.Equal("assertion-1", params1["client_assertion"]);
        Assert.Equal("assertion-2", params2["client_assertion"]);
    }

    // ── PrivateKeyJwtAuthentication (pre-built) ──────────────────────────────
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void PrivateKeyJwtAuthentication_InvalidPreBuiltAssertion_Throws(string? assertion)
    {
        Assert.ThrowsAny<ArgumentException>(() => new PrivateKeyJwtAuthentication(assertion!));
    }

    [Fact]
    public void PrivateKeyJwtAuthentication_PreBuiltAssertion_UsedAsIs()
    {
        var parameters = new Dictionary<string, string>();
        new PrivateKeyJwtAuthentication("my.pre.built")
            .AddAuthentication(CreateRequest(), ClientId, parameters);

        Assert.Equal("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", parameters["client_assertion_type"]);
        Assert.Equal("my.pre.built", parameters["client_assertion"]);
        Assert.DoesNotContain("client_id", parameters.Keys);
    }

    // ── OAuth2ClientConfiguration ─────────────────────────────────────────────
    [Fact]
    public void OAuth2ClientConfiguration_DefaultAuthentication_IsNone()
    {
        var config = new OAuth2ClientConfiguration(
            new Uri("https://example.com"),
            new Uri("https://example.com/.well-known/openid-configuration"),
            "clientId");

        Assert.Equal(ClientAuthentication.None, config.Authentication.Method);
    }

    [Fact]
    public void OAuth2ClientConfiguration_CustomAuthentication_IsUsed()
    {
        var auth = new ClientSecretAuthentication("secret");
        var config = new OAuth2ClientConfiguration(
            new Uri("https://example.com"),
            new Uri("https://example.com/.well-known/openid-configuration"),
            "clientId",
            authentication: auth);

        Assert.Equal(ClientAuthentication.ClientSecret, config.Authentication.Method);
        Assert.Same(auth, config.Authentication);
    }
}
