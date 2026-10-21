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

using Microsoft.Extensions.Configuration;
using Okta.AuthFoundation.Exceptions;
using Okta.AuthFoundation.OAuth2;
using Okta.OAuth2.Flows;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    [CollectionDefinition("CurrentDirectory", DisableParallelization = true)]
    public class CurrentDirectoryGroup
    {
    }

    [Collection("CurrentDirectory")]
    public class OktaConfigurationTests : IDisposable
    {
        private readonly string _tempDir;

        public OktaConfigurationTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(_tempDir);
        }

        public void Dispose()
        {
            Directory.Delete(_tempDir, recursive: true);
            GC.SuppressFinalize(this);
        }

        private string WriteConfig(string json)
        {
            var path = Path.Combine(_tempDir, "test-config.json");
            File.WriteAllText(path, json);
            return path;
        }

        // ── Load: valid files ─────────────────────────────────────────────────
        [Fact]
        public void Load_PascalCase_SetsAllProperties()
        {
            var path = WriteConfig("""
                {
                  "IssuerUrl": "https://example.okta.com/oauth2/default",
                  "ClientId": "client123",
                  "Scopes": ["openid", "profile"],
                  "RedirectUri": "http://localhost:8080/callback",
                  "LogoutRedirectUri": "http://localhost:8080/",
                  "Audience": "api://default"
                }
                """);

            var config = OktaConfiguration.Load(path);

            Assert.Equal(new Uri("https://example.okta.com/oauth2/default"), config.IssuerUrl);
            Assert.Equal("client123", config.ClientId);
            Assert.Equal(["openid", "profile"], config.Scope);
            Assert.Equal(new Uri("http://localhost:8080/callback"), config.RedirectUri);
            Assert.Equal(new Uri("http://localhost:8080/"), config.LogoutRedirectUri);
            Assert.Equal("api://default", config.Audience);
            Assert.Null(config.Authentication);
            Assert.Null(config.AdditionalParameters);
        }

        [Fact]
        public void Load_SnakeCaseAliases_ResolvesCorrectly()
        {
            var path = WriteConfig("""
                {
                  "issuer_url": "https://example.okta.com/oauth2/default",
                  "client_id": "client123",
                  "scope": "openid profile",
                  "redirect_uri": "http://localhost:8080/callback",
                  "logout_redirect_uri": "http://localhost:8080/"
                }
                """);

            var config = OktaConfiguration.Load(path);

            Assert.Equal(new Uri("https://example.okta.com/oauth2/default"), config.IssuerUrl);
            Assert.Equal("client123", config.ClientId);
            Assert.Equal(["openid", "profile"], config.Scope);
            Assert.Equal(new Uri("http://localhost:8080/callback"), config.RedirectUri);
            Assert.Equal(new Uri("http://localhost:8080/"), config.LogoutRedirectUri);
        }

        [Fact]
        public void Load_IssuerAlias_ResolvesCorrectly()
        {
            var path = WriteConfig("""
                {
                  "issuer": "https://example.okta.com/oauth2/default",
                  "client_id": "client123",
                  "scope": "openid"
                }
                """);

            var config = OktaConfiguration.Load(path);

            Assert.Equal(new Uri("https://example.okta.com/oauth2/default"), config.IssuerUrl);
        }

        [Fact]
        public void Load_SpaceSeparatedScope_ParsedToList()
        {
            var path = WriteConfig("""
                {
                  "IssuerUrl": "https://example.okta.com/oauth2/default",
                  "ClientId": "client123",
                  "Scopes": "openid profile email offline_access"
                }
                """);

            var config = OktaConfiguration.Load(path);

            Assert.Equal(["openid", "profile", "email", "offline_access"], config.Scope);
        }

        [Fact]
        public void Load_ClientSecret_SetsClientSecretAuthentication()
        {
            var path = WriteConfig("""
                {
                  "IssuerUrl": "https://example.okta.com/oauth2/default",
                  "ClientId": "client123",
                  "ClientSecret": "super-secret"
                }
                """);

            var config = OktaConfiguration.Load(path);

            Assert.NotNull(config.Authentication);
            Assert.Equal(ClientAuthentication.ClientSecret, config.Authentication.Method);
        }

        [Fact]
        public void Load_ClientSecretSnakeCase_SetsClientSecretAuthentication()
        {
            var path = WriteConfig("""
                {
                  "issuer": "https://example.okta.com/oauth2/default",
                  "client_id": "client123",
                  "client_secret": "super-secret"
                }
                """);

            var config = OktaConfiguration.Load(path);

            Assert.NotNull(config.Authentication);
            Assert.Equal(ClientAuthentication.ClientSecret, config.Authentication.Method);
        }

        [Fact]
        public void Load_UnknownStringKeys_CapturedAsAdditionalParameters()
        {
            var path = WriteConfig("""
                {
                  "IssuerUrl": "https://example.okta.com/oauth2/default",
                  "ClientId": "client123",
                  "custom_param": "custom_value",
                  "another_param": "another_value"
                }
                """);

            var config = OktaConfiguration.Load(path);

            Assert.NotNull(config.AdditionalParameters);
            Assert.Equal("custom_value", config.AdditionalParameters!["custom_param"]);
            Assert.Equal("another_value", config.AdditionalParameters["another_param"]);
        }

        [Fact]
        public void Load_NoScopes_ReturnsEmptyList()
        {
            var path = WriteConfig("""
                {
                  "IssuerUrl": "https://example.okta.com/oauth2/default",
                  "ClientId": "client123"
                }
                """);

            var config = OktaConfiguration.Load(path);

            Assert.Empty(config.Scope);
        }

        // ── Load: validation errors ───────────────────────────────────────────
        [Fact]
        public void Load_FileNotFound_ThrowsOktaConfigurationException()
        {
            Assert.Throws<OktaConfigurationException>(() =>
                OktaConfiguration.Load(Path.Combine(_tempDir, "nonexistent.json")));
        }

        [Fact]
        public void Load_InvalidJson_ThrowsOktaConfigurationException()
        {
            var path = WriteConfig("{ this is not json }");

            var ex = Assert.Throws<OktaConfigurationException>(() =>
                OktaConfiguration.Load(path));

            Assert.Contains("parse", ex.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void Load_MissingIssuerUrl_ThrowsOktaConfigurationException()
        {
            var path = WriteConfig("""{ "ClientId": "client123" }""");

            var ex = Assert.Throws<OktaConfigurationException>(() =>
                OktaConfiguration.Load(path));

            Assert.Contains("IssuerUrl", ex.Message);
        }

        [Fact]
        public void Load_MissingClientId_ThrowsOktaConfigurationException()
        {
            var path = WriteConfig("""{ "IssuerUrl": "https://example.okta.com/oauth2/default" }""");

            var ex = Assert.Throws<OktaConfigurationException>(() =>
                OktaConfiguration.Load(path));

            Assert.Contains("ClientId", ex.Message);
        }

        [Fact]
        public void Load_InvalidIssuerUrl_ThrowsOktaConfigurationException()
        {
            var path = WriteConfig("""
                {
                  "IssuerUrl": "not-a-url",
                  "ClientId": "client123"
                }
                """);

            var ex = Assert.Throws<OktaConfigurationException>(() =>
                OktaConfiguration.Load(path));

            Assert.Contains("IssuerUrl", ex.Message);
        }

        [Fact]
        public void Load_InvalidRedirectUri_ThrowsOktaConfigurationException()
        {
            var path = WriteConfig("""
                {
                  "IssuerUrl": "https://example.okta.com/oauth2/default",
                  "ClientId": "client123",
                  "RedirectUri": "not-a-url"
                }
                """);

            var ex = Assert.Throws<OktaConfigurationException>(() =>
                OktaConfiguration.Load(path));

            Assert.Contains("RedirectUri", ex.Message);
        }

        // ── LoadDefault ───────────────────────────────────────────────────────
        [Fact]
        public void LoadDefault_NoFile_ThrowsOktaConfigurationException()
        {
            var originalDir = Directory.GetCurrentDirectory();
            var isolatedDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(isolatedDir);
            try
            {
                Directory.SetCurrentDirectory(isolatedDir);
                Assert.Throws<OktaConfigurationException>(() => OktaConfiguration.LoadDefault());
            }
            finally
            {
                Directory.SetCurrentDirectory(originalDir);
                Directory.Delete(isolatedDir, recursive: true);
            }
        }

        [Fact]
        public void LoadDefault_FileInCurrentDirectory_LoadsSuccessfully()
        {
            var originalDir = Directory.GetCurrentDirectory();
            var isolatedDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(isolatedDir);
            var json = """
                {
                  "IssuerUrl": "https://example.okta.com/oauth2/default",
                  "ClientId": "default-client",
                  "Scopes": ["openid"]
                }
                """;
            File.WriteAllText(Path.Combine(isolatedDir, "Okta.json"), json);
            try
            {
                Directory.SetCurrentDirectory(isolatedDir);
                var config = OktaConfiguration.LoadDefault();
                Assert.Equal("default-client", config.ClientId);
            }
            finally
            {
                Directory.SetCurrentDirectory(originalDir);
                Directory.Delete(isolatedDir, recursive: true);
            }
        }

        // ── ToOAuth2ClientConfiguration ───────────────────────────────────────
        [Fact]
        public void ToOAuth2ClientConfiguration_MapsFieldsCorrectly()
        {
            var path = WriteConfig("""
                {
                  "IssuerUrl": "https://example.okta.com/oauth2/default",
                  "ClientId": "client123",
                  "Scopes": ["openid", "profile"]
                }
                """);

            var config = OktaConfiguration.Load(path);
            var oauth2Config = config.ToOAuth2ClientConfiguration();

            Assert.Equal(new Uri("https://example.okta.com/oauth2/default"), oauth2Config.BaseUrl);
            Assert.Equal("client123", oauth2Config.ClientId);
            Assert.Equal(["openid", "profile"], oauth2Config.Scope);
        }

        // ── Flow constructors ─────────────────────────────────────────────────
        [Fact]
        public void AuthorizationCodeFlow_FromConfig_SetsClientAndRedirectUri()
        {
            var path = WriteConfig("""
                {
                  "IssuerUrl": "https://example.okta.com/oauth2/default",
                  "ClientId": "client123",
                  "RedirectUri": "http://localhost:8080/callback"
                }
                """);

            var config = OktaConfiguration.Load(path);
            var flow = new AuthorizationCodeFlow(config);

            Assert.Equal("http://localhost:8080/callback", flow.RedirectUri);
            Assert.Equal("client123", flow.Client.Configuration.ClientId);
        }

        [Fact]
        public void AuthorizationCodeFlow_FromConfig_MissingRedirectUri_ThrowsOktaConfigurationException()
        {
            var path = WriteConfig("""
                {
                  "IssuerUrl": "https://example.okta.com/oauth2/default",
                  "ClientId": "client123"
                }
                """);

            var config = OktaConfiguration.Load(path);

            Assert.Throws<OktaConfigurationException>(() => new AuthorizationCodeFlow(config));
        }

        [Fact]
        public void ResourceOwnerFlow_FromConfig_SetsClient()
        {
            var path = WriteConfig("""
                {
                  "IssuerUrl": "https://example.okta.com/oauth2/default",
                  "ClientId": "client123"
                }
                """);

            var config = OktaConfiguration.Load(path);
            var flow = new ResourceOwnerFlow(config);

            Assert.Equal("client123", flow.Client.Configuration.ClientId);
        }

        [Fact]
        public void DeviceAuthorizationCodeFlow_FromConfig_SetsClient()
        {
            var path = WriteConfig("""
                {
                  "IssuerUrl": "https://example.okta.com/oauth2/default",
                  "ClientId": "client123"
                }
                """);

            var config = OktaConfiguration.Load(path);
            var flow = new DeviceAuthorizationCodeFlow(config);

            Assert.Equal("client123", flow.Client.Configuration.ClientId);
        }

        [Fact]
        public void TokenExchangeFlow_FromConfig_SetsClientAndAudience()
        {
            var path = WriteConfig("""
                {
                  "IssuerUrl": "https://example.okta.com/oauth2/default",
                  "ClientId": "client123",
                  "Audience": "api://default"
                }
                """);

            var config = OktaConfiguration.Load(path);
            var flow = new TokenExchangeFlow(config);

            Assert.Equal("client123", flow.Client.Configuration.ClientId);
            Assert.Equal("api://default", flow.Audience);
        }

        // ── Non-object JSON root ──────────────────────────────────────────────
        [Fact]
        public void Load_JsonArray_ThrowsOktaConfigurationException()
        {
            var path = WriteConfig("""["not", "an", "object"]""");

            var ex = Assert.Throws<OktaConfigurationException>(() =>
                OktaConfiguration.Load(path));

            Assert.Contains("parse", ex.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void Load_JsonScalar_ThrowsOktaConfigurationException()
        {
            var path = WriteConfig(""""hello"""");

            var ex = Assert.Throws<OktaConfigurationException>(() =>
                OktaConfiguration.Load(path));

            Assert.Contains("parse", ex.Message, StringComparison.OrdinalIgnoreCase);
        }

        // ── Parameterless flow constructors ──────────────────────────────────────
        private static void WithIsolatedOktaJson(string json, Action action)
        {
            var originalDir = Directory.GetCurrentDirectory();
            var isolatedDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(isolatedDir);
            try
            {
                File.WriteAllText(Path.Combine(isolatedDir, "Okta.json"), json);
                Directory.SetCurrentDirectory(isolatedDir);
                action();
            }
            finally
            {
                Directory.SetCurrentDirectory(originalDir);
                Directory.Delete(isolatedDir, recursive: true);
            }
        }

        private static void WithNoOktaJson(Action action)
        {
            var originalDir = Directory.GetCurrentDirectory();
            var isolatedDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(isolatedDir);
            try
            {
                Directory.SetCurrentDirectory(isolatedDir);
                action();
            }
            finally
            {
                Directory.SetCurrentDirectory(originalDir);
                Directory.Delete(isolatedDir, recursive: true);
            }
        }

        [Fact]
        public void AuthorizationCodeFlow_Parameterless_LoadsFromOktaJson()
        {
            WithIsolatedOktaJson(
                """
                {
                  "IssuerUrl": "https://example.okta.com/oauth2/default",
                  "ClientId": "client123",
                  "RedirectUri": "http://localhost:8080/callback"
                }
                """,
                () =>
                {
                    var flow = new AuthorizationCodeFlow();
                    Assert.Equal("http://localhost:8080/callback", flow.RedirectUri);
                    Assert.Equal("client123", flow.Client.Configuration.ClientId);
                });
        }

        [Fact]
        public void AuthorizationCodeFlow_Parameterless_NoFile_Throws()
        {
            WithNoOktaJson(() =>
                Assert.Throws<OktaConfigurationException>(() => new AuthorizationCodeFlow()));
        }

        [Fact]
        public void ResourceOwnerFlow_Parameterless_LoadsFromOktaJson()
        {
            WithIsolatedOktaJson(
                """
                {
                  "IssuerUrl": "https://example.okta.com/oauth2/default",
                  "ClientId": "client123"
                }
                """,
                () =>
                {
                    var flow = new ResourceOwnerFlow();
                    Assert.Equal("client123", flow.Client.Configuration.ClientId);
                });
        }

        [Fact]
        public void ResourceOwnerFlow_Parameterless_NoFile_Throws()
        {
            WithNoOktaJson(() =>
                Assert.Throws<OktaConfigurationException>(() => new ResourceOwnerFlow()));
        }

        [Fact]
        public void DeviceAuthorizationCodeFlow_Parameterless_LoadsFromOktaJson()
        {
            WithIsolatedOktaJson(
                """
                {
                  "IssuerUrl": "https://example.okta.com/oauth2/default",
                  "ClientId": "client123"
                }
                """,
                () =>
                {
                    var flow = new DeviceAuthorizationCodeFlow();
                    Assert.Equal("client123", flow.Client.Configuration.ClientId);
                });
        }

        [Fact]
        public void DeviceAuthorizationCodeFlow_Parameterless_NoFile_Throws()
        {
            WithNoOktaJson(() =>
                Assert.Throws<OktaConfigurationException>(() => new DeviceAuthorizationCodeFlow()));
        }

        [Fact]
        public void TokenExchangeFlow_Parameterless_LoadsFromOktaJson()
        {
            WithIsolatedOktaJson(
                """
                {
                  "IssuerUrl": "https://example.okta.com/oauth2/default",
                  "ClientId": "client123",
                  "Audience": "api://default"
                }
                """,
                () =>
                {
                    var flow = new TokenExchangeFlow();
                    Assert.Equal("client123", flow.Client.Configuration.ClientId);
                    Assert.Equal("api://default", flow.Audience);
                });
        }

        [Fact]
        public void TokenExchangeFlow_Parameterless_NoFile_Throws()
        {
            WithNoOktaJson(() =>
                Assert.Throws<OktaConfigurationException>(() => new TokenExchangeFlow()));
        }

        // ── FromConfiguration (IConfiguration binding) ────────────────────────
        [Fact]
        public void FromConfiguration_WithAllFields_SetsProperties()
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["IssuerUrl"] = "https://example.okta.com/oauth2/default",
                    ["ClientId"] = "client123",
                    ["Scopes:0"] = "openid",
                    ["Scopes:1"] = "profile",
                    ["RedirectUri"] = "http://localhost:8080/callback",
                    ["LogoutRedirectUri"] = "http://localhost:8080/",
                    ["Audience"] = "api://default",
                })
                .Build();

            var config = OktaConfiguration.FromConfiguration(configuration);

            Assert.Equal(new Uri("https://example.okta.com/oauth2/default"), config.IssuerUrl);
            Assert.Equal("client123", config.ClientId);
            Assert.Equal(["openid", "profile"], config.Scope);
            Assert.Equal(new Uri("http://localhost:8080/callback"), config.RedirectUri);
            Assert.Equal(new Uri("http://localhost:8080/"), config.LogoutRedirectUri);
            Assert.Equal("api://default", config.Audience);
        }

        [Fact]
        public void FromConfiguration_WithSnakeCaseKeys_ResolvesCorrectly()
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["issuer_url"] = "https://example.okta.com/oauth2/default",
                    ["client_id"] = "client123",
                    ["scope"] = "openid profile email",
                })
                .Build();

            var config = OktaConfiguration.FromConfiguration(configuration);

            Assert.Equal(new Uri("https://example.okta.com/oauth2/default"), config.IssuerUrl);
            Assert.Equal("client123", config.ClientId);
            Assert.Equal(["openid", "profile", "email"], config.Scope);
        }

        [Fact]
        public void FromConfiguration_WithClientSecret_SetsAuthentication()
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["IssuerUrl"] = "https://example.okta.com/oauth2/default",
                    ["ClientId"] = "client123",
                    ["ClientSecret"] = "secret",
                })
                .Build();

            var config = OktaConfiguration.FromConfiguration(configuration);

            Assert.NotNull(config.Authentication);
            Assert.Equal(ClientAuthentication.ClientSecret, config.Authentication.Method);
        }

        [Fact]
        public void FromConfiguration_WithUnknownKeys_CapturedAsAdditionalParameters()
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["IssuerUrl"] = "https://example.okta.com/oauth2/default",
                    ["ClientId"] = "client123",
                    ["custom_param"] = "custom_value",
                })
                .Build();

            var config = OktaConfiguration.FromConfiguration(configuration);

            Assert.NotNull(config.AdditionalParameters);
            Assert.Equal("custom_value", config.AdditionalParameters!["custom_param"]);
        }

        [Fact]
        public void FromConfiguration_MissingIssuerUrl_Throws()
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ClientId"] = "client123",
                })
                .Build();

            var ex = Assert.Throws<OktaConfigurationException>(() =>
                OktaConfiguration.FromConfiguration(configuration));

            Assert.Contains("IssuerUrl", ex.Message);
        }

        [Fact]
        public void FromConfiguration_FromJsonFile_WorksEndToEnd()
        {
            var path = WriteConfig("""
                {
                  "Okta": {
                    "IssuerUrl": "https://example.okta.com/oauth2/default",
                    "ClientId": "json-client",
                    "Scopes": ["openid", "profile"]
                  }
                }
                """);

            var configuration = new ConfigurationBuilder()
                .AddJsonFile(path)
                .Build();

            var config = OktaConfiguration.FromConfiguration(configuration.GetSection("Okta"));

            Assert.Equal("json-client", config.ClientId);
            Assert.Equal(["openid", "profile"], config.Scope);
        }
    }
}
