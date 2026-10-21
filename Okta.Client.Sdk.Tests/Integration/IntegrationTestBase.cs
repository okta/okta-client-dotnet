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
using Okta.AuthFoundation.Http;
using Okta.AuthFoundation.OAuth2;
using Okta.AuthFoundation.TokenManagement;
using Okta.OAuth2.Flows;

namespace Okta.Client.Sdk.Tests.Integration
{
    /// <summary>
    /// Base class for integration tests that hit a live Okta preview server.
    /// Reads config/okta-native.json for OAuth2 settings and config/test-credentials.json for test user credentials.
    /// </summary>
    public abstract class IntegrationTestBase : IDisposable
    {
        protected IConfiguration Configuration { get; }

        protected Uri Issuer { get; }

        protected string ClientId { get; }

        protected List<string> Scopes { get; }

        protected string TestUsername { get; }

        protected string TestPassword { get; }

        protected OAuth2ClientConfiguration ClientConfig { get; }

        protected OAuth2Client Client { get; }

        private readonly string _tempStorageDir;

        protected IntegrationTestBase()
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

            Configuration = builder.Build();

            Issuer = new Uri(Configuration["IssuerUrl"]!);
            ClientId = Configuration["ClientId"]!;
            Scopes = Configuration.GetSection("Scopes").Get<List<string>>()
                     ?? new List<string> { "openid", "profile", "offline_access" };

            var testUserSection = Configuration.GetSection("TestUser");
            TestUsername = testUserSection["Username"]!;
            TestPassword = testUserSection["Password"]!;

            ClientConfig = new OAuth2ClientConfiguration(Issuer, ClientId, Scopes);
            Client = new OAuth2Client(ClientConfig);

            _tempStorageDir = Path.Combine(Path.GetTempPath(), "okta-sdk-tests-" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempStorageDir);
        }

        protected string TempStoragePath => Path.Combine(_tempStorageDir, "tokens.encrypted.json");

        protected ITokenStorage CreateTempStorage()
        {
            if (OperatingSystem.IsWindows())
            {
                return new WindowsEncryptedTokenStorage(TempStoragePath);
            }

            if (OperatingSystem.IsLinux())
            {
                return new LinuxFileKeyTokenStorage(TempStoragePath, Path.Combine(_tempStorageDir, "encryption.key"));
            }

            throw new PlatformNotSupportedException("Integration tests require Windows or Linux.");
        }

        /// <summary>
        /// Obtains a real token from the live Okta server using ResourceOwnerFlow.
        /// </summary>
        protected async Task<Token> ObtainTokenAsync()
        {
            var flow = new ResourceOwnerFlow(Client);
            var response = await flow.StartAsync(TestUsername, TestPassword);

            if (!response.IsSuccess || response.Result == null)
            {
                throw new InvalidOperationException(
                    $"Failed to obtain token via ResourceOwnerFlow: {response.ErrorMessage}");
            }

            return response.Result;
        }

        /// <summary>
        /// Walks up from the test output directory to find config/okta-native.json.
        /// Returns null if not found.
        /// </summary>
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

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_tempStorageDir))
                {
                    Directory.Delete(_tempStorageDir, recursive: true);
                }
            }
            catch
            {
            }

            GC.SuppressFinalize(this);
        }
    }
}
