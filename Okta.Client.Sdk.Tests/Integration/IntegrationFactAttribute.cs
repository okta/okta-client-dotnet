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
using Xunit;

namespace Okta.Client.Sdk.Tests.Integration
{
    /// <summary>
    /// A custom xUnit <see cref="FactAttribute"/> that skips the test when config/okta-native.json
    /// is not found or config/test-credentials.json is missing required credentials.
    /// </summary>
    public sealed class IntegrationFactAttribute : FactAttribute
    {
        public IntegrationFactAttribute()
        {
            var configPath = IntegrationTestBase.FindConfigPathOrDefault();
            if (configPath == null)
            {
                Skip = "Integration tests require config/okta-native.json.";
                return;
            }

            var configDir = Path.GetDirectoryName(configPath)!;
            var credentialsPath = Path.Combine(configDir, "test-credentials.json");
            if (!File.Exists(credentialsPath))
            {
                Skip = "Integration tests require config/test-credentials.json.";
                return;
            }

            var config = new ConfigurationBuilder()
                .AddJsonFile(configPath, optional: false)
                .AddJsonFile(credentialsPath, optional: false)
                .Build();

            if (string.IsNullOrEmpty(config["ClientId"]))
            {
                Skip = "Integration tests require ClientId in config/okta-native.json.";
                return;
            }

            var testUser = config.GetSection("TestUser");
            if (string.IsNullOrEmpty(testUser["Username"]) || string.IsNullOrEmpty(testUser["Password"]))
            {
                Skip = "Integration tests require TestUser credentials in config/test-credentials.json.";
            }
        }
    }
}
