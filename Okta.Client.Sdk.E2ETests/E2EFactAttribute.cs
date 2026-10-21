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

namespace Okta.Client.Sdk.E2ETests;

public sealed class E2EFactAttribute : FactAttribute
{
    public E2EFactAttribute()
    {
        var configPath = E2ETestBase.FindConfigPathOrDefault();
        if (configPath == null)
        {
            Skip = "E2E tests require config/okta-native.json.";
            return;
        }

        var configDir = Path.GetDirectoryName(configPath)!;
        var credentialsPath = Path.Combine(configDir, "test-credentials.json");
        var hasCredentialsFile = File.Exists(credentialsPath);
        var hasEnvVars = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("E2E_USERNAME"))
                      && !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("E2E_PASSWORD"));

        if (!hasCredentialsFile && !hasEnvVars)
        {
            Skip = "E2E tests require config/test-credentials.json or E2E_USERNAME/E2E_PASSWORD.";
            return;
        }

        var builder = new ConfigurationBuilder().AddJsonFile(configPath, optional: false);
        if (hasCredentialsFile)
        {
            builder.AddJsonFile(credentialsPath, optional: false);
        }

        var config = builder.Build();

        if (string.IsNullOrEmpty(config["ClientId"]))
        {
            Skip = "E2E tests require ClientId in config/okta-native.json.";
            return;
        }

        var username = Environment.GetEnvironmentVariable("E2E_USERNAME") ?? config.GetSection("TestUser")["Username"];
        var password = Environment.GetEnvironmentVariable("E2E_PASSWORD") ?? config.GetSection("TestUser")["Password"];
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            Skip = "E2E tests require TestUser credentials in config/test-credentials.json or E2E_USERNAME/E2E_PASSWORD.";
        }
    }
}
