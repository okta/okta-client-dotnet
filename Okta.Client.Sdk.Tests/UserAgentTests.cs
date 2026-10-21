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

using Okta.AuthFoundation.Http;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    [Collection("UserAgent")]
    public class UserAgentTests : IDisposable
    {
        private readonly List<string> _savedState;

        public UserAgentTests()
        {
            _savedState = UserAgent.Snapshot();
            UserAgent.Restore([]);
        }

        public void Dispose()
        {
            UserAgent.Restore(_savedState);
            GC.SuppressFinalize(this);
        }

        [Fact]
        public void HeaderValue_WithNoRegistrations_ReturnsFallback()
        {
            var header = UserAgent.HeaderValue;

            Assert.StartsWith("okta-client-dotnet/0.1.0 ", header);
        }

        [Fact]
        public void HeaderValue_IncludesRegisteredComponent_RuntimeAndPlatform()
        {
            UserAgent.Register("okta-authfoundation-dotnet", "0.1.0");

            var header = UserAgent.HeaderValue;

            Assert.StartsWith("okta-authfoundation-dotnet/0.1.0 ", header);
            Assert.DoesNotContain("okta-client-dotnet", header);
            Assert.Contains($"dotnet/{Environment.Version}", header);
            Assert.True(
                header.Contains("Windows/") ||
                header.Contains("macOS/") ||
                header.Contains("Linux/") ||
                header.Contains("Unknown/"),
                $"Header should contain a platform token, got: {header}");
        }

        [Fact]
        public void HeaderValue_WithMultipleRegistrations_IncludesAllInOrder_AndInvalidatesCache()
        {
            UserAgent.Register("okta-authfoundation-dotnet", "0.1.0");
            var headerBefore = UserAgent.HeaderValue;

            UserAgent.Register("okta-oauth2-dotnet", "0.2.0");
            var headerAfter = UserAgent.HeaderValue;

            Assert.DoesNotContain("okta-oauth2-dotnet", headerBefore);
            var foundationIndex = headerAfter.IndexOf("okta-authfoundation-dotnet/0.1.0", StringComparison.Ordinal);
            var oauth2Index = headerAfter.IndexOf("okta-oauth2-dotnet/0.2.0", StringComparison.Ordinal);
            Assert.True(foundationIndex >= 0 && oauth2Index >= 0, "Both components should be present");
            Assert.True(foundationIndex < oauth2Index, "Components should appear in registration order");
        }

        [Fact]
        public void Register_DeduplicatesByAgentName()
        {
            UserAgent.Register("okta-authfoundation-dotnet", "0.1.0");
            UserAgent.Register("okta-authfoundation-dotnet", "0.1.0");

            var header = UserAgent.HeaderValue;
            var firstIndex = header.IndexOf("okta-authfoundation-dotnet/", StringComparison.Ordinal);
            var secondIndex = header.IndexOf("okta-authfoundation-dotnet/", firstIndex + 1, StringComparison.Ordinal);
            Assert.True(firstIndex >= 0 && secondIndex < 0, "Component should appear exactly once");

            UserAgent.Register("okta-authfoundation-dotnet", "0.2.0");
            header = UserAgent.HeaderValue;
            Assert.Contains("okta-authfoundation-dotnet/0.2.0", header);
            Assert.DoesNotContain("okta-authfoundation-dotnet/0.1.0", header);
        }

        [Fact]
        public void Restore_ClearsAllComponents()
        {
            UserAgent.Register("okta-authfoundation-dotnet", "0.1.0");
            var headerBefore = UserAgent.HeaderValue;

            UserAgent.Restore([]);
            var headerAfter = UserAgent.HeaderValue;

            Assert.Contains("okta-authfoundation-dotnet", headerBefore);
            Assert.StartsWith("okta-client-dotnet/0.1.0 ", headerAfter);
        }

        [Theory]
        [InlineData(null, "1.0.0")]
        [InlineData("my-agent", "")]
        [InlineData("agent\r\nEvil: header", "1.0.0")]
        [InlineData("my-agent", "1.0 0")]
        public void Register_RejectsInvalidInput(string? agentName, string? version)
        {
            Assert.ThrowsAny<ArgumentException>(() => UserAgent.Register(agentName!, version!));
        }
    }

    // prevent parallel execution since tests modify global UserAgent state
    [CollectionDefinition("UserAgent", DisableParallelization = true)]
    public class UserAgentTestGroup
    {
    }
}
