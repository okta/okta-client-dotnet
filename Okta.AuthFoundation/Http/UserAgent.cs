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

using System.Runtime.InteropServices;

namespace Okta.AuthFoundation.Http
{
    /// <summary>
    /// Provides the SDK User-Agent string for outgoing HTTP requests.
    /// Sub-packages register themselves via <see cref="Register"/> at startup.
    /// Example: okta-authfoundation-dotnet/0.1.0 okta-oauth2-dotnet/1.0.0 dotnet/8.0.0 macOS/14.2.1
    /// </summary>
    public static class UserAgent
    {
        private const string FallbackName = "okta-client-dotnet";
        private const string FallbackVersion = "0.1.0";

        private static readonly object _writeLock = new();
        private static readonly List<string> _components = new();
        private static volatile string? _headerValue;

        internal static string HeaderValue
        {
            get
            {
                var cached = _headerValue;
                if (cached is not null)
                {
                    return cached;
                }

                lock (_writeLock)
                {
                    return _headerValue ??= BuildHeaderValue();
                }
            }
        }

        /// <summary>
        /// Registers an SDK sub-package to be included in the User-Agent string.
        /// Call this once per sub-package during initialization (e.g. in a module initializer).
        /// Duplicate registrations for the same <paramref name="agentName"/> are ignored.
        /// If a different version is registered for an existing <paramref name="agentName"/>,
        /// the entry is replaced with the new version.
        /// </summary>
        /// <param name="agentName">The user-agent component name, e.g. "okta-oauth2-dotnet".</param>
        /// <param name="version">The package version, e.g. "0.1.0".</param>
        public static void Register(string agentName, string version)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(agentName);
            ArgumentException.ThrowIfNullOrWhiteSpace(version);

            if (!IsValidToken(agentName) || !IsValidToken(version))
            {
                throw new ArgumentException($"Agent name or version contains invalid characters: '{agentName}/{version}'.", nameof(agentName));
            }

            lock (_writeLock)
            {
                var token = $"{agentName}/{version}";
                var prefix = $"{agentName}/";
                var existingIndex = _components.FindIndex(c => c.StartsWith(prefix, StringComparison.Ordinal));

                if (existingIndex >= 0)
                {
                    if (_components[existingIndex] == token)
                    {
                        return;
                    }

                    _components[existingIndex] = token;
                }
                else
                {
                    _components.Add(token);
                }

                _headerValue = null; // invalidate cached header value since it has changed
            }
        }

        private static string BuildHeaderValue()
        {
            var tokens = new List<string>();

            if (_components.Count > 0)
            {
                tokens.AddRange(_components);
            }
            else
            {
                tokens.Add($"{FallbackName}/{FallbackVersion}");
            }

            tokens.Add($"dotnet/{Environment.Version}");

            var platform = GetPlatformToken();
            if (platform is not null)
            {
                tokens.Add(platform);
            }

            return string.Join(" ", tokens);
        }

        private static string? GetPlatformToken()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return $"Windows/{Environment.OSVersion.Version}";
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return $"macOS/{Environment.OSVersion.Version}";
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return $"Linux/{Environment.OSVersion.Version}";
            }

            return null;
        }

        // RFC 7230 token: one or more characters from !#$%&'*+-.^_`|~ plus DIGIT and ALPHA
        private static bool IsValidToken(string value)
        {
            foreach (var c in value)
            {
                if (c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9'))
                {
                    continue;
                }

                if ("!#$%&'*+-.^_`|~".Contains(c))
                {
                    continue;
                }

                return false;
            }

            return true;
        }

        // for testing purposes only
        internal static List<string> Snapshot()
        {
            lock (_writeLock)
            {
                return new List<string>(_components);
            }
        }

        // for testing purposes only
        internal static void Restore(List<string> snapshot)
        {
            lock (_writeLock)
            {
                _components.Clear();
                _components.AddRange(snapshot);
                _headerValue = null;
            }
        }
    }
}
