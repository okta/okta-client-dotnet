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

using System.Collections.ObjectModel;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Okta.AuthFoundation.Exceptions;

namespace Okta.AuthFoundation.OAuth2
{
    /// <summary>
    /// Represents the OAuth2 client configuration loaded from an <c>Okta.json</c> file.
    /// </summary>
    public sealed class OktaConfiguration
    {
        /// <summary>Gets the issuer URL of the authorization server.</summary>
        public Uri IssuerUrl { get; }

        /// <summary>Gets the OAuth2 client ID.</summary>
        public string ClientId { get; }

        /// <summary>Gets the requested scopes.</summary>
        public IReadOnlyList<string> Scope { get; }

        /// <summary>Gets the redirect URI for flows that require a callback (e.g. Authorization Code).</summary>
        public Uri? RedirectUri { get; }

        /// <summary>Gets the logout redirect URI.</summary>
        public Uri? LogoutRedirectUri { get; }

        /// <summary>Gets the audience value for the target authorization server.</summary>
        public string? Audience { get; }

        /// <summary>
        /// Gets the client authentication strategy. Set automatically when <c>client_secret</c> is present in the file.
        /// </summary>
        public IClientAuthentication? Authentication { get; }

        /// <summary>Gets any unrecognized string properties from the configuration file.</summary>
        public IReadOnlyDictionary<string, string>? AdditionalParameters { get; }

        private OktaConfiguration(
            Uri issuerUrl,
            string clientId,
            IReadOnlyList<string> scopes,
            Uri? redirectUri,
            Uri? logoutRedirectUri,
            string? audience,
            IClientAuthentication? authentication,
            IReadOnlyDictionary<string, string>? additionalParameters)
        {
            IssuerUrl = issuerUrl;
            ClientId = clientId;
            Scope = scopes;
            RedirectUri = redirectUri;
            LogoutRedirectUri = logoutRedirectUri;
            Audience = audience;
            Authentication = authentication;
            AdditionalParameters = additionalParameters;
        }

        /// <summary>
        /// Loads an <see cref="OktaConfiguration"/> from the specified file path.
        /// </summary>
        /// <param name="filePath">The path to the JSON configuration file.</param>
        /// <returns>The loaded <see cref="OktaConfiguration"/>.</returns>
        /// <exception cref="Okta.AuthFoundation.Exceptions.OktaConfigurationException">Thrown if the file is not found, cannot be parsed, or is missing required fields.</exception>
        public static OktaConfiguration Load(string filePath)
        {
            string json;
            try
            {
                json = File.ReadAllText(filePath);
            }
            catch (Exception ex)
            {
                throw OktaConfigurationException.CannotReadFile(filePath, ex);
            }

            return Parse(json, filePath);
        }

        /// <summary>
        /// Loads an <see cref="OktaConfiguration"/> from an <c>Okta.json</c> file, searching the current directory
        /// and each parent directory until the file is found.
        /// </summary>
        /// <returns>The loaded <see cref="OktaConfiguration"/>.</returns>
        /// <exception cref="Okta.AuthFoundation.Exceptions.OktaConfigurationException">Thrown if no <c>Okta.json</c> file is found or the file is invalid.</exception>
        public static OktaConfiguration LoadDefault()
        {
            var path = FindDefaultPath();
            if (path is null)
            {
                throw OktaConfigurationException.DefaultFileNotFound();
            }

            return Load(path);
        }

        /// <summary>
        /// Creates an <see cref="OktaConfiguration"/> from an <see cref="Microsoft.Extensions.Configuration.IConfiguration"/> section,
        /// enabling integration with ASP.NET Core's configuration system.
        /// </summary>
        /// <param name="configuration">The configuration section containing OAuth2 client settings.</param>
        /// <returns>The created <see cref="OktaConfiguration"/>.</returns>
        /// <exception cref="Okta.AuthFoundation.Exceptions.OktaConfigurationException">Thrown if required fields are missing or invalid.</exception>
        public static OktaConfiguration FromConfiguration(IConfiguration configuration)
        {
            var strings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var arrays = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

            foreach (var child in configuration.GetChildren())
            {
                if (child.Value != null)
                {
                    strings[child.Key] = child.Value;
                }
                else
                {
                    var list = child.GetChildren()
                        .Where(c => c.Value != null)
                        .Select(c => c.Value!)
                        .ToList();
                    if (list.Count > 0)
                    {
                        arrays[child.Key] = list;
                    }
                }
            }

            return Build(strings, arrays);
        }

        /// <summary>
        /// Creates an <see cref="OAuth2ClientConfiguration"/> from this configuration.
        /// </summary>
        /// <returns>A new <see cref="OAuth2ClientConfiguration"/> populated from this instance.</returns>
        public OAuth2ClientConfiguration ToOAuth2ClientConfiguration() =>
            new(IssuerUrl, ClientId, Scope, Authentication);

        private static string? FindDefaultPath()
        {
            var dir = new DirectoryInfo(Directory.GetCurrentDirectory());
            while (dir != null)
            {
                var candidate = Path.Combine(dir.FullName, "Okta.json");
                if (File.Exists(candidate))
                {
                    return candidate;
                }

                dir = dir.Parent;
            }

            return null;
        }

        private static readonly string[] _scopeKeys = new[] { "Scopes", "Scope", "scope", "scopes" };

        private static readonly HashSet<string> _knownKeys = new(StringComparer.OrdinalIgnoreCase)
        {
            "IssuerUrl", "issuer_url", "issuer",
            "ClientId", "client_id",
            "Scopes", "Scope", "scope", "scopes",
            "RedirectUri", "redirect_uri",
            "LogoutRedirectUri", "logout_redirect_uri",
            "Audience",
            "ClientSecret", "client_secret",
        };

        private static OktaConfiguration Parse(string json, string filePath)
        {
            JsonDocument doc;
            try
            {
                doc = JsonDocument.Parse(json);
            }
            catch (JsonException ex)
            {
                throw OktaConfigurationException.InvalidJson(filePath, ex);
            }

            using (doc)
            {
                if (doc.RootElement.ValueKind != JsonValueKind.Object)
                {
                    throw OktaConfigurationException.InvalidJson(
                        filePath,
                        new JsonException("Configuration file must contain a JSON object."));
                }

                var strings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                var arrays = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    if (prop.Value.ValueKind == JsonValueKind.String)
                    {
                        strings[prop.Name] = prop.Value.GetString()!;
                    }
                    else if (prop.Value.ValueKind == JsonValueKind.Array)
                    {
                        var list = new List<string>();
                        foreach (var item in prop.Value.EnumerateArray())
                        {
                            if (item.ValueKind == JsonValueKind.String)
                            {
                                list.Add(item.GetString()!);
                            }
                        }

                        arrays[prop.Name] = list;
                    }
                }

                return Build(strings, arrays);
            }
        }

        private static OktaConfiguration Build(
            Dictionary<string, string> strings,
            Dictionary<string, List<string>> arrays)
        {
            var issuerStr = strings.GetValueOrDefault("IssuerUrl")
                ?? strings.GetValueOrDefault("issuer_url")
                ?? strings.GetValueOrDefault("issuer");
            if (string.IsNullOrWhiteSpace(issuerStr))
            {
                throw OktaConfigurationException.MissingRequiredField("IssuerUrl");
            }

            if (!Uri.TryCreate(issuerStr, UriKind.Absolute, out var issuerUrl))
            {
                throw OktaConfigurationException.InvalidFieldValue("IssuerUrl", issuerStr);
            }

            var clientId = strings.GetValueOrDefault("ClientId")
                ?? strings.GetValueOrDefault("client_id");
            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw OktaConfigurationException.MissingRequiredField("ClientId");
            }

            var scopes = new List<string>();
            var scopeArrayKey = _scopeKeys.FirstOrDefault(k => arrays.ContainsKey(k));
            if (scopeArrayKey != null)
            {
                scopes = arrays[scopeArrayKey];
            }
            else
            {
                var scopeStr = _scopeKeys
                    .Select(k => strings.GetValueOrDefault(k))
                    .FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));
                if (scopeStr != null)
                {
                    scopes.AddRange(scopeStr.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
                }
            }

            Uri? redirectUri = ParseOptionalUri(strings, "RedirectUri", "redirect_uri");
            Uri? logoutRedirectUri = ParseOptionalUri(strings, "LogoutRedirectUri", "logout_redirect_uri");

            var audience = strings.GetValueOrDefault("Audience");
            if (string.IsNullOrWhiteSpace(audience))
            {
                audience = null;
            }

            var clientSecret = strings.GetValueOrDefault("ClientSecret")
                ?? strings.GetValueOrDefault("client_secret");
            IClientAuthentication? authentication = string.IsNullOrWhiteSpace(clientSecret)
                ? null
                : new ClientSecretAuthentication(clientSecret);

            var additional = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var kvp in strings)
            {
                if (!_knownKeys.Contains(kvp.Key))
                {
                    additional[kvp.Key] = kvp.Value;
                }
            }

            return new OktaConfiguration(
                issuerUrl,
                clientId,
                scopes.AsReadOnly(),
                redirectUri,
                logoutRedirectUri,
                audience,
                authentication,
                additional.Count > 0 ? new ReadOnlyDictionary<string, string>(additional) : null);
        }

        private static Uri? ParseOptionalUri(Dictionary<string, string> strings, params string[] keys)
        {
            foreach (var key in keys)
            {
                var value = strings.GetValueOrDefault(key);
                if (!string.IsNullOrWhiteSpace(value))
                {
                    if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
                    {
                        throw OktaConfigurationException.InvalidFieldValue(key, value);
                    }

                    return uri;
                }
            }

            return null;
        }
    }
}
