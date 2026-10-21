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

using System.Text.Json;

namespace Okta.AuthFoundation.Claims
{
    internal static class ClaimConversions
    {
        internal static readonly Dictionary<Type, Func<JsonElement, object?>> Registry = new()
        {
            // bool: STJ handles true/false; this adds support for 0/1 integers (some OIDC providers)
            [typeof(bool)] = e => e.ValueKind switch
            {
                JsonValueKind.Number when e.TryGetInt32(out var i) => (object?)(i != 0),
                _ => e.Deserialize<bool>(),
            },

            [typeof(bool?)] = e => e.ValueKind switch
            {
                JsonValueKind.Number when e.TryGetInt32(out var i) => (object?)(bool?)(i != 0),
                _ => e.Deserialize<bool?>(),
            },

            // DateTime/DateTimeOffset: STJ handles ISO 8601 strings; this adds Unix epoch seconds (JWT standard)
            [typeof(DateTime)] = e => e.ValueKind == JsonValueKind.Number && e.TryGetInt64(out var ts)
                ? (object?)DateTimeOffset.FromUnixTimeSeconds(ts).UtcDateTime
                : e.Deserialize<DateTime>(),

            [typeof(DateTimeOffset)] = e => e.ValueKind == JsonValueKind.Number && e.TryGetInt64(out var ts)
                ? (object?)DateTimeOffset.FromUnixTimeSeconds(ts)
                : e.Deserialize<DateTimeOffset>(),

            // Uri: STJ doesn't convert strings to Uri
            [typeof(Uri)] = e =>
                e.ValueKind == JsonValueKind.String &&
                Uri.TryCreate(e.GetString(), UriKind.Absolute, out var uri)
                    ? (object?)uri
                    : null,

            // string[]: STJ handles arrays; this adds space-separated strings (OAuth2 scope claim)
            [typeof(string[])] = e => e.ValueKind switch
            {
                JsonValueKind.Array =>
                    (object?)e.EnumerateArray().Select(x => x.GetString() ?? string.Empty).ToArray(),
                JsonValueKind.String =>
                    e.GetString()!.Split(' ', StringSplitOptions.RemoveEmptyEntries),
                _ => null,
            },
        };
    }
}
