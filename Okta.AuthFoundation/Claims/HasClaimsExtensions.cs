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
    /// <summary>
    /// Extension methods for accessing claim values on any <see cref="IHasClaims"/> instance.
    /// </summary>
    public static class HasClaimsExtensions
    {
        /// <summary>
        /// Gets the value of a claim by its raw string key, or default if not present.
        /// </summary>
        /// <typeparam name="T">The expected type of the claim value.</typeparam>
        /// <param name="self">The claims source.</param>
        /// <param name="key">The raw claim key (e.g. "sub", "email").</param>
        /// <returns>The claim value deserialized as <typeparamref name="T"/>, or default if not found.</returns>
        public static T? GetValue<T>(this IHasClaims self, string key)
        {
            if (!self.Payload.TryGetValue(key, out var element))
            {
                return default;
            }

            if (ClaimConversions.Registry.TryGetValue(typeof(T), out var converter))
            {
                return (T?)converter(element);
            }

            return element.Deserialize<T>();
        }

        /// <summary>
        /// Gets the value of a claim by its <see cref="JwtClaim"/> definition, or default if not present.
        /// </summary>
        /// <typeparam name="T">The expected type of the claim value.</typeparam>
        /// <param name="self">The claims source.</param>
        /// <param name="claim">The claim definition.</param>
        /// <returns>The claim value deserialized as <typeparamref name="T"/>, or default if not found.</returns>
        public static T? GetValue<T>(this IHasClaims self, JwtClaim claim)
            => self.GetValue<T>(claim.RawKey);

        /// <summary>
        /// Gets the value of a claim or throws <see cref="ClaimNotFoundException"/> if not present.
        /// </summary>
        /// <typeparam name="T">The expected type of the claim value.</typeparam>
        /// <param name="self">The claims source.</param>
        /// <param name="key">The raw claim key.</param>
        /// <returns>The claim value deserialized as <typeparamref name="T"/>.</returns>
        /// <exception cref="ClaimNotFoundException">Thrown when the claim is not present.</exception>
        public static T RequireValue<T>(this IHasClaims self, string key)
        {
            var value = self.GetValue<T>(key);
            if (value is null)
            {
                throw new ClaimNotFoundException(key);
            }

            return value;
        }

        /// <summary>
        /// Gets the value of a claim or throws <see cref="ClaimNotFoundException"/> if not present.
        /// </summary>
        /// <typeparam name="T">The expected type of the claim value.</typeparam>
        /// <param name="self">The claims source.</param>
        /// <param name="claim">The claim definition.</param>
        /// <returns>The claim value deserialized as <typeparamref name="T"/>.</returns>
        /// <exception cref="ClaimNotFoundException">Thrown when the claim is not present.</exception>
        public static T RequireValue<T>(this IHasClaims self, JwtClaim claim)
            => self.RequireValue<T>(claim.RawKey);

        /// <summary>
        /// Returns the standard <see cref="JwtClaim"/> instances that are present in the payload.
        /// </summary>
        /// <param name="self">The claims source.</param>
        /// <returns>An enumerable of standard claims found in the payload.</returns>
        public static IEnumerable<JwtClaim> GetClaims(this IHasClaims self)
            => self.Payload.Keys.Select(JwtClaim.FromKey).Where(c => c is not null)!;

        /// <summary>
        /// Returns the raw keys of non-standard (custom) claims present in the payload.
        /// </summary>
        /// <param name="self">The claims source.</param>
        /// <returns>An enumerable of custom claim key strings.</returns>
        public static IEnumerable<string> GetCustomClaims(this IHasClaims self)
            => self.Payload.Keys.Where(k => JwtClaim.FromKey(k) is null);

        /// <summary>
        /// Returns all raw claim keys present in the payload.
        /// </summary>
        /// <param name="self">The claims source.</param>
        /// <returns>An enumerable of all claim key strings.</returns>
        public static IEnumerable<string> GetAllClaims(this IHasClaims self)
            => self.Payload.Keys;
    }
}
