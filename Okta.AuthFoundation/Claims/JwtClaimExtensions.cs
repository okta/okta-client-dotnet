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

namespace Okta.AuthFoundation.Claims
{
    /// <summary>
    /// Typed convenience extension methods for accessing standard JWT/OIDC claims on any <see cref="IHasClaims"/> instance.
    /// </summary>
    public static class JwtClaimExtensions
    {
        // Core JWT claims

        /// <summary>Gets the issuer (iss) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? Issuer(this IHasClaims self) => self.GetValue<string>(JwtClaim.Issuer);

        /// <summary>Gets the subject (sub) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? Subject(this IHasClaims self) => self.GetValue<string>(JwtClaim.Subject);

        /// <summary>Gets the audience (aud) claim as a single string value.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? Audience(this IHasClaims self) => self.GetValue<string>(JwtClaim.Audience);

        /// <summary>Gets the expiration time (exp) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static DateTime? ExpirationTime(this IHasClaims self) => self.GetValue<DateTime>(JwtClaim.ExpirationTime);

        /// <summary>Gets the not-before (nbf) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static DateTime? NotBefore(this IHasClaims self) => self.GetValue<DateTime>(JwtClaim.NotBefore);

        /// <summary>Gets the issued-at (iat) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static DateTime? IssuedAt(this IHasClaims self) => self.GetValue<DateTime>(JwtClaim.IssuedAt);

        /// <summary>Gets the JWT ID (jti) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? JwtId(this IHasClaims self) => self.GetValue<string>(JwtClaim.JwtId);

        // Authentication claims

        /// <summary>Gets the nonce claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? Nonce(this IHasClaims self) => self.GetValue<string>(JwtClaim.Nonce);

        /// <summary>Gets the authentication time (auth_time) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static DateTime? AuthTime(this IHasClaims self) => self.GetValue<DateTime>(JwtClaim.AuthTime);

        /// <summary>Gets the authentication context class reference (acr) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? AuthContextClassReference(this IHasClaims self) => self.GetValue<string>(JwtClaim.AuthContextClassReference);

        /// <summary>Gets the authentication methods reference (amr) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string[]? AuthMethodsReference(this IHasClaims self) => self.GetValue<string[]>(JwtClaim.AuthMethodsReference);

        /// <summary>Gets the authorized party (azp) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? AuthorizedParty(this IHasClaims self) => self.GetValue<string>(JwtClaim.AuthorizedParty);

        /// <summary>Gets the access token hash (at_hash) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? AccessTokenHash(this IHasClaims self) => self.GetValue<string>(JwtClaim.AccessTokenHash);

        /// <summary>Gets the code hash (c_hash) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? CodeHash(this IHasClaims self) => self.GetValue<string>(JwtClaim.CodeHash);

        // Authorization claims

        /// <summary>Gets the scope (scp) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string[]? Scope(this IHasClaims self) => self.GetValue<string[]>(JwtClaim.Scope);

        /// <summary>Gets the client ID (cid) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? ClientId(this IHasClaims self) => self.GetValue<string>(JwtClaim.ClientId);

        // Profile claims

        /// <summary>Gets the full name (name) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? Name(this IHasClaims self) => self.GetValue<string>(JwtClaim.Name);

        /// <summary>Gets the given name (given_name) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? GivenName(this IHasClaims self) => self.GetValue<string>(JwtClaim.GivenName);

        /// <summary>Gets the family name (family_name) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? FamilyName(this IHasClaims self) => self.GetValue<string>(JwtClaim.FamilyName);

        /// <summary>Gets the middle name (middle_name) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? MiddleName(this IHasClaims self) => self.GetValue<string>(JwtClaim.MiddleName);

        /// <summary>Gets the nickname claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? Nickname(this IHasClaims self) => self.GetValue<string>(JwtClaim.Nickname);

        /// <summary>Gets the preferred username (preferred_username) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? PreferredUsername(this IHasClaims self) => self.GetValue<string>(JwtClaim.PreferredUsername);

        /// <summary>Gets the profile URL (profile) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? Profile(this IHasClaims self) => self.GetValue<string>(JwtClaim.Profile);

        /// <summary>Gets the picture URL (picture) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? Picture(this IHasClaims self) => self.GetValue<string>(JwtClaim.Picture);

        /// <summary>Gets the website URL (website) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? Website(this IHasClaims self) => self.GetValue<string>(JwtClaim.Website);

        /// <summary>Gets the email claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? Email(this IHasClaims self) => self.GetValue<string>(JwtClaim.Email);

        /// <summary>Gets the email verified (email_verified) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static bool? EmailVerified(this IHasClaims self) => self.GetValue<bool?>(JwtClaim.EmailVerified);

        /// <summary>Gets the phone number (phone_number) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? PhoneNumber(this IHasClaims self) => self.GetValue<string>(JwtClaim.PhoneNumber);

        /// <summary>Gets the phone number verified (phone_number_verified) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static bool? PhoneNumberVerified(this IHasClaims self) => self.GetValue<bool?>(JwtClaim.PhoneNumberVerified);

        /// <summary>Gets the address claim as a dictionary of address components.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static Dictionary<string, string>? Address(this IHasClaims self) => self.GetValue<Dictionary<string, string>>(JwtClaim.Address);

        /// <summary>Gets the birthdate claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? Birthdate(this IHasClaims self) => self.GetValue<string>(JwtClaim.Birthdate);

        /// <summary>Gets the timezone (zoneinfo) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? ZoneInfo(this IHasClaims self) => self.GetValue<string>(JwtClaim.ZoneInfo);

        /// <summary>Gets the locale claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string? Locale(this IHasClaims self) => self.GetValue<string>(JwtClaim.Locale);

        /// <summary>Gets the updated-at (updated_at) claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static DateTime? UpdatedAt(this IHasClaims self) => self.GetValue<DateTime>(JwtClaim.UpdatedAt);

        // Okta-specific

        /// <summary>Gets the groups claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string[]? Groups(this IHasClaims self) => self.GetValue<string[]>(JwtClaim.Groups);

        /// <summary>Gets the roles claim.</summary>
        /// <param name="self">The <see cref="IHasClaims"/> instance to read from.</param>
        /// <returns>The claim value, or <see langword="null"/> if the claim is not present.</returns>
        public static string[]? Roles(this IHasClaims self) => self.GetValue<string[]>(JwtClaim.Roles);
    }
}
