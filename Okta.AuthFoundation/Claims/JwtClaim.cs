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
    /// Represents a JWT claim key, with static instances for standard JWT/OIDC claims and a <see cref="Custom"/> factory for application-specific claims.
    /// </summary>
    public sealed class JwtClaim : IEquatable<JwtClaim>
    {
        /// <summary>
        /// Gets the raw string key of this claim (e.g. "sub", "email").
        /// </summary>
        public string RawKey { get; }

        private readonly bool _isCustom;

        private JwtClaim(string rawKey, bool isCustom = false)
        {
            RawKey = rawKey;
            _isCustom = isCustom;
        }

        // Core JWT claims (RFC 7519)

        /// <summary>Identifies the principal that issued the JWT (<c>iss</c>).</summary>
        public static readonly JwtClaim Issuer = new("iss");

        /// <summary>Identifies the principal that is the subject of the JWT (<c>sub</c>).</summary>
        public static readonly JwtClaim Subject = new("sub");

        /// <summary>Identifies the recipients the JWT is intended for (<c>aud</c>).</summary>
        public static readonly JwtClaim Audience = new("aud");

        /// <summary>The time after which the JWT must not be accepted (<c>exp</c>).</summary>
        public static readonly JwtClaim ExpirationTime = new("exp");

        /// <summary>The time before which the JWT must not be accepted (<c>nbf</c>).</summary>
        public static readonly JwtClaim NotBefore = new("nbf");

        /// <summary>The time at which the JWT was issued (<c>iat</c>).</summary>
        public static readonly JwtClaim IssuedAt = new("iat");

        /// <summary>A unique identifier for the JWT (<c>jti</c>).</summary>
        public static readonly JwtClaim JwtId = new("jti");

        // Authentication claims (OIDC Core)

        /// <summary>A random string used to associate a client session with the ID token (<c>nonce</c>).</summary>
        public static readonly JwtClaim Nonce = new("nonce");

        /// <summary>The time the end-user authentication occurred (<c>auth_time</c>).</summary>
        public static readonly JwtClaim AuthTime = new("auth_time");

        /// <summary>The Authentication Context Class that the authentication performed satisfied (<c>acr</c>).</summary>
        public static readonly JwtClaim AuthContextClassReference = new("acr");

        /// <summary>The authentication methods used in the authentication (<c>amr</c>).</summary>
        public static readonly JwtClaim AuthMethodsReference = new("amr");

        /// <summary>The party to which the ID token was issued (<c>azp</c>).</summary>
        public static readonly JwtClaim AuthorizedParty = new("azp");

        /// <summary>A hash of the access token, used to validate the token binding (<c>at_hash</c>).</summary>
        public static readonly JwtClaim AccessTokenHash = new("at_hash");

        /// <summary>A hash of the authorization code, used to validate the token binding (<c>c_hash</c>).</summary>
        public static readonly JwtClaim CodeHash = new("c_hash");

        // Authorization claims

        /// <summary>The scopes associated with the token (<c>scp</c>).</summary>
        public static readonly JwtClaim Scope = new("scp");

        /// <summary>The client identifier for the OAuth 2.0 client that requested the token (<c>cid</c>).</summary>
        public static readonly JwtClaim ClientId = new("cid");

        // Profile claims (OIDC Core)

        /// <summary>The end-user's full name (<c>name</c>).</summary>
        public static readonly JwtClaim Name = new("name");

        /// <summary>The end-user's given name (<c>given_name</c>).</summary>
        public static readonly JwtClaim GivenName = new("given_name");

        /// <summary>The end-user's surname or last name (<c>family_name</c>).</summary>
        public static readonly JwtClaim FamilyName = new("family_name");

        /// <summary>The end-user's middle name (<c>middle_name</c>).</summary>
        public static readonly JwtClaim MiddleName = new("middle_name");

        /// <summary>A casual name for the end-user (<c>nickname</c>).</summary>
        public static readonly JwtClaim Nickname = new("nickname");

        /// <summary>A shorthand name the end-user wishes to be referred to (<c>preferred_username</c>).</summary>
        public static readonly JwtClaim PreferredUsername = new("preferred_username");

        /// <summary>A URL of the end-user's profile page (<c>profile</c>).</summary>
        public static readonly JwtClaim Profile = new("profile");

        /// <summary>A URL of the end-user's profile picture (<c>picture</c>).</summary>
        public static readonly JwtClaim Picture = new("picture");

        /// <summary>A URL of the end-user's web page or blog (<c>website</c>).</summary>
        public static readonly JwtClaim Website = new("website");

        /// <summary>The end-user's preferred email address (<c>email</c>).</summary>
        public static readonly JwtClaim Email = new("email");

        /// <summary>Whether the end-user's email address has been verified (<c>email_verified</c>).</summary>
        public static readonly JwtClaim EmailVerified = new("email_verified");

        /// <summary>The end-user's preferred telephone number (<c>phone_number</c>).</summary>
        public static readonly JwtClaim PhoneNumber = new("phone_number");

        /// <summary>Whether the end-user's phone number has been verified (<c>phone_number_verified</c>).</summary>
        public static readonly JwtClaim PhoneNumberVerified = new("phone_number_verified");

        /// <summary>The end-user's preferred postal address (<c>address</c>).</summary>
        public static readonly JwtClaim Address = new("address");

        /// <summary>The end-user's date of birth (<c>birthdate</c>).</summary>
        public static readonly JwtClaim Birthdate = new("birthdate");

        /// <summary>The end-user's time zone, e.g. "America/Los_Angeles" (<c>zoneinfo</c>).</summary>
        public static readonly JwtClaim ZoneInfo = new("zoneinfo");

        /// <summary>The end-user's locale, e.g. "en-US" (<c>locale</c>).</summary>
        public static readonly JwtClaim Locale = new("locale");

        /// <summary>The time the end-user's information was last updated (<c>updated_at</c>).</summary>
        public static readonly JwtClaim UpdatedAt = new("updated_at");

        // Okta-specific

        /// <summary>The groups the end-user belongs to (<c>groups</c>).</summary>
        public static readonly JwtClaim Groups = new("groups");

        /// <summary>The roles assigned to the end-user (<c>roles</c>).</summary>
        public static readonly JwtClaim Roles = new("roles");

        /// <summary>
        /// Creates a <see cref="JwtClaim"/> for a custom (non-standard) claim key.
        /// </summary>
        /// <param name="key">The raw claim key string.</param>
        /// <returns>A new <see cref="JwtClaim"/> instance representing the custom claim.</returns>
        public static JwtClaim Custom(string key)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(key);
            return new(key, isCustom: true);
        }

        /// <summary>
        /// Gets all standard claims recognized by this SDK.
        /// </summary>
        public static readonly IReadOnlyList<JwtClaim> StandardClaims;

        private static readonly Dictionary<string, JwtClaim> StandardClaimsByKey;

        static JwtClaim()
        {
            StandardClaims =
            [
                Issuer, Subject, Audience, ExpirationTime, NotBefore, IssuedAt, JwtId,
                Nonce, AuthTime, AuthContextClassReference, AuthMethodsReference, AuthorizedParty,
                AccessTokenHash, CodeHash,
                Scope, ClientId,
                Name, GivenName, FamilyName, MiddleName, Nickname, PreferredUsername,
                Profile, Picture, Website, Email, EmailVerified,
                PhoneNumber, PhoneNumberVerified, Address, Birthdate, ZoneInfo, Locale, UpdatedAt,
                Groups, Roles,
            ];
            StandardClaimsByKey = StandardClaims.ToDictionary(c => c.RawKey);
        }

        internal static JwtClaim? FromKey(string key) =>
            StandardClaimsByKey.GetValueOrDefault(key);

        /// <inheritdoc />
        public bool Equals(JwtClaim? other) => other is not null && RawKey == other.RawKey && _isCustom == other._isCustom;

        /// <inheritdoc />
        public override bool Equals(object? obj) => Equals(obj as JwtClaim);

        /// <inheritdoc />
        public override int GetHashCode() => HashCode.Combine(RawKey, _isCustom);

        /// <summary>Returns true if both instances represent the same claim key and kind.</summary>
        public static bool operator ==(JwtClaim? left, JwtClaim? right) => Equals(left, right);

        /// <summary>Returns true if the instances represent different claim keys or kinds.</summary>
        public static bool operator !=(JwtClaim? left, JwtClaim? right) => !Equals(left, right);

        /// <inheritdoc />
        public override string ToString() => RawKey;
    }
}
