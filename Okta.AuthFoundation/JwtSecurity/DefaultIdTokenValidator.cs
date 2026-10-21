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

using System.Diagnostics.CodeAnalysis;
using Okta.AuthFoundation.Claims;
using Okta.AuthFoundation.Exceptions;
using Okta.AuthFoundation.OAuth2;

namespace Okta.AuthFoundation.JwtSecurity
{
    /// <summary>
    /// The default implementation of <see cref="IIdTokenValidator"/> that validates ID token claims.
    /// </summary>
    public class DefaultIdTokenValidator : IIdTokenValidator
    {
        private readonly ITimeCoordinator _timeCoordinator = OktaServices.Resolve<ITimeCoordinator>();
        private readonly ValidationCheck[] _checks;
        private readonly int _issuedAtGraceInterval;

        /// <summary>
        /// Initializes a new instance of <see cref="DefaultIdTokenValidator"/>.
        /// </summary>
        /// <param name="checks">The set of validation checks to perform, or <see langword="null"/> to use all checks.</param>
        /// <param name="issuedAtGraceInterval">The maximum allowed clock skew in seconds for the issued-at claim.</param>
        public DefaultIdTokenValidator(ValidationCheck[]? checks = null, int issuedAtGraceInterval = 300)
        {
            _checks = checks ?? IIdTokenValidator.AllChecks;
            _issuedAtGraceInterval = issuedAtGraceInterval;
        }

        /// <inheritdoc/>
        public void Validate(Jwt idToken, Uri issuer, string clientId, IdTokenValidatorContext? context)
        {
            foreach (var check in _checks)
            {
                switch (check)
                {
                    case ValidationCheck.Issuer:
                        if (TryParseIssuer(idToken, out var issuerClaim)
                            && OAuth2ClientConfiguration.IsSameIssuer(issuer, issuerClaim))
                        {
                            break;
                        }

                        throw new JwtException($"Invalid issuer (iss) claim.");

                    case ValidationCheck.Audience:
                        if (idToken.Audiences.Contains(clientId))
                        {
                            break;
                        }

                        throw new JwtException($"Invalid audience (aud) claim.");

                    case ValidationCheck.Scheme:
                        if (TryParseIssuer(idToken, out var schemeClaim) && schemeClaim.Scheme == Uri.UriSchemeHttps)
                        {
                            break;
                        }

                        throw new JwtException("Issuer must use HTTPS scheme.");

                    case ValidationCheck.Algorithm:
                        if (context?.SupportedAlgs != null)
                        {
                            var alg = idToken.Algorithm;
                            if (Array.Exists(context.SupportedAlgs, a => a == alg))
                            {
                                break;
                            }

                            throw new JwtException($"Unsupported signature algorithm.");
                        }

                        break;

                    case ValidationCheck.ExpirationTime:
                        if (idToken.ExpirationTime() > _timeCoordinator.Now)
                        {
                            break;
                        }

                        throw new JwtException("Jwt has expired.");

                    case ValidationCheck.IssuedAtTime:
                        var iat = idToken.IssuedAt();
                        if (iat != null && Math.Abs((_timeCoordinator.Now - iat.Value).TotalSeconds) <= _issuedAtGraceInterval)
                        {
                            break;
                        }

                        throw new JwtException("Token issued at time (iat) exceeds grace interval.");

                    case ValidationCheck.Nonce:
                        if (context?.Nonce != null)
                        {
                            if (idToken.Nonce() != context.Nonce)
                            {
                                throw new JwtException("Nonce claim does not match.");
                            }
                        }

                        break;

                    case ValidationCheck.MaxAge:
                        if (context?.MaxAge != null)
                        {
                            var authTime = idToken.AuthTime();
                            if (authTime == null)
                            {
                                throw new JwtException("auth_time claim is required when max_age is requested.");
                            }

                            if ((_timeCoordinator.Now - authTime.Value).TotalSeconds > context.MaxAge.Value)
                            {
                                throw new JwtException("Authentication time (auth_time) exceeds max_age.");
                            }
                        }

                        break;

                    case ValidationCheck.Subject:
                        if (!string.IsNullOrEmpty(idToken.Subject()))
                        {
                            break;
                        }

                        throw new JwtException("Subject (sub) claim is missing.");

                    case ValidationCheck.Acr:
                        if (context?.AcrValues != null)
                        {
                            if (string.IsNullOrEmpty(idToken.AuthContextClassReference()))
                            {
                                throw new JwtException("ACR claim is missing.");
                            }
                        }

                        break;

                    default:
                        break;
                }
            }
        }

        /// <summary>
        /// Parses the issuer (iss) claim of an id token.
        /// </summary>
        /// <param name="idToken">The id token to read the claim from.</param>
        /// <param name="issuer">The parsed issuer, when the claim is an absolute URL.</param>
        /// <returns><see langword="true"/> when the claim is present and an absolute URL.</returns>
        private static bool TryParseIssuer(Jwt idToken, [NotNullWhen(true)] out Uri? issuer) =>

            // The claim is an unvalidated string from a token whose signature has not been verified yet, so the
            // caller reports a malformed value as JwtException.
            Uri.TryCreate(idToken.Issuer(), UriKind.Absolute, out issuer);
    }
}
