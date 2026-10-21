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

namespace Okta.AuthFoundation.OAuth2
{
    /// <summary>
    /// Authenticates requests using the JWT Bearer Client Authentication method (RFC 7523).
    /// </summary>
    /// <remarks>
    /// <para>
    /// On each token endpoint request, the provided <see cref="Func{Uri, String}"/> factory is invoked
    /// with the token endpoint URI and its return value is attached as the <c>client_assertion</c>
    /// parameter. Because the factory is called per-request, each assertion can carry a fresh
    /// <c>iat</c>, <c>exp</c>, and <c>jti</c> as required by the specification.
    /// </para>
    /// <para>
    /// The SDK does not perform signing. Signing is left entirely to the caller, allowing any
    /// key management strategy — HSMs, cloud KMS services, platform secure enclaves, or local
    /// key stores — to be used without restriction.
    /// </para>
    /// <para>
    /// A conforming JWT assertion must include the following claims:
    /// <list type="bullet">
    ///   <item><term>iss</term><description>The client ID.</description></item>
    ///   <item><term>sub</term><description>The client ID.</description></item>
    ///   <item><term>aud</term><description>The token endpoint URL (passed as the argument to the factory).</description></item>
    ///   <item><term>iat</term><description>The time the assertion was issued.</description></item>
    ///   <item><term>exp</term><description>The expiry time of the assertion.</description></item>
    ///   <item><term>jti</term><description>A unique identifier for the assertion (recommended to prevent replay).</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    public sealed class PrivateKeyJwtAuthentication : IClientAuthentication
    {
        private readonly Func<Uri, string> _assertionFactory;

        /// <summary>
        /// Initializes a new instance that invokes <paramref name="assertionFactory"/> on each request
        /// to obtain a fresh, signed JWT assertion.
        /// </summary>
        /// <param name="assertionFactory">
        /// A factory that receives the token endpoint URI as its argument and returns a signed JWT
        /// assertion string. Called on every token request so that each assertion can carry a fresh
        /// <c>iat</c>, <c>exp</c>, and <c>jti</c>.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="assertionFactory"/> is <c>null</c>.
        /// </exception>
        public PrivateKeyJwtAuthentication(Func<Uri, string> assertionFactory)
        {
            ArgumentNullException.ThrowIfNull(assertionFactory);
            _assertionFactory = assertionFactory;
        }

        /// <summary>
        /// Initializes a new instance using a static, pre-built JWT assertion string.
        /// </summary>
        /// <remarks>
        /// Because the assertion string is static, it will become invalid once its <c>exp</c> claim
        /// is reached. This overload is suitable for testing or single-request scenarios. For
        /// long-lived clients, use <see cref="PrivateKeyJwtAuthentication(Func{Uri, string})"/>
        /// so that a fresh assertion is produced on every request.
        /// </remarks>
        /// <param name="preBuiltAssertion">A pre-signed JWT assertion string.</param>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="preBuiltAssertion"/> is <c>null</c>, empty, or whitespace.
        /// </exception>
        public PrivateKeyJwtAuthentication(string preBuiltAssertion)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(preBuiltAssertion);
            _assertionFactory = _ => preBuiltAssertion;
        }

        /// <inheritdoc/>
        public ClientAuthentication Method => ClientAuthentication.PrivateKeyJwt;

        /// <inheritdoc/>
        public void AddAuthentication(HttpRequestMessage request, string clientId, Dictionary<string, string> parameters)
        {
            if (request.RequestUri is null)
            {
                throw new ArgumentException("Request must have a URI set before authentication can be applied.", nameof(request));
            }

            parameters["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
            parameters["client_assertion"] = _assertionFactory(request.RequestUri);
        }
    }
}
