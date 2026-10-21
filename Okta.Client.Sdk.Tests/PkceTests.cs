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

using Okta.OAuth2;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    public class PkceTests
    {
        [Fact]
        public void GenerateVerifier_ProducesCorrectLength()
        {
            var verifier = Pkce.GenerateVerifier(32);

            // Base64 URL encoding of 32 bytes produces ~43 characters
            Assert.InRange(verifier.Length, 40, 45);
        }

        [Fact]
        public void GenerateVerifier_UsesOnlyUnreservedCharacters()
        {
            var verifier = Pkce.GenerateVerifier(32);

            // RFC 7636: unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
            Assert.Matches(@"^[A-Za-z0-9\-._~]+$", verifier);
        }

        [Fact]
        public void GenerateVerifier_DifferentCalls_ProduceDifferentValues()
        {
            var verifier1 = Pkce.GenerateVerifier(32);
            var verifier2 = Pkce.GenerateVerifier(32);

            Assert.NotEqual(verifier1, verifier2);
        }

        [Fact]
        public void GenerateVerifier_VariousByteLengths()
        {
            var byteLengths = new[] { 16, 24, 32, 48, 64 };

            foreach (var byteLength in byteLengths)
            {
                var verifier = Pkce.GenerateVerifier(byteLength);

                Assert.NotEmpty(verifier);
                Assert.Matches(@"^[A-Za-z0-9\-._~]+$", verifier);
            }
        }

        [Fact]
        public void GenerateChallenge_WithKnownVerifier_MatchesExpectedValue()
        {
            // RFC 7636 Appendix B test vector
            var verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
            var expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

            var challenge = Pkce.GenerateChallenge(verifier);

            Assert.Equal(expectedChallenge, challenge);
        }

        [Fact]
        public void GenerateChallenge_ProducesUrlSafeBase64()
        {
            var verifier = Pkce.GenerateVerifier(32);
            var challenge = Pkce.GenerateChallenge(verifier);

            Assert.NotEmpty(challenge);
            Assert.DoesNotContain("+", challenge);
            Assert.DoesNotContain("/", challenge);
            Assert.DoesNotContain("=", challenge);
        }

        [Fact]
        public void GenerateChallenge_SameVerifier_ProducesSameChallenge()
        {
            var verifier = "test-verifier-value";
            var challenge1 = Pkce.GenerateChallenge(verifier);
            var challenge2 = Pkce.GenerateChallenge(verifier);

            Assert.Equal(challenge1, challenge2);
        }

        [Fact]
        public void GenerateChallenge_DifferentVerifiers_ProduceDifferentChallenges()
        {
            var verifier1 = Pkce.GenerateVerifier(32);
            var verifier2 = Pkce.GenerateVerifier(32);

            var challenge1 = Pkce.GenerateChallenge(verifier1);
            var challenge2 = Pkce.GenerateChallenge(verifier2);

            Assert.NotEqual(challenge1, challenge2);
        }

        [Fact]
        public void Generate_ProducesValidPkceInstance()
        {
            var pkce = Pkce.Generate();

            Assert.NotNull(pkce.Verifier);
            Assert.NotNull(pkce.Challenge);
            Assert.NotEmpty(pkce.Verifier);
            Assert.NotEmpty(pkce.Challenge);
        }

        [Fact]
        public void Generate_MethodIsAlwaysS256()
        {
            var pkce = Pkce.Generate();

            Assert.Equal("S256", pkce.Method);
        }

        [Fact]
        public void Generate_ChallengeMatchesVerifier()
        {
            var pkce = Pkce.Generate();

            var computedChallenge = Pkce.GenerateChallenge(pkce.Verifier);

            Assert.Equal(computedChallenge, pkce.Challenge);
        }

        [Fact]
        public void Generate_ProducesDifferentPairsEachTime()
        {
            var pkce1 = Pkce.Generate();
            var pkce2 = Pkce.Generate();

            Assert.NotEqual(pkce1.Verifier, pkce2.Verifier);
            Assert.NotEqual(pkce1.Challenge, pkce2.Challenge);
        }

        [Fact]
        public void Verifier_MeetsRfc7636LengthRequirement()
        {
            // RFC 7636: verifier should be between 43-128 characters
            var verifier = Pkce.GenerateVerifier(32);

            Assert.InRange(verifier.Length, 43, 128);
        }

        [Fact]
        public void Challenge_IsCorrectLength()
        {
            var pkce = Pkce.Generate();

            Assert.Equal(43, pkce.Challenge.Length);
        }
    }
}
