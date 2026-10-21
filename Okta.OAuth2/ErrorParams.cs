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

namespace Okta.OAuth2
{
    internal class ErrorParams : IRedirectUriParams
    {
        public string Type => "error";

        public string Error { get; init; }

        public string? ErrorDescription { get; init; }

        public string? ErrorUri { get; init; }

        public ErrorParams(
            string error,
            string? errorDescription,
            string? errorUri)
        {
            Error = error;
            ErrorDescription = errorDescription;
            ErrorUri = errorUri;
        }
    }
}
