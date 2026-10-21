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

using Okta.AuthFoundation.Http;
using Okta.AuthFoundation.TokenManagement;

namespace Okta.AuthFoundation.OAuth2
{
    /// <summary>
    /// Represents an API request to the OpenID Connect UserInfo endpoint.
    /// </summary>
    internal class UserInfoRequest<T> : ApiRequest<T>
        where T : UserInfo
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UserInfoRequest{T}"/> class.
        /// </summary>
        /// <param name="userInfoEndpoint">The UserInfo endpoint URI.</param>
        /// <param name="token">The token to use for authorization.</param>
        internal UserInfoRequest(Uri userInfoEndpoint)
        {
            Method = HttpMethod.Get;
            Url = userInfoEndpoint;
        }
    }
}
