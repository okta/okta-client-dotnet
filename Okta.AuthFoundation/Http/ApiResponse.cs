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

using System.Net;

namespace Okta.AuthFoundation.Http
{
    /// <summary>
    /// Represents a generic API response containing the result data, metadata, and HTTP response information.
    /// </summary>
    /// <typeparam name="T">The type of the result data returned by the API.</typeparam>
    public class ApiResponse<T>
    {
#pragma warning disable CA1000 // Factory methods are intentionally on the generic type; using ApiResponse<T>.Success(…) is the intended API
        /// <summary>
        /// Creates a successful <see cref="ApiResponse{T}"/> with the given result.
        /// </summary>
        /// <param name="result">The deserialized result data.</param>
        /// <param name="statusCode">The HTTP status code of the response.</param>
        /// <param name="requestId">The unique request identifier from the X-Request-Id header.</param>
        /// <param name="date">The date and time when the response was received; defaults to <see cref="DateTime.UtcNow"/> if null.</param>
        /// <param name="links">The parsed Link header values, keyed by relation type.</param>
        /// <param name="rateLimit">Rate-limit metadata from the response, or <c>null</c> if not present.</param>
        /// <returns>A successful <see cref="ApiResponse{T}"/> instance.</returns>
        public static ApiResponse<T> Success(T result, HttpStatusCode statusCode = HttpStatusCode.OK, string? requestId = null, DateTime? date = null, Dictionary<string, string>? links = null, ApiRateLimit? rateLimit = null)
        {
            return new ApiResponse<T>(result, true, statusCode, date ?? DateTime.UtcNow, null, requestId, links, rateLimit);
        }

        /// <summary>
        /// Creates a failed <see cref="ApiResponse{T}"/> with the given error message.
        /// </summary>
        /// <param name="errorMessage">The error message describing the failure.</param>
        /// <param name="statusCode">The HTTP status code of the response.</param>
        /// <param name="requestId">The unique request identifier from the X-Request-Id header.</param>
        /// <param name="date">The date and time when the response was received; defaults to <see cref="DateTime.UtcNow"/> if null.</param>
        /// <param name="links">The parsed Link header values, keyed by relation type.</param>
        /// <param name="rateLimit">Rate-limit metadata from the response, or <c>null</c> if not present.</param>
        /// <returns>A failed <see cref="ApiResponse{T}"/> instance.</returns>
        public static ApiResponse<T> Failure(string errorMessage, HttpStatusCode statusCode, string? requestId = null, DateTime? date = null, Dictionary<string, string>? links = null, ApiRateLimit? rateLimit = null)
        {
            return new ApiResponse<T>(default, false, statusCode, date ?? DateTime.UtcNow, errorMessage, requestId, links, rateLimit);
        }
#pragma warning restore CA1000

        private ApiResponse(T? result, bool isSuccess, HttpStatusCode statusCode, DateTime date, string? errorMessage, string? requestId, Dictionary<string, string>? links, ApiRateLimit? rateLimit)
        {
            Result = result;
            IsSuccess = isSuccess;
            StatusCode = statusCode;
            ErrorMessage = errorMessage;
            Date = date;
            RequestId = requestId;
            Links = links ?? new Dictionary<string, string>();
            RateLimit = rateLimit;
        }

        /// <summary>
        /// Gets the deserialized result data from the API response.
        /// </summary>
        public T? Result { get; }

        /// <summary>
        /// Gets the date and time when the API response was received.
        /// </summary>
        public DateTime Date { get; }

        /// <summary>
        /// Gets the HTTP status code of the API response.
        /// </summary>
        public HttpStatusCode StatusCode { get; }

        /// <summary>
        /// Gets the unique request identifier from the X-Request-Id header.
        /// </summary>
        public string? RequestId { get; }

        /// <summary>
        /// Gets a value indicating whether the API response indicates success.
        /// </summary>
        public bool IsSuccess { get; }

        /// <summary>
        /// Gets the error message if the response was not successful.
        /// </summary>
        public string? ErrorMessage { get; }

        /// <summary>
        /// Gets the parsed Link header values, keyed by relation type (e.g., "next", "self").
        /// </summary>
        public Dictionary<string, string> Links { get; }

        /// <summary>
        /// Gets rate-limit metadata from the final response, or <c>null</c> if not present.
        /// Available on both success and failure responses; populated even after retries.
        /// </summary>
        public ApiRateLimit? RateLimit { get; }
    }
}
