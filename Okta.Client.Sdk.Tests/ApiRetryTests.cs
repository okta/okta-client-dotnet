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
using Okta.AuthFoundation;
using Okta.AuthFoundation.Http;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    public class ApiRetryTests : IDisposable
    {
        private readonly TestHttpMessageHandler _mockHandler;
        private readonly TestApiClient _client;
        private readonly List<HttpRequestMessage> _sentRequests = new List<HttpRequestMessage>();
        private int _sendCount;

        public ApiRetryTests()
        {
            _mockHandler = new TestHttpMessageHandler((request, ct) =>
            {
                _sendCount++;
                _sentRequests.Add(request);
                return Task.FromResult(Make200());
            });
            _client = new TestApiClient(new HttpClient(_mockHandler), new DefaultTimeCoordinator());
        }

        private static HttpResponseMessage Make200() =>
            new(HttpStatusCode.OK) { Content = new StringContent("{}") };

        private static HttpResponseMessage Make429(int retryAfterSeconds = 0, int? rateLimitReset = null, DateTimeOffset? responseDate = null)
        {
            var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests)
            {
                Content = new StringContent("rate limited"),
            };
            response.Headers.Add("Retry-After", retryAfterSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture));
            if (rateLimitReset.HasValue)
            {
                response.Headers.Add("X-Rate-Limit-Limit", "60");
                response.Headers.Add("X-Rate-Limit-Remaining", "0");
                response.Headers.Add("X-Rate-Limit-Reset", rateLimitReset.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));
                response.Headers.Date = responseDate ?? DateTimeOffset.UtcNow;
            }

            return response;
        }

        private void SetResponses(params HttpResponseMessage[] responses)
        {
            int index = 0;
            _mockHandler.HandlerFunc = (request, ct) =>
            {
                _sendCount++;
                _sentRequests.Add(request);
                var response = index < responses.Length ? responses[index++] : Make200();
                return Task.FromResult(response);
            };
        }

        public void Dispose()
        {
            _mockHandler.Dispose();
            GC.SuppressFinalize(this);
        }

        [Fact]
        public async Task NoRetry_On200()
        {
            SetResponses(Make200());

            await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.Equal(1, _sendCount);
        }

        [Fact]
        public async Task RetriesOnce_WhenFirst429_ThenSucceeds()
        {
            SetResponses(Make429(), Make200());

            var result = await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.Equal(2, _sendCount);
            Assert.True(result.IsSuccess);
        }

        [Fact]
        public async Task RetriesUpToDefault_WhenAll429_ReturnsFailure()
        {
            // Default max is 3 retries = 4 total sends
            SetResponses(Make429(), Make429(), Make429(), Make429());

            var result = await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.Equal(4, _sendCount);
            Assert.False(result.IsSuccess);
            Assert.Equal(HttpStatusCode.TooManyRequests, result.StatusCode);
        }

        [Fact]
        public async Task StopsRetrying_AfterMaxExhausted()
        {
            // 5 x 429 but default max is 3 retries — should stop after 4 sends
            SetResponses(Make429(), Make429(), Make429(), Make429(), Make429());

            var result = await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.Equal(4, _sendCount);
            Assert.False(result.IsSuccess);
        }

        [Fact]
        public async Task RetriesSuccessfully_WhenFirst429HasRetryAfterHeader()
        {
            SetResponses(Make429(retryAfterSeconds: 0), Make200());

            var result = await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.Equal(2, _sendCount);
            Assert.True(result.IsSuccess);
        }

        [Fact]
        public async Task ApiRateLimit_ParsedOnFinal429_WhenRetryExhausted()
        {
            // Use Retry-After: 0 to avoid real delays; include rate-limit headers for metadata verification
            var resetEpoch = DateTimeOffset.UtcNow.AddSeconds(5).ToUnixTimeSeconds();
            var responseDate = DateTimeOffset.UtcNow;
            SetResponses(
                Make429(retryAfterSeconds: 0, rateLimitReset: (int)resetEpoch, responseDate: responseDate),
                Make429(retryAfterSeconds: 0, rateLimitReset: (int)resetEpoch, responseDate: responseDate),
                Make429(retryAfterSeconds: 0, rateLimitReset: (int)resetEpoch, responseDate: responseDate),
                Make429(retryAfterSeconds: 0, rateLimitReset: (int)resetEpoch, responseDate: responseDate));

            var result = await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.False(result.IsSuccess);
            Assert.NotNull(result.RateLimit);
            Assert.Equal(0, result.RateLimit!.Remaining);
        }

        [Fact]
        public async Task PerRequestDoNotRetry_Returns429Immediately()
        {
            SetResponses(Make429(), Make200());

            var apiRequest = new TestApiRequest(new Uri("https://example.com"));
            apiRequest.Retry = ApiRetry.DoNotRetry;

            var result = await _client.SendAsync<object>(apiRequest);

            Assert.Equal(1, _sendCount);
            Assert.False(result.IsSuccess);
            Assert.Equal(HttpStatusCode.TooManyRequests, result.StatusCode);
        }

        [Fact]
        public async Task PerRequestRetry1_RetriesOnce()
        {
            SetResponses(Make429(), Make429(), Make200());

            var apiRequest = new TestApiRequest(new Uri("https://example.com"));
            apiRequest.Retry = ApiRetry.Retry(1);

            var result = await _client.SendAsync<object>(apiRequest);

            Assert.Equal(2, _sendCount);
            Assert.False(result.IsSuccess); // 2nd 429, max 1 retry
        }

        [Fact]
        public async Task PerRequestRetry_TakesPrecedenceOverRetryHandler()
        {
            SetResponses(Make429(), Make200());

            // Retry handler says retry 5 times, but per-request says don't retry
            _client.AddRetryHandler(new CallbackRetryHandler(shouldRetry: (_, _, _, _) => ApiRetry.Retry(5)));

            var apiRequest = new TestApiRequest(new Uri("https://example.com"));
            apiRequest.Retry = ApiRetry.DoNotRetry;

            var result = await _client.SendAsync<object>(apiRequest);

            Assert.Equal(1, _sendCount);
            Assert.False(result.IsSuccess);
        }

        [Fact]
        public async Task RetryHandler_DoNotRetry_Returns429Immediately()
        {
            SetResponses(Make429(), Make200());

            _client.AddRetryHandler(new CallbackRetryHandler(shouldRetry: (_, _, _, _) => ApiRetry.DoNotRetry));

            var result = await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.Equal(1, _sendCount);
            Assert.False(result.IsSuccess);
        }

        [Fact]
        public async Task RetryHandler_Retry5_AllowsUpTo5Retries()
        {
            // 3 x 429 then 200 — handler allows 5, so it retries through all 429s
            SetResponses(Make429(), Make429(), Make429(), Make200());

            _client.AddRetryHandler(new CallbackRetryHandler(shouldRetry: (_, _, _, _) => ApiRetry.Retry(5)));

            var result = await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.Equal(4, _sendCount);
            Assert.True(result.IsSuccess);
        }

        [Fact]
        public async Task RetryHandler_ReturnsNull_DefersToBuiltInDefault()
        {
            SetResponses(Make429(), Make200());

            _client.AddRetryHandler(new CallbackRetryHandler(shouldRetry: (_, _, _, _) => null));

            var result = await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            // Built-in default (3 retries) applies — retried once, succeeded
            Assert.Equal(2, _sendCount);
            Assert.True(result.IsSuccess);
        }

        [Fact]
        public async Task FirstNonNullRetryHandler_Wins()
        {
            SetResponses(Make429(), Make200());

            _client.AddRetryHandler(new CallbackRetryHandler(shouldRetry: (_, _, _, _) => null));         // defers
            _client.AddRetryHandler(new CallbackRetryHandler(shouldRetry: (_, _, _, _) => ApiRetry.DoNotRetry)); // wins
            _client.AddRetryHandler(new CallbackRetryHandler(shouldRetry: (_, _, _, _) => ApiRetry.Retry(5)));   // never reached

            var result = await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.Equal(1, _sendCount);
            Assert.False(result.IsSuccess);
        }

        [Fact]
        public async Task RetryAttempts_IncludeRetryCountHeader()
        {
            SetResponses(Make429(), Make429(), Make200());

            await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            // First request: no retry headers
            Assert.False(_sentRequests[0].Headers.Contains("X-Okta-Retry-Count"));

            // Second request (first retry): count = 1
            Assert.Equal("1", _sentRequests[1].Headers.GetValues("X-Okta-Retry-Count").First());

            // Third request (second retry): count = 2
            Assert.Equal("2", _sentRequests[2].Headers.GetValues("X-Okta-Retry-Count").First());
        }

        [Fact]
        public async Task RetryAttempts_IncludeRetryForHeader_WhenRequestIdPresent()
        {
            int localCount = 0;
            _mockHandler.HandlerFunc = (request, ct) =>
            {
                _sendCount++;
                _sentRequests.Add(request);
                localCount++;
                if (localCount == 1)
                {
                    var r = Make429();
                    r.Headers.Add("X-Request-Id", "original-req-id");
                    return Task.FromResult(r);
                }

                return Task.FromResult(Make200());
            };

            await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.Equal("original-req-id", _sentRequests[1].Headers.GetValues("X-Okta-Retry-For").First());
        }

        [Fact]
        public async Task NoRetryHeaders_OnFirstAttempt()
        {
            SetResponses(Make200());

            await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.False(_sentRequests[0].Headers.Contains("X-Okta-Retry-Count"));
            Assert.False(_sentRequests[0].Headers.Contains("X-Okta-Retry-For"));
        }

        [Fact]
        public void ApiRateLimit_TryParse_ReturnsNull_WhenHeadersMissing()
        {
            var headers = new HttpResponseMessage().Headers;
            var result = ApiRateLimit.TryParse(headers, DateTimeOffset.UtcNow);
            Assert.Null(result);
        }

        [Fact]
        public void ApiRateLimit_TryParse_ParsesOktaHeaders()
        {
            var resetTime = DateTimeOffset.UtcNow.AddSeconds(10);
            var response = new HttpResponseMessage();
            response.Headers.Add("X-Rate-Limit-Limit", "60");
            response.Headers.Add("X-Rate-Limit-Remaining", "0");
            response.Headers.Add("X-Rate-Limit-Reset", resetTime.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture));

            var result = ApiRateLimit.TryParse(response.Headers, DateTimeOffset.UtcNow);

            Assert.NotNull(result);
            Assert.Equal(60, result!.Limit);
            Assert.Equal(0, result.Remaining);
            Assert.NotNull(result.Delay);
            Assert.True(result.Delay!.Value.TotalSeconds >= 1);
        }

        [Fact]
        public void ApiRateLimit_TryParse_RetryAfterHeader_TakesPrecedence()
        {
            var resetTime = DateTimeOffset.UtcNow.AddSeconds(30);
            var response = new HttpResponseMessage();
            response.Headers.Add("Retry-After", "5");
            response.Headers.Add("X-Rate-Limit-Limit", "60");
            response.Headers.Add("X-Rate-Limit-Remaining", "0");
            response.Headers.Add("X-Rate-Limit-Reset", resetTime.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture));

            var result = ApiRateLimit.TryParse(response.Headers, DateTimeOffset.UtcNow);

            Assert.NotNull(result);
            Assert.Equal(TimeSpan.FromSeconds(5), result!.Delay);
        }

        [Fact]
        public void ApiRateLimit_TryParse_NoDelay_WhenRemainingAboveZero()
        {
            var resetTime = DateTimeOffset.UtcNow.AddSeconds(10);
            var response = new HttpResponseMessage();
            response.Headers.Add("X-Rate-Limit-Limit", "60");
            response.Headers.Add("X-Rate-Limit-Remaining", "5");
            response.Headers.Add("X-Rate-Limit-Reset", resetTime.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture));

            var result = ApiRateLimit.TryParse(response.Headers, DateTimeOffset.UtcNow);

            Assert.NotNull(result);
            Assert.Null(result!.Delay);
        }
    }

    /// <summary>
    /// Minimal concrete ApiRequest subclass for testing per-request Retry property.
    /// </summary>
    internal sealed class TestApiRequest : ApiRequest<object>
    {
        public TestApiRequest(Uri uri)
        {
            Method = HttpMethod.Get;
            Url = uri;
        }
    }
}
