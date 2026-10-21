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
    internal sealed class CallbackRetryHandler : IApiRetryHandler
    {
        private readonly Func<ApiClient, HttpRequestMessage, int, ApiRateLimit?, ApiRetry?>? _shouldRetry;

        public CallbackRetryHandler(
            Func<ApiClient, HttpRequestMessage, int, ApiRateLimit?, ApiRetry?>? shouldRetry = null)
        {
            _shouldRetry = shouldRetry;
        }

        public ApiRetry? ShouldRetry(ApiClient client, HttpRequestMessage request, int retryCount, ApiRateLimit? rateLimit)
            => _shouldRetry?.Invoke(client, request, retryCount, rateLimit);
    }

    /// <summary>
    /// Minimal concrete subclass of ApiClient for testing base class behavior.
    /// </summary>
    internal sealed class TestApiClient : ApiClient
    {
        public TestApiClient(HttpClient httpClient, ITimeCoordinator? timeCoordinator = null)
            : base(new Uri("https://example.com"), httpClient, timeCoordinator)
        {
        }
    }

    public class ApiClientTests : IDisposable
    {
        private readonly TestHttpMessageHandler _mockHandler;
        private readonly HttpClient _httpClient;
        private readonly TestApiClient _client;
        private readonly DefaultTimeCoordinator _timeCoordinator;

        public ApiClientTests()
        {
            _mockHandler = new TestHttpMessageHandler((request, cancellationToken) =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{}"),
                }));
            _httpClient = new HttpClient(_mockHandler);
            _timeCoordinator = new DefaultTimeCoordinator();
            _client = new TestApiClient(_httpClient, _timeCoordinator);
        }

        public void Dispose()
        {
            _httpClient.Dispose();
            _mockHandler.Dispose();
            GC.SuppressFinalize(this);
        }

        [Fact]
        public async Task AddRequestInterceptor_ModifiesRequestBeforeSending()
        {
            HttpRequestMessage? capturedRequest = null;
            _mockHandler.HandlerFunc = (request, ct) =>
            {
                capturedRequest = request;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{}"),
                });
            };

            _client.AddRequestInterceptor(async request =>
            {
                request.Headers.Add("X-Custom", "intercepted");
                await Task.CompletedTask;
            });

            await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.NotNull(capturedRequest);
            Assert.Equal("intercepted", capturedRequest.Headers.GetValues("X-Custom").First());
        }

        [Fact]
        public async Task AddRequestInterceptor_MultipleInterceptors_RunInOrder()
        {
            var order = new List<int>();

            _client.AddRequestInterceptor(async request =>
            {
                order.Add(1);
                await Task.CompletedTask;
            });
            _client.AddRequestInterceptor(async request =>
            {
                order.Add(2);
                await Task.CompletedTask;
            });
            _client.AddRequestInterceptor(async request =>
            {
                order.Add(3);
                await Task.CompletedTask;
            });

            await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.Equal([1, 2, 3], order);
        }

        [Fact]
        public void AddRequestInterceptor_ThrowsOnNull()
        {
            Assert.Throws<ArgumentNullException>(() => _client.AddRequestInterceptor(null!));
        }

        [Fact]
        public async Task RemoveRequestInterceptor_RemovedInterceptor_DoesNotRun()
        {
            bool interceptorRan = false;
            Func<HttpRequestMessage, Task> interceptor = request =>
            {
                interceptorRan = true;
                return Task.CompletedTask;
            };

            _client.AddRequestInterceptor(interceptor);
            _client.RemoveRequestInterceptor(interceptor);

            await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.False(interceptorRan);
        }

        [Fact]
        public async Task RemoveRequestInterceptor_OnlyRemovesMatchingInterceptor()
        {
            var order = new List<int>();
            Func<HttpRequestMessage, Task> interceptor1 = request =>
            {
                order.Add(1);
                return Task.CompletedTask;
            };
            Func<HttpRequestMessage, Task> interceptor2 = request =>
            {
                order.Add(2);
                return Task.CompletedTask;
            };
            Func<HttpRequestMessage, Task> interceptor3 = request =>
            {
                order.Add(3);
                return Task.CompletedTask;
            };

            _client.AddRequestInterceptor(interceptor1);
            _client.AddRequestInterceptor(interceptor2);
            _client.AddRequestInterceptor(interceptor3);
            _client.RemoveRequestInterceptor(interceptor2);

            await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.Equal([1, 3], order);
        }

        [Fact]
        public void RemoveRequestInterceptor_InterceptorNotRegistered_IsNoOp()
        {
            Func<HttpRequestMessage, Task> interceptor = request => Task.CompletedTask;
            var ex = Record.Exception(() => _client.RemoveRequestInterceptor(interceptor));
            Assert.Null(ex);
        }

        [Fact]
        public void RemoveRequestInterceptor_ThrowsOnNull()
        {
            Assert.Throws<ArgumentNullException>(() => _client.RemoveRequestInterceptor(null!));
        }

        [Fact]
        public async Task AddRequestInterceptor_AsyncInterceptorAwaited()
        {
            bool interceptorCompleted = false;

            _client.AddRequestInterceptor(async request =>
            {
                await Task.Delay(50);
                interceptorCompleted = true;
            });

            _mockHandler.HandlerFunc = (request, ct) =>
            {
                Assert.True(interceptorCompleted);
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{}"),
                });
            };

            await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.True(interceptorCompleted);
        }

        [Fact]
        public async Task WillSend_Event_FiresBeforeHttpSend()
        {
            HttpRequestMessage? eventRequest = null;
            bool willSendFiredBeforeHttp = false;

            _mockHandler.HandlerFunc = (request, ct) =>
            {
                willSendFiredBeforeHttp = eventRequest != null;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{}"),
                });
            };

            _client.WillSend += (sender, e) => eventRequest = e.Request;

            await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.True(willSendFiredBeforeHttp);
            Assert.NotNull(eventRequest);
        }

        [Fact]
        public async Task DidSend_Event_FiresAfterHttpSend()
        {
            HttpRequestMessage? eventRequest = null;
            HttpStatusCode? eventStatusCode = null;

            _client.DidSend += (sender, e) =>
            {
                eventRequest = e.Request;
                eventStatusCode = e.StatusCode;
            };

            await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.NotNull(eventRequest);
            Assert.Equal(HttpStatusCode.OK, eventStatusCode);
        }

        [Fact]
        public async Task WillSend_Event_FiresAfterInterceptors()
        {
            bool interceptorRan = false;
            bool interceptorRanBeforeWillSend = false;

            _client.AddRequestInterceptor(async request =>
            {
                interceptorRan = true;
                await Task.CompletedTask;
            });
            _client.WillSend += (sender, e) =>
            {
                interceptorRanBeforeWillSend = interceptorRan;
            };

            await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.True(interceptorRanBeforeWillSend);
        }

        [Fact]
        public void AddRetryHandler_ThrowsOnNull()
        {
            Assert.Throws<ArgumentNullException>(() => _client.AddRetryHandler(null!));
        }

        [Fact]
        public async Task Response_IncludesRequestId()
        {
            _mockHandler.HandlerFunc = (request, ct) =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{}"),
                };
                response.Headers.Add("X-Request-Id", "req-12345");
                return Task.FromResult(response);
            };

            var result = await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.Equal("req-12345", result.RequestId);
        }

        [Fact]
        public async Task Response_RequestId_IsNull_WhenHeaderMissing()
        {
            var result = await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.Null(result.RequestId);
        }

        [Fact]
        public async Task Response_IncludesServerDate()
        {
            var serverDate = new DateTimeOffset(2025, 6, 15, 12, 0, 0, TimeSpan.Zero);
            var handler = new TestHttpMessageHandler((request, ct) =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{}"),
                };
                response.Headers.Date = serverDate;
                return Task.FromResult(response);
            });
            var localCoordinator = new DefaultTimeCoordinator();
            var client = new TestApiClient(new HttpClient(handler), localCoordinator);

            var result = await client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.InRange(result.Date, serverDate.UtcDateTime.AddSeconds(-1), serverDate.UtcDateTime.AddSeconds(1));
        }

        [Fact]
        public async Task Response_ParsesLinkHeader()
        {
            _mockHandler.HandlerFunc = (request, ct) =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{}"),
                };
                response.Headers.Add("Link", @"<https://example.com/api?after=abc>; rel=""next"", <https://example.com/api>; rel=""self""");
                return Task.FromResult(response);
            };

            var result = await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.Equal(2, result.Links.Count);
            Assert.Equal("https://example.com/api?after=abc", result.Links["next"]);
            Assert.Equal("https://example.com/api", result.Links["self"]);
        }

        [Fact]
        public async Task Response_Links_IsEmpty_WhenNoLinkHeader()
        {
            var result = await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.NotNull(result.Links);
            Assert.Empty(result.Links);
        }

        [Fact]
        public async Task Response_IncludesMetadata_OnFailure()
        {
            _mockHandler.HandlerFunc = (request, ct) =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent("bad request"),
                };
                response.Headers.Add("X-Request-Id", "req-fail");
                response.Headers.Add("Link", @"<https://example.com/help>; rel=""help""");
                return Task.FromResult(response);
            };

            var result = await _client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.False(result.IsSuccess);
            Assert.Equal("req-fail", result.RequestId);
            Assert.Equal("https://example.com/help", result.Links["help"]);
            Assert.Contains("bad request", result.ErrorMessage);
        }

        [Fact]
        public async Task SendAsync_ResponseWithDateHeader_UpdatesTimeCoordinator()
        {
            var timeCoordinator = new DefaultTimeCoordinator();
            var serverDate = DateTimeOffset.UtcNow.AddMinutes(5);
            _mockHandler.HandlerFunc = (request, ct) =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{}"),
                };
                response.Headers.Date = serverDate;
                return Task.FromResult(response);
            };

            var client = new TestApiClient(new HttpClient(_mockHandler), timeCoordinator);
            await client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.InRange(timeCoordinator.Offset.TotalMinutes, 4.5, 5.5);
        }

        [Fact]
        public async Task SendAsync_ResponseWithoutDateHeader_DoesNotUpdateTimeCoordinator()
        {
            var timeCoordinator = new DefaultTimeCoordinator();
            _mockHandler.HandlerFunc = (request, ct) =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{}"),
                };
                return Task.FromResult(response);
            };

            var client = new TestApiClient(new HttpClient(_mockHandler), timeCoordinator);
            await client.SendAsync<object>(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));

            Assert.Equal(TimeSpan.Zero, timeCoordinator.Offset);
        }
    }
}