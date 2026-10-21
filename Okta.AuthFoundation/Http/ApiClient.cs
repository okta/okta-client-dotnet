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

using System;
using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Okta.AuthFoundation.Http
{
    /// <summary>
    /// Provides an abstract base implementation for API clients that communicate with HTTP-based services.
    /// </summary>
    public abstract class ApiClient
    {
        private readonly HttpClient _client;
        private readonly object _interceptorLock = new();
        private readonly object _retryHandlerLock = new();
        private readonly ILogger<ApiClient> _logger = OktaServices.Resolve<ILogger<ApiClient>>();
        private readonly ITimeCoordinator _timeCoordinator;
        private volatile List<Func<HttpRequestMessage, Task>> _interceptors = new();
        private volatile List<IApiRetryHandler> _retryHandlers = new();

        /// <summary>
        /// Gets the base URL for the API endpoint.
        /// </summary>
        public Uri BaseUrl { get; }

        /// <summary>
        /// Gets the <see cref="HttpClient"/> instance used for making HTTP requests.
        /// Exposed for advanced scenarios (e.g., custom request pipelines). SDK-level interceptors
        /// and retry logic are bypassed when using this property directly.
        /// </summary>
        public HttpClient Client => _client;

        /// <summary>
        /// Initializes a new instance of the <see cref="ApiClient"/> class.
        /// </summary>
        /// <param name="baseUrl">The base URL for the API endpoint.</param>
        /// <param name="httpClient">The HTTP client to use for requests.</param>
        /// <param name="timeCoordinator">Optional time coordinator. Defaults to the registered <see cref="ITimeCoordinator"/>.</param>
        protected ApiClient(Uri baseUrl, HttpClient httpClient, ITimeCoordinator? timeCoordinator = null)
        {
            BaseUrl = baseUrl ?? throw new ArgumentNullException(nameof(baseUrl));
            _client = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _timeCoordinator = timeCoordinator ?? OktaServices.Resolve<ITimeCoordinator>();
            ConfigureDefaultHeaders(_client);
        }

        /// <summary>
        /// Registers an asynchronous interceptor that is invoked before each request is sent.
        /// Use this to mutate the request (e.g., add authentication headers).
        /// </summary>
        /// <param name="interceptor">The interceptor to register.</param>
        public void AddRequestInterceptor(Func<HttpRequestMessage, Task> interceptor)
        {
            ArgumentNullException.ThrowIfNull(interceptor);
            lock (_interceptorLock)
            {
                var copy = new List<Func<HttpRequestMessage, Task>>(_interceptors) { interceptor };
                _interceptors = copy;
            }
        }

        /// <summary>
        /// Unregisters a previously added interceptor. If the interceptor is not found, this is a no-op.
        /// </summary>
        /// <param name="interceptor">The interceptor to unregister.</param>
        public void RemoveRequestInterceptor(Func<HttpRequestMessage, Task> interceptor)
        {
            ArgumentNullException.ThrowIfNull(interceptor);
            lock (_interceptorLock)
            {
                var copy = new List<Func<HttpRequestMessage, Task>>(_interceptors);
                copy.Remove(interceptor);
                _interceptors = copy;
            }
        }

        /// <summary>
        /// Raised once before a request is sent, after all interceptors have run.
        /// </summary>
        public event EventHandler<WillSendEventArgs>? WillSend;

        /// <summary>
        /// Raised once after the final response is received (after all retries complete).
        /// </summary>
        public event EventHandler<DidSendEventArgs>? DidSend;

        /// <summary>
        /// Registers a handler to customize retry behavior on HTTP 429 responses.
        /// </summary>
        /// <param name="handler">The retry handler to register.</param>
        public void AddRetryHandler(IApiRetryHandler handler)
        {
            ArgumentNullException.ThrowIfNull(handler);
            lock (_retryHandlerLock)
            {
                if (_retryHandlers.Contains(handler))
                {
                    return;
                }

                var copy = new List<IApiRetryHandler>(_retryHandlers) { handler };
                _retryHandlers = copy;
            }
        }

        /// <summary>
        /// Unregisters a previously added retry handler. If the handler is not found, this is a no-op.
        /// </summary>
        /// <param name="handler">The retry handler to unregister.</param>
        public void RemoveRetryHandler(IApiRetryHandler handler)
        {
            ArgumentNullException.ThrowIfNull(handler);
            lock (_retryHandlerLock)
            {
                var copy = new List<IApiRetryHandler>(_retryHandlers);
                copy.Remove(handler);
                _retryHandlers = copy;
            }
        }

        /// <summary>
        /// Sends an HTTP request asynchronously and deserializes the response.
        /// Automatically retries on HTTP 429 responses according to the configured retry policy.
        /// </summary>
        /// <typeparam name="TResponse">The type to deserialize the response body into.</typeparam>
        /// <param name="requestMessage">The HTTP request message to send.</param>
        /// <param name="cancellationToken">The cancellation token to observe.</param>
        /// <returns>
        /// An <see cref="ApiResponse{TResponse}"/> containing the deserialized result and response metadata.
        /// </returns>
        /// <exception cref="HttpRequestException">Thrown when the HTTP request fails at the network level.</exception>
        public virtual async Task<ApiResponse<TResponse>> SendAsync<TResponse>(HttpRequestMessage requestMessage, CancellationToken cancellationToken = default)
        {
            await ApplyRequestInterceptorsAsync(requestMessage).ConfigureAwait(false);

            WillSend?.Invoke(this, new WillSendEventArgs(requestMessage));

            // Buffer body bytes so the content can be replayed across attempts.
            // HttpRequestMessage can only be sent once; a fresh clone is used for every attempt
            // to avoid mutating the caller-supplied requestMessage.
            byte[]? bodyBytes = null;
            List<KeyValuePair<string, IEnumerable<string>>>? contentHeaders = null;
            if (requestMessage.Content != null)
            {
                bodyBytes = await requestMessage.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
                contentHeaders = requestMessage.Content.Headers.ToList();
            }

            int retryCount = 0;
            string? originalRequestId = null;
            ApiRateLimit? lastRateLimit = null;

            while (true)
            {
                var attemptRequest = CloneRequest(requestMessage, bodyBytes, contentHeaders);
                if (retryCount > 0)
                {
                    if (originalRequestId != null)
                    {
                        attemptRequest.Headers.TryAddWithoutValidation("X-Okta-Retry-For", originalRequestId);
                    }

                    attemptRequest.Headers.TryAddWithoutValidation("X-Okta-Retry-Count", retryCount.ToString(System.Globalization.CultureInfo.InvariantCulture));
                }

                HttpResponseMessage response;
                try
                {
                    response = await Client.SendAsync(attemptRequest, cancellationToken).ConfigureAwait(false);
                }
                catch (HttpRequestException ex)
                {
                    _logger.LogWarning(ex, "Network request to '{Url}' failed.", requestMessage.RequestUri);
                    attemptRequest.Dispose();
                    throw;
                }

                using (response)
                {
                    if (response.Headers.Date is { } serverDate)
                    {
                        _timeCoordinator.Observe(serverDate);
                    }

                    lastRateLimit = ApiRateLimit.TryParse(response.Headers, new DateTimeOffset(_timeCoordinator.Now));

                    if (response.StatusCode == HttpStatusCode.TooManyRequests)
                    {
                        var retryPolicy = GetEffectiveRetry(requestMessage, retryCount, lastRateLimit);

                        if (retryCount < retryPolicy.MaximumCount)
                        {
                            originalRequestId ??= response.Headers.TryGetValues("X-Request-Id", out var ridValues)
                                ? ridValues.FirstOrDefault()
                                : null;

                            retryCount++;
                            var delay = GetRetryDelay(response, lastRateLimit);
                            attemptRequest.Dispose();
                            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                            continue;
                        }
                    }

                    DidSend?.Invoke(this, new DidSendEventArgs(requestMessage, response));

                    return await DeserializeResponseAsync<TResponse>(response, lastRateLimit).ConfigureAwait(false);
                }
            }
        }

        /// <summary>
        /// Invokes all registered request interceptors in order.
        /// </summary>
        /// <param name="request">The HTTP request message to pass to each interceptor.</param>
        protected virtual async Task ApplyRequestInterceptorsAsync(HttpRequestMessage request)
        {
            foreach (var interceptor in _interceptors)
            {
                await interceptor(request).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Deserializes the HTTP response message into an <see cref="ApiResponse{TResponse}"/> object.
        /// </summary>
        /// <typeparam name="TResponse">The type to deserialize the response body into.</typeparam>
        /// <param name="response">The HTTP response message to deserialize.</param>
        /// <param name="rateLimit">The rate limit information parsed from the response headers, if available.</param>
        /// <returns>An <see cref="ApiResponse{TResponse}"/> containing the deserialized result and response metadata.</returns>
        protected virtual async Task<ApiResponse<TResponse>> DeserializeResponseAsync<TResponse>(HttpResponseMessage response, ApiRateLimit? rateLimit = null)
        {
            var requestId = response.Headers.TryGetValues("X-Request-Id", out var ridValues) ? ridValues.FirstOrDefault() : null;
            var date = _timeCoordinator.Now;
            var links = ParseLinkHeader(response);

            if (response.IsSuccessStatusCode)
            {
                TResponse? result;

                if (typeof(TResponse) == typeof(Empty) || response.Content.Headers.ContentLength == 0)
                {
                    result = default;
                }
                else
                {
                    var responseBody = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
                    result = await JsonSerializer.DeserializeAsync<TResponse>(responseBody);
                }

                return ApiResponse<TResponse>.Success(result, response.StatusCode, requestId, date, links, rateLimit);
            }

            var errorMessage = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            return ApiResponse<TResponse>.Failure(errorMessage, response.StatusCode, requestId, date, links, rateLimit);
        }

        private static HttpRequestMessage CloneRequest(
            HttpRequestMessage original,
            byte[]? bodyBytes,
            List<KeyValuePair<string, IEnumerable<string>>>? contentHeaders)
        {
            var clone = new HttpRequestMessage(original.Method, original.RequestUri)
            {
                Version = original.Version,
                VersionPolicy = original.VersionPolicy,
            };

            foreach (var header in original.Headers)
            {
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            if (bodyBytes != null && contentHeaders != null)
            {
                clone.Content = CreateContent(bodyBytes, contentHeaders);
            }

            foreach (var option in original.Options)
            {
                clone.Options.Set(new HttpRequestOptionsKey<object?>(option.Key), option.Value);
            }

            return clone;
        }

        private static ByteArrayContent CreateContent(byte[] bytes, List<KeyValuePair<string, IEnumerable<string>>> headers)
        {
            var content = new ByteArrayContent(bytes);
            foreach (var header in headers)
            {
                content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            return content;
        }

        private static Dictionary<string, string> ParseLinkHeader(HttpResponseMessage response)
        {
            var links = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (!response.Headers.TryGetValues("Link", out var linkValues))
            {
                return links;
            }

            foreach (var header in linkValues)
            {
                foreach (var entry in header.Split(',', StringSplitOptions.TrimEntries))
                {
                    var parts = entry.Split(';', StringSplitOptions.TrimEntries);
                    if (parts.Length < 2)
                    {
                        continue;
                    }

                    var url = parts[0].Trim('<', '>');
                    foreach (var param in parts.Skip(1))
                    {
                        var trimmed = param.Trim();
                        if (trimmed.StartsWith("rel=", StringComparison.OrdinalIgnoreCase))
                        {
                            var rel = trimmed[4..].Trim('"');
                            links[rel] = url;
                        }
                    }
                }
            }

            return links;
        }

        private static void ConfigureDefaultHeaders(HttpClient client)
        {
            var sdkUserAgent = UserAgent.HeaderValue;
            var existing = client.DefaultRequestHeaders.UserAgent;

            if (existing.ToString().Contains(sdkUserAgent))
            {
                return;
            }

            existing.ParseAdd(sdkUserAgent);
        }

        private TimeSpan GetRetryDelay(HttpResponseMessage response, ApiRateLimit? rateLimit)
        {
            if (rateLimit?.Delay is { } rlDelay)
            {
                return rlDelay;
            }

            if (response.Headers.RetryAfter?.Delta is { } delta)
            {
                return delta;
            }

            if (response.Headers.RetryAfter?.Date is { } retryDate)
            {
                var computed = retryDate - new DateTimeOffset(_timeCoordinator.Now);
                return computed > TimeSpan.Zero ? computed : TimeSpan.Zero;
            }

            return TimeSpan.FromSeconds(1);
        }

        private ApiRetry GetEffectiveRetry(HttpRequestMessage request, int retryCount, ApiRateLimit? rateLimit)
        {
            if (request is ApiRequest apiRequest && apiRequest.Retry is { } perRequestPolicy)
            {
                return perRequestPolicy;
            }

            foreach (var handler in _retryHandlers)
            {
                var policy = handler.ShouldRetry(this, request, retryCount, rateLimit);
                if (policy != null)
                {
                    return policy;
                }
            }

            return ApiRetry.Default;
        }
    }
}
