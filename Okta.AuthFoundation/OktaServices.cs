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

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Okta.AuthFoundation.JwtSecurity;
using Okta.AuthFoundation.OAuth2;
using Okta.AuthFoundation.TokenManagement;

namespace Okta.AuthFoundation
{
    /// <summary>
    /// SDK-internal service registry providing default implementations for all services.
    /// Built on <see cref="ServiceCollection"/>/<see cref="IServiceProvider"/>.
    /// Consumers can swap defaults without configuring an external DI container.
    /// </summary>
    public static class OktaServices
    {
        internal const string HttpClientName = "default";

        // Services that are internal SDK infrastructure and cannot be replaced by consumers.
        private static readonly HashSet<Type> _lockedServices = new() { typeof(ICredentialCoordinator) };

        private static ServiceCollection _services = new();

        // Lazy<T> handles thread-safe one-time construction on first Resolve() call.
        // Registrations are only made at app startup before any concurrent access.
        private static Lazy<ServiceProvider> _provider = new(() => _services.BuildServiceProvider());

        static OktaServices()
        {
            RegisterDefaults();
        }

        private static void RegisterDefaults()
        {
            _services.AddSingleton<ITimeCoordinator, DefaultTimeCoordinator>();
            if (OperatingSystem.IsWindows())
            {
                _services.AddSingleton<ITokenStorage, WindowsEncryptedTokenStorage>();
            }
            else if (OperatingSystem.IsLinux())
            {
                _services.AddSingleton<ITokenStorage, LinuxFileKeyTokenStorage>();
            }
            else
            {
                _services.AddSingleton<ITokenStorage>(_ => throw new PlatformNotSupportedException(
                    "No built-in token storage is available for this platform. " +
                    "Provide a custom implementation via OktaServices.AddSingleton<ITokenStorage>(...)."));
            }

            _services.AddSingleton<ICredentialDataSource, DefaultCredentialDataSource>();
            _services.AddSingleton<ICredentialCoordinator, CredentialCoordinator>();
            _services.AddSingleton<IIdTokenValidator, DefaultIdTokenValidator>();
            _services.AddSingleton<IJwkValidator, DefaultJwkValidator>();
            _services.AddSingleton<ITokenHashValidator, DefaultTokenHashValidator>();
            _services.AddLogging();

            // A named client is required to obtain an IHttpClientBuilder, which is needed
            // to support ConfigureHttpMessageHandler. "default" identifies the SDK's primary client.
            _services.AddHttpClient(HttpClientName);
        }

        private static void RemoveExisting<TService>() => _services.RemoveAll<TService>();

        /// <summary>
        /// Resolves an instance of <typeparamref name="TService"/>.
        /// Singletons return the same instance; transients return a new instance each time.
        /// </summary>
        /// <returns>The resolved <typeparamref name="TService"/> instance.</returns>
        /// <exception cref="InvalidOperationException">No service is registered for <typeparamref name="TService"/>.</exception>
        public static TService Resolve<TService>()
            where TService : class =>
            _provider.Value.GetRequiredService<TService>();

        private static void ThrowIfBuilt()
        {
            if (_provider.IsValueCreated)
            {
                throw new InvalidOperationException(
                    "Services cannot be registered after the first call to Resolve(). " +
                    "Register all service overrides at app startup.");
            }
        }

        private static void ThrowIfLocked<TService>()
        {
            if (_lockedServices.Contains(typeof(TService)))
            {
                throw new InvalidOperationException(
                    $"{typeof(TService).Name} is internal SDK infrastructure and cannot be replaced.");
            }
        }

        /// <summary>
        /// Registers a pre-created instance as the singleton for <typeparamref name="TService"/>.
        /// Replaces any existing registration. Must be called at app startup before first use.
        /// </summary>
        /// <param name="instance">The singleton instance to register.</param>
        public static void AddSingleton<TService>(TService instance)
            where TService : class
        {
            ArgumentNullException.ThrowIfNull(instance);
            ThrowIfBuilt();
            ThrowIfLocked<TService>();
            RemoveExisting<TService>();
            _services.AddSingleton(instance);
        }

        /// <summary>
        /// Registers a factory that will be called once to create the singleton for <typeparamref name="TService"/>.
        /// Replaces any existing registration. Must be called at app startup before first use.
        /// </summary>
        /// <param name="factory">A factory that produces the singleton instance.</param>
        public static void AddSingleton<TService>(Func<TService> factory)
            where TService : class
        {
            ArgumentNullException.ThrowIfNull(factory);
            ThrowIfBuilt();
            ThrowIfLocked<TService>();
            RemoveExisting<TService>();
            _services.AddSingleton<TService>(_ => factory());
        }

        /// <summary>
        /// Registers a factory that will be called on every resolve to create a new <typeparamref name="TService"/>.
        /// Replaces any existing registration. Must be called at app startup before first use.
        /// </summary>
        /// <param name="factory">A factory that produces the transient instance.</param>
        public static void AddTransient<TService>(Func<TService> factory)
            where TService : class
        {
            ArgumentNullException.ThrowIfNull(factory);
            ThrowIfBuilt();
            ThrowIfLocked<TService>();
            RemoveExisting<TService>();
            _services.AddTransient<TService>(_ => factory());
        }

        /// <summary>
        /// Configures the <see cref="System.Net.Http.HttpMessageHandler"/> used by all <see cref="System.Net.Http.HttpClient"/> instances
        /// created internally by the SDK. Use this to configure transport-level settings such as
        /// proxy, TLS configuration, and certificate pinning.
        /// <para>
        /// This affects all <see cref="OAuth2.OAuth2Client"/> instances that do not have an explicit
        /// <see cref="System.Net.Http.HttpClient"/> provided at construction time, including clients created automatically
        /// by <see cref="TokenManagement.CredentialCoordinator"/>.
        /// </para>
        /// <para>
        /// Must be called at app startup before first use.
        /// </para>
        /// </summary>
        /// <param name="handlerFactory">A factory that produces the <see cref="System.Net.Http.HttpMessageHandler"/> to use.</param>
        public static void ConfigureHttpMessageHandler(Func<HttpMessageHandler> handlerFactory)
        {
            ArgumentNullException.ThrowIfNull(handlerFactory);
            ThrowIfBuilt();
            _services.AddHttpClient(HttpClientName).ConfigurePrimaryHttpMessageHandler(handlerFactory);
        }

        private static Func<string, string, IClientAuthentication>? _clientAuthenticationFactory;

        /// <summary>
        /// Registers a factory that resolves an <see cref="IClientAuthentication"/> for credentials
        /// loaded from storage. The factory receives the credential's client ID and the
        /// authentication method name that was recorded when the token was originally minted
        /// (e.g. "ClientSecret", "PrivateKeyJwt"), and returns the corresponding
        /// <see cref="IClientAuthentication"/> instance.
        /// <para>
        /// <see cref="IClientAuthentication"/> instances cannot be serialized to storage —
        /// <see cref="PrivateKeyJwtAuthentication"/> wraps a signing delegate, and
        /// <see cref="ClientSecretAuthentication"/> wraps a secret that should not be persisted
        /// alongside tokens. Apps using confidential client authentication must call this method
        /// at startup so the SDK can rebind the authentication method when reloading credentials.
        /// </para>
        /// <para>
        /// If this method is not called and a credential is loaded that was originally minted
        /// with a non-<see cref="ClientAuthentication.None"/> method, the SDK throws
        /// <see cref="InvalidOperationException"/> at reload time rather than silently
        /// downgrading to no authentication.
        /// </para>
        /// </summary>
        /// <param name="factory">A function that maps (clientId, authenticationMethod) to an <see cref="IClientAuthentication"/>.</param>
        public static void ConfigureClientAuthentication(Func<string, string, IClientAuthentication> factory)
        {
            ArgumentNullException.ThrowIfNull(factory);
            _clientAuthenticationFactory = factory;
        }

        /// <summary>
        /// Resolves the <see cref="IClientAuthentication"/> for a credential being reloaded from storage,
        /// based on the authentication method recorded in its <see cref="TokenManagement.TokenContext"/>.
        /// </summary>
        /// <param name="clientId">The credential's client ID.</param>
        /// <param name="authenticationMethod">The recorded authentication method name, or <c>null</c> if none was recorded.</param>
        /// <returns>The resolved <see cref="IClientAuthentication"/>.</returns>
        /// <exception cref="InvalidOperationException">
        /// Thrown when the recorded method is not <see cref="ClientAuthentication.None"/> but no factory has been registered via
        /// <see cref="ConfigureClientAuthentication"/>.
        /// </exception>
        internal static IClientAuthentication ResolveClientAuthentication(string clientId, string? authenticationMethod)
        {
            // No recorded method, or explicitly None: use the no-op authentication.
            if (string.IsNullOrEmpty(authenticationMethod) || authenticationMethod == ClientAuthentication.None.ToString())
            {
                return new NoneClientAuthentication();
            }

            if (_clientAuthenticationFactory is null)
            {
                throw new InvalidOperationException(
                    $"Cannot reload credential for client '{clientId}': it was originally minted with '{authenticationMethod}' " +
                    $"authentication, but no factory is registered. Call OktaServices.ConfigureClientAuthentication(...) at app startup.");
            }

            return _clientAuthenticationFactory(clientId, authenticationMethod);
        }

        /// <summary>
        /// Clears all registrations and re-registers the SDK defaults. For use in tests only.
        /// </summary>
        internal static void Reset()
        {
            if (_provider.IsValueCreated)
            {
                _provider.Value.Dispose();
            }

            _services = new ServiceCollection();
            _provider = new Lazy<ServiceProvider>(() => _services.BuildServiceProvider());
            _clientAuthenticationFactory = null;
            RegisterDefaults();
        }
    }
}
