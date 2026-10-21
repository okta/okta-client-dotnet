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

using System.Runtime.InteropServices;
using Xunit;

namespace Okta.Client.Sdk.Tests
{
    /// <summary>
    /// A custom xUnit <see cref="FactAttribute"/> that runs only when a D-Bus session bus
    /// is reachable on Linux. Skips on non-Linux platforms or when D-Bus is not available
    /// (no DBUS_SESSION_BUS_ADDRESS env var and no $XDG_RUNTIME_DIR/bus socket).
    /// </summary>
    public sealed class KeyringFactAttribute : FactAttribute
    {
        public KeyringFactAttribute()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                Skip = "This test requires Linux.";
                return;
            }

            var busAddr = Environment.GetEnvironmentVariable("DBUS_SESSION_BUS_ADDRESS");
            if (!string.IsNullOrEmpty(busAddr))
            {
                return;
            }

            var runtimeDir = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR");
            if (!string.IsNullOrEmpty(runtimeDir) && File.Exists(Path.Combine(runtimeDir, "bus")))
            {
                return;
            }

            Skip = "This test requires a running D-Bus session bus and a compatible keyring daemon.";
        }
    }
}
