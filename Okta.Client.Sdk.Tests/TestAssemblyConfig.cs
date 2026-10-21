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

using Xunit;

// OktaServicesTests calls Reset() in its constructor and Dispose(), which disposes and
// rebuilds the global ServiceProvider. Running it in parallel with other test classes that
// call OktaServices.Resolve() would cause ObjectDisposedException. Services are expected
// to be registered only at startup in production; Reset() is a test-only operation.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
