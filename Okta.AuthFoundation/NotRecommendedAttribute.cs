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

namespace Okta.AuthFoundation
{
    /// <summary>
    /// Marks an API as not recommended for new usage. This attribute is informational only —
    /// it does <b>not</b> produce a compiler warning and does <b>not</b> imply the API will
    /// be removed in a future version. The marked API remains fully supported for consumers
    /// that need it (typically for legacy compatibility).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Use <see cref="NotRecommendedAttribute"/> when a better alternative exists (usually
    /// for security or standards-alignment reasons) but the marked API must remain in the
    /// public surface. For APIs that will be removed in a future version, use
    /// <see cref="ObsoleteAttribute"/> instead.
    /// </para>
    /// <para>
    /// The <see cref="Message"/> and optional <see cref="Url"/> surface in generated API
    /// documentation (via XML doc tooling) and in IDE tooltips that read attribute metadata.
    /// </para>
    /// </remarks>
    [AttributeUsage(
        AttributeTargets.Class | AttributeTargets.Struct | AttributeTargets.Interface |
        AttributeTargets.Method | AttributeTargets.Constructor | AttributeTargets.Property |
        AttributeTargets.Field | AttributeTargets.Event | AttributeTargets.Delegate | AttributeTargets.Enum,
        AllowMultiple = false,
        Inherited = false)]
    public sealed class NotRecommendedAttribute : Attribute
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="NotRecommendedAttribute"/> class.
        /// </summary>
        /// <param name="message">A human-readable reason and suggested alternative.</param>
        public NotRecommendedAttribute(string message)
        {
            Message = message;
        }

        /// <summary>
        /// Gets the reason the API is not recommended, and the suggested alternative.
        /// </summary>
        public string Message { get; }

        /// <summary>
        /// Gets or sets an optional URL to documentation explaining the recommendation.
        /// </summary>
        public string? Url { get; set; }
    }
}
