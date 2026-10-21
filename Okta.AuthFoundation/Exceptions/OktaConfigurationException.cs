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

namespace Okta.AuthFoundation.Exceptions
{
    /// <summary>The exception thrown when an Okta SDK configuration is missing, invalid, or incomplete.</summary>
    public class OktaConfigurationException : Exception
    {
        /// <summary>Initializes a new instance of <see cref="OktaConfigurationException"/> with no message.</summary>
        public OktaConfigurationException()
            : base()
        {
        }

        /// <summary>Initializes a new instance of <see cref="OktaConfigurationException"/> with the specified message.</summary>
        /// <param name="message">The message that describes the error.</param>
        public OktaConfigurationException(string message)
            : base(message)
        {
        }

        /// <summary>Initializes a new instance of <see cref="OktaConfigurationException"/> with the specified message and inner exception.</summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public OktaConfigurationException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        internal static OktaConfigurationException DefaultFileNotFound() =>
            new("Okta.json was not found in the current directory or any parent directory.");

        internal static OktaConfigurationException CannotReadFile(string path, Exception inner) =>
            new($"Cannot read configuration file '{path}'.", inner);

        internal static OktaConfigurationException InvalidJson(string path, Exception inner) =>
            new($"Failed to parse configuration file '{path}'.", inner);

        internal static OktaConfigurationException MissingRequiredField(string fieldName) =>
            new($"Required configuration field '{fieldName}' is missing or empty.");

        internal static OktaConfigurationException InvalidFieldValue(string fieldName, string? value) =>
            new($"Configuration field '{fieldName}' has an invalid value: '{value}'.");

        internal static OktaConfigurationException MissingFieldForFlow(string fieldName, string flowName) =>
            new($"'{fieldName}' is required for {flowName} but was not set in the configuration.");
    }
}
