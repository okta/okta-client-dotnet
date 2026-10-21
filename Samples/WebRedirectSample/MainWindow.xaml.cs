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

using Okta.AuthFoundation.Claims;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Windows;
using Okta.AuthFoundation;
using Microsoft.Extensions.Configuration;
using Okta.AuthFoundation.OAuth2;
using Okta.AuthFoundation.TokenManagement;
using Okta.OAuth2;
using Okta.OAuth2.Flows;

namespace Okta.Client.Sdk.Samples.WebRedirect
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private AuthorizationCodeFlow? _authFlow;
        private readonly IConfiguration _configuration;
        private HttpListener? _httpListener;
        private CancellationTokenSource? _cancellationTokenSource;
        private Token? _currentToken;
        private OAuth2Client? _currentClient;
        private Credential? _currentCredential;

        public MainWindow()
        {
            InitializeComponent();

            // Load configuration from appsettings.json
            _configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .Build();

            LoadConfiguration();
        }

        private void LoadConfiguration()
        {
            var oauth2Section = _configuration.GetSection("OAuth2");

            IssuerTextBox.Text = oauth2Section["IssuerUrl"] ?? "https://your-domain.okta.com/oauth2/default";
            ClientIdTextBox.Text = oauth2Section["ClientId"] ?? "your-client-id";
            RedirectUriTextBox.Text = oauth2Section["RedirectUri"] ?? "http://localhost:8080/callback";

            var scopes = oauth2Section.GetSection("Scopes").Get<string[]>();
            ScopesTextBox.Text = scopes != null ? string.Join(" ", scopes) : "openid profile email offline_access";
        }

        private async void StartAuthButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                StartAuthButton.IsEnabled = false;
                LogoutButton.IsEnabled = false;
                CancelButton.IsEnabled = true;
                ResultsTextBox.Text = "Starting authorization flow...\n";

                // Parse configuration
                var issuer = new Uri(IssuerTextBox.Text.Trim());
                var clientId = ClientIdTextBox.Text.Trim();
                var redirectUri = RedirectUriTextBox.Text.Trim();
                var scopes = ScopesTextBox.Text.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();

                // Create OAuth2 client and authorization flow
                var config = new OAuth2ClientConfiguration(issuer, clientId, scopes);
                var client = new OAuth2Client(config);
                _currentClient = client;
                _authFlow = new AuthorizationCodeFlow(client, redirectUri);

                // Start the authorization flow
                var authorizeUrl = await _authFlow.StartAsync();

                ResultsTextBox.Text += $"Authorization URL: {authorizeUrl}\n\n";

                // Start loopback server
                _cancellationTokenSource = new CancellationTokenSource();
                var redirectUriParsed = new Uri(redirectUri);
                var listenerPrefix = $"{redirectUriParsed.Scheme}://{redirectUriParsed.Host}:{redirectUriParsed.Port}/";

                ResultsTextBox.Text += $"Starting loopback server on {listenerPrefix}...\n";

                _httpListener = new HttpListener();
                _httpListener.Prefixes.Add(listenerPrefix);
                _httpListener.Start();

                ResultsTextBox.Text += "Opening browser for authentication...\n\n";

                // Open the system browser
                Process.Start(new ProcessStartInfo
                {
                    FileName = authorizeUrl.ToString(),
                    UseShellExecute = true
                });

                ResultsTextBox.Text += "Waiting for authorization callback...\n";

                // Wait for the callback
                var callbackUri = await WaitForCallbackAsync(redirectUriParsed.AbsolutePath, _cancellationTokenSource.Token);

                if (callbackUri != null)
                {
                    ResultsTextBox.Text += $"\nCallback received: {callbackUri}\n\n";
                    ResultsTextBox.Text += "Exchanging authorization code for tokens...\n";

                    var response = await _authFlow.ResumeAsync(callbackUri);

                    if (response.IsSuccess && response.Result != null)
                    {
                        _currentToken = response.Result;
                        DisplaySuccessfulLogin(_currentToken);
                        LogoutButton.IsEnabled = true;
                        StoreCredentialButton.IsEnabled = true;
                    }
                    else
                    {
                        ResultsTextBox.Text += $"\nAuthentication failed: {response.ErrorMessage}\n";
                    }
                }
            }
            catch (OperationCanceledException)
            {
                ResultsTextBox.Text += "\nAuthorization cancelled by user.\n";
            }
            catch (Exception ex)
            {
                ResultsTextBox.Text += $"\nError: {ex.Message}\n";
                if (ex.InnerException != null)
                {
                    ResultsTextBox.Text += $"Inner: {ex.InnerException.Message}\n";
                }
            }
            finally
            {
                StopLoopbackServer();
                StartAuthButton.IsEnabled = true;
                CancelButton.IsEnabled = false;
            }
        }

        private void DisplaySuccessfulLogin(Token token)
        {
            ResultsTextBox.Text += "\nAuthentication successful!\n\n";

            // Display user information from ID token claims
            if (token.IdToken != null)
            {
                var name = token.IdToken.Name();
                var email = token.IdToken.Email();
                var preferredUsername = token.IdToken.PreferredUsername();

                ResultsTextBox.Text += "=== User Information ===\n";
                if (!string.IsNullOrEmpty(name))
                {
                    ResultsTextBox.Text += $"Name: {name}\n";
                }
                if (!string.IsNullOrEmpty(email))
                {
                    ResultsTextBox.Text += $"Email: {email}\n";
                }
                if (!string.IsNullOrEmpty(preferredUsername))
                {
                    ResultsTextBox.Text += $"Username: {preferredUsername}\n";
                }
                ResultsTextBox.Text += $"Subject: {token.IdToken.Subject()}\n";
                ResultsTextBox.Text += "\n";
            }

            ResultsTextBox.Text += "=== Token Information ===\n";
            ResultsTextBox.Text += $"Access Token: {TruncateToken(token.AccessToken)}\n";
            ResultsTextBox.Text += $"Token Type: {token.TokenType}\n";
            ResultsTextBox.Text += $"Expires In: {token.ExpiresIn} seconds\n";

            if (!string.IsNullOrEmpty(token.RefreshToken))
            {
                ResultsTextBox.Text += $"Refresh Token: {TruncateToken(token.RefreshToken)}\n";
            }

            if (token.Scope != null)
            {
                ResultsTextBox.Text += $"Scopes: {string.Join(" ", token.Scope)}\n";
            }
        }

        private async void LogoutButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentToken?.IdToken == null || _currentClient == null)
            {
                ResultsTextBox.Text += "\nNo active session to logout.\n";
                return;
            }

            try
            {
                StartAuthButton.IsEnabled = false;
                LogoutButton.IsEnabled = false;
                CancelButton.IsEnabled = true;
                ResultsTextBox.Text = "Starting logout flow...\n";

                var redirectUri = new Uri(RedirectUriTextBox.Text.Trim());
                var logoutFlow = new SessionLogoutFlow(_currentClient, redirectUri);

                var state = Crypto.GenerateRandomString();
                var context = new SessionLogoutFlowContext(_currentToken.IdToken.EncodedToken, state);

                var logoutUrl = await logoutFlow.StartAsync(context);

                ResultsTextBox.Text += $"Logout URL: {logoutUrl}\n\n";

                _cancellationTokenSource = new CancellationTokenSource();
                var listenerPrefix = $"{redirectUri.Scheme}://{redirectUri.Host}:{redirectUri.Port}/";

                ResultsTextBox.Text += $"Starting loopback server on {listenerPrefix}...\n";

                _httpListener = new HttpListener();
                _httpListener.Prefixes.Add(listenerPrefix);
                _httpListener.Start();

                ResultsTextBox.Text += "Opening browser for logout...\n\n";

                // Open the system browser
                Process.Start(new ProcessStartInfo
                {
                    FileName = logoutUrl.ToString(),
                    UseShellExecute = true
                });

                ResultsTextBox.Text += "Waiting for logout callback...\n";

                // Wait for the logout callback
                var callbackUri = await WaitForLogoutCallbackAsync(redirectUri.AbsolutePath, _cancellationTokenSource.Token);

                if (callbackUri != null)
                {
                    ResultsTextBox.Text += $"\nLogout callback received: {callbackUri}\n\n";
                    ResultsTextBox.Text += "Logout successful! Session has been terminated.\n";
                    _currentToken = null;
                    _currentClient = null;
                }
            }
            catch (OperationCanceledException)
            {
                ResultsTextBox.Text += "\nLogout cancelled by user.\n";
            }
            catch (Exception ex)
            {
                ResultsTextBox.Text += $"\nLogout error: {ex.Message}\n";
                if (ex.InnerException != null)
                {
                    ResultsTextBox.Text += $"Inner: {ex.InnerException.Message}\n";
                }
            }
            finally
            {
                StopLoopbackServer();
                StartAuthButton.IsEnabled = true;
                CancelButton.IsEnabled = false;
            }
        }

        private async void StoreCredentialButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentToken == null)
            {
                ResultsTextBox.Text += "\nNo token to store. Please login first.\n";
                return;
            }

            try
            {
                ResultsTextBox.Text += "\n=== Storing Credential ===\n";
                _currentCredential = await Credential.StoreAsync(_currentToken);
                ResultsTextBox.Text += $"Credential stored. ID: {_currentCredential.Id}\n";

                var defaultCredential = await Credential.GetDefaultAsync();
                ResultsTextBox.Text += $"Default credential ID: {defaultCredential?.Id}\n";

                StoreCredentialButton.IsEnabled = false;
                RefreshTokenButton.IsEnabled = true;
                RevokeTokenButton.IsEnabled = true;
                RemoveCredentialButton.IsEnabled = true;
                UserInfoButton.IsEnabled = true;
            }
            catch (Exception ex)
            {
                ResultsTextBox.Text += $"Store error: {ex.Message}\n";
            }
        }

        private async void RefreshTokenButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentCredential == null)
            {
                ResultsTextBox.Text += "\nNo stored credential. Store a credential first.\n";
                return;
            }

            try
            {
                ResultsTextBox.Text += "\n=== Refreshing Token ===\n";
                ResultsTextBox.Text += $"Old Access Token: {TruncateToken(_currentCredential.Token.AccessToken)}\n";

                await _currentCredential.RefreshAsync();

                _currentToken = _currentCredential.Token;
                ResultsTextBox.Text += $"New Access Token: {TruncateToken(_currentCredential.Token.AccessToken)}\n";
                ResultsTextBox.Text += $"Expires In: {_currentCredential.Token.ExpiresIn} seconds\n";
                ResultsTextBox.Text += "Token refreshed successfully.\n";
            }
            catch (Exception ex)
            {
                ResultsTextBox.Text += $"Refresh error: {ex.Message}\n";
            }
        }

        private async void RevokeTokenButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentCredential == null)
            {
                ResultsTextBox.Text += "\nNo stored credential. Store a credential first.\n";
                return;
            }

            try
            {
                ResultsTextBox.Text += "\n=== Revoking Token ===\n";
                await _currentCredential.RevokeAsync(TokenRevokeType.Access);
                ResultsTextBox.Text += "Access token revoked successfully.\n";

                _currentToken = null;
                _currentCredential = null;
                _currentClient = null;
                StartAuthButton.IsEnabled = true;
                LogoutButton.IsEnabled = false;
                StoreCredentialButton.IsEnabled = false;
                RefreshTokenButton.IsEnabled = false;
                RevokeTokenButton.IsEnabled = false;
                RemoveCredentialButton.IsEnabled = false;
                UserInfoButton.IsEnabled = false;
            }
            catch (Exception ex)
            {
                ResultsTextBox.Text += $"Revoke error: {ex.Message}\n";
            }
        }

        private async void RemoveCredentialButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentCredential == null)
            {
                ResultsTextBox.Text += "\nNo stored credential. Store or load a credential first.\n";
                return;
            }

            try
            {
                ResultsTextBox.Text += "\n=== Removing Credential ===\n";
                ResultsTextBox.Text += $"Removing credential {_currentCredential.Id} from storage...\n";
                await _currentCredential.RemoveAsync();
                ResultsTextBox.Text += $"Credential {_currentCredential.Id} removed.\n";

                _currentToken = null;
                _currentCredential = null;
                _currentClient = null;
                StartAuthButton.IsEnabled = true;
                LogoutButton.IsEnabled = false;
                StoreCredentialButton.IsEnabled = false;
                RefreshTokenButton.IsEnabled = false;
                RevokeTokenButton.IsEnabled = false;
                RemoveCredentialButton.IsEnabled = false;
                UserInfoButton.IsEnabled = false;
            }
            catch (Exception ex)
            {
                ResultsTextBox.Text += $"Remove error: {ex.Message}\n";
            }
        }

        private async void UserInfoButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentCredential == null)
            {
                ResultsTextBox.Text += "\nNo stored credential. Store or load a credential first.\n";
                return;
            }

            try
            {
                ResultsTextBox.Text += "\n=== Fetching User Info ===\n";
                var userInfo = await _currentCredential.UserInfoAsync();

                if (!string.IsNullOrEmpty(userInfo.Name()))
                    ResultsTextBox.Text += $"Name: {userInfo.Name()}\n";
                if (!string.IsNullOrEmpty(userInfo.Email()))
                    ResultsTextBox.Text += $"Email: {userInfo.Email()}\n";
                if (!string.IsNullOrEmpty(userInfo.PreferredUsername()))
                    ResultsTextBox.Text += $"Username: {userInfo.PreferredUsername()}\n";
                if (!string.IsNullOrEmpty(userInfo.Subject()))
                    ResultsTextBox.Text += $"Subject: {userInfo.Subject()}\n";
                if (!string.IsNullOrEmpty(userInfo.GivenName()))
                    ResultsTextBox.Text += $"Given Name: {userInfo.GivenName()}\n";
                if (!string.IsNullOrEmpty(userInfo.FamilyName()))
                    ResultsTextBox.Text += $"Family Name: {userInfo.FamilyName()}\n";
                if (!string.IsNullOrEmpty(userInfo.Locale()))
                    ResultsTextBox.Text += $"Locale: {userInfo.Locale()}\n";
                if (!string.IsNullOrEmpty(userInfo.ZoneInfo()))
                    ResultsTextBox.Text += $"Zone Info: {userInfo.ZoneInfo()}\n";
            }
            catch (Exception ex)
            {
                ResultsTextBox.Text += $"User info error: {ex.Message}\n";
            }
        }

        private async void ListCredentialsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ResultsTextBox.Text += "\n=== Stored Credentials ===\n";
                var ids = await Credential.AllIDsAsync();

                if (ids.Count == 0)
                {
                    ResultsTextBox.Text += "No credentials stored.\n";
                    return;
                }

                foreach (var id in ids)
                {
                    var credential = await Credential.WithIdAsync(id);
                    if (credential != null)
                    {
                        ResultsTextBox.Text += $"  ID: {id}\n";
                        ResultsTextBox.Text += $"    Token Type: {credential.Token.TokenType}\n";
                        ResultsTextBox.Text += $"    Expires In: {credential.Token.ExpiresIn}s\n";
                        ResultsTextBox.Text += $"    Has Refresh Token: {!string.IsNullOrEmpty(credential.Token.RefreshToken)}\n";
                    }
                }

                var defaultCred = await Credential.GetDefaultAsync();
                ResultsTextBox.Text += $"  Default: {defaultCred?.Id ?? "(none)"}\n";
            }
            catch (Exception ex)
            {
                ResultsTextBox.Text += $"List error: {ex.Message}\n";
            }
        }

        private async void LoadDefaultButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ResultsTextBox.Text += "\n=== Loading Default Credential ===\n";
                var credential = await Credential.GetDefaultAsync();

                if (credential == null)
                {
                    ResultsTextBox.Text += "No default credential found.\n";
                    return;
                }

                _currentCredential = credential;
                _currentToken = credential.Token;
                _currentClient = credential.Client;
                ResultsTextBox.Text += $"Loaded credential ID: {credential.Id}\n";
                ResultsTextBox.Text += $"  Access Token: {TruncateToken(credential.Token.AccessToken)}\n";
                ResultsTextBox.Text += $"  Token Type: {credential.Token.TokenType}\n";
                ResultsTextBox.Text += $"  Expires In: {credential.Token.ExpiresIn}s\n";

                // Refresh the token if it's expired or near-expiry
                try
                {
                    await credential.RefreshIfNeededAsync();
                    _currentToken = credential.Token;
                    ResultsTextBox.Text += "Token refreshed automatically.\n";
                    ResultsTextBox.Text += $"  New Access Token: {TruncateToken(credential.Token.AccessToken)}\n";

                    // Verify the session is valid by fetching user info from Okta
                    var userInfo = await credential.UserInfoAsync();
                    ResultsTextBox.Text += "\n=== Session Restored ===\n";
                    if (!string.IsNullOrEmpty(userInfo.Name()))
                        ResultsTextBox.Text += $"  Name: {userInfo.Name()}\n";
                    if (!string.IsNullOrEmpty(userInfo.Email()))
                        ResultsTextBox.Text += $"  Email: {userInfo.Email()}\n";
                }
                catch (Exception refreshEx)
                {
                    ResultsTextBox.Text += $"  Session restore failed: {refreshEx.Message}\n";
                    ResultsTextBox.Text += "  You may need to sign in again.\n";
                }

                LogoutButton.IsEnabled = true;
                StartAuthButton.IsEnabled = false;
                StoreCredentialButton.IsEnabled = false;
                RefreshTokenButton.IsEnabled = true;
                RevokeTokenButton.IsEnabled = true;
                RemoveCredentialButton.IsEnabled = true;
                UserInfoButton.IsEnabled = true;
            }
            catch (Exception ex)
            {
                ResultsTextBox.Text += $"Load error: {ex.Message}\n";
            }
        }

        private async void ClearAllButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ResultsTextBox.Text += "\n=== Clearing All Credentials ===\n";

                await Credential.ClearAsync();
                ResultsTextBox.Text += "All credentials cleared.\n";

                _currentToken = null;
                _currentCredential = null;
                _currentClient = null;
                StartAuthButton.IsEnabled = true;
                LogoutButton.IsEnabled = false;
                StoreCredentialButton.IsEnabled = false;
                RefreshTokenButton.IsEnabled = false;
                RevokeTokenButton.IsEnabled = false;
                RemoveCredentialButton.IsEnabled = false;
                UserInfoButton.IsEnabled = false;
            }
            catch (Exception ex)
            {
                ResultsTextBox.Text += $"Clear all error: {ex.Message}\n";
            }
        }

        private async Task<string?> WaitForCallbackAsync(string redirectPath, CancellationToken cancellationToken)
        {
            return await WaitForHttpCallbackAsync(redirectPath, cancellationToken, "Authentication Complete", "Authentication Successful");
        }

        private async Task<string?> WaitForLogoutCallbackAsync(string redirectPath, CancellationToken cancellationToken)
        {
            return await WaitForHttpCallbackAsync(redirectPath, cancellationToken, "Logout Complete", "Logout Successful");
        }

        private async Task<string?> WaitForHttpCallbackAsync(string redirectPath, CancellationToken cancellationToken, string title, string heading)
        {
            if (_httpListener == null)
                return null;

            try
            {
                while (true)
                {
                    var contextTask = _httpListener.GetContextAsync();
                    var completedTask = await Task.WhenAny(contextTask, Task.Delay(Timeout.Infinite, cancellationToken));

                    if (completedTask != contextTask)
                    {
                        return null; // Cancelled
                    }

                    var context = await contextTask;

                    // Ignore requests that aren't for the callback path (e.g. favicon.ico)
                    if (!string.Equals(context.Request.Url?.AbsolutePath, redirectPath, StringComparison.OrdinalIgnoreCase))
                    {
                        context.Response.StatusCode = 404;
                        context.Response.Close();
                        continue;
                    }

                    var callbackUri = context.Request.Url?.ToString();

                    var responseHtml = $@"
<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;
               background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }}
        .container {{ text-align: center; background: white; padding: 40px 60px; border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); }}
        h1 {{ color: #28a745; margin-bottom: 10px; }}
        p {{ color: #666; }}
    </style>
</head>
<body>
    <div class='container'>
        <h1>{heading}</h1>
        <p>You can close this window and return to the application.</p>
    </div>
</body>
</html>";

                    var buffer = Encoding.UTF8.GetBytes(responseHtml);
                    context.Response.ContentLength64 = buffer.Length;
                    context.Response.ContentType = "text/html";
                    await context.Response.OutputStream.WriteAsync(buffer, cancellationToken);
                    context.Response.Close();

                    return callbackUri;
                }
            }
            catch (ObjectDisposedException)
            {
                return null;
            }
            catch (HttpListenerException)
            {
                return null;
            }
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            StopLoopbackServer();
            ResultsTextBox.Text += "\nCancelling...\n";
        }

        private void StopLoopbackServer()
        {
            try
            {
                _httpListener?.Stop();
                _httpListener?.Close();
                _httpListener = null;
            }
            catch { }

            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = null;
        }

        protected override void OnClosed(EventArgs e)
        {
            StopLoopbackServer();
            base.OnClosed(e);
        }

        private static string TruncateToken(string? token)
        {
            if (string.IsNullOrEmpty(token))
                return "(empty)";

            if (token.Length <= 20)
                return token;

            return $"{token[..10]}...{token[^10..]}";
        }
    }
}
