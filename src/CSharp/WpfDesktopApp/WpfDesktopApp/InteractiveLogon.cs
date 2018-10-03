// Copyright 2016 Google Inc.
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Newtonsoft.Json.Linq;
using System.Linq;

namespace WpfDesktopApp
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public class InteractiveLogon
    {
        private readonly Action<string> logListener;

        public InteractiveLogon(Action<string> logListener)
        {
            this.logListener = logListener ?? throw new ArgumentNullException("logListener");
        }

        public async Task<AuthenticationResult> DoLogon(MainWindow mainWindow)
        {
            // Generates state and PKCE values.
            string state = RandomDataBase64url(32);

            // Creates a redirect URI using an available port on the loopback address.
            string redirectURI = string.Format("http://{0}:{1}/", IPAddress.Loopback, ConfigurationExtensions.Port);
            Output("redirect URI: " + redirectURI);

            // Creates an HttpListener to listen for requests on that redirect URI.
            var http = new HttpListener();
            http.Prefixes.Add(redirectURI);
            Output("Listening..");
            http.Start();

            // Creates the OAuth 2.0 authorization request.
            string authorizationRequest = string.Format("{0}?response_type=code&scope={4}&redirect_uri={1}&client_id={2}&state={3}",
                ConfigurationExtensions.AuthorizationEndpoint,
                System.Uri.EscapeDataString(redirectURI),
                ConfigurationExtensions.ClientId,
                state,
                HttpUtility.UrlEncode(ConfigurationExtensions.Scope));

            // Opens request in the browser.
            System.Diagnostics.Process.Start(authorizationRequest);

            // Waits for the OAuth authorization response.
            var context = await http.GetContextAsync();

            // Brings this app back to the foreground.
            mainWindow.Activate();

            // Sends an HTTP response to the browser.
            var response = context.Response;
            // TODO: replace google.com with your own landing page
            string responseString = string.Format("<html><head><meta http-equiv='refresh' content='10;url=https://google.com'></head><body>Please return to the app.</body></html>");
            var buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
            response.ContentLength64 = buffer.Length;
            var responseOutput = response.OutputStream;
            Task responseTask = responseOutput.WriteAsync(buffer, 0, buffer.Length).ContinueWith((task) =>
            {
                responseOutput.Close();
                http.Stop();
                Console.WriteLine("HTTP server stopped.");
            });

            // Checks for errors.
            if (context.Request.QueryString.Get("error") != null)
            {
                Output(String.Format("OAuth authorization error: {0}.", context.Request.QueryString.Get("error")));
                return null;
            }
            if (context.Request.QueryString.Get("code") == null
                || context.Request.QueryString.Get("state") == null)
            {
                Output("Malformed authorization response. " + context.Request.QueryString);
                return null;
            }

            // extracts the code
            var code = context.Request.QueryString.Get("code");
            var incoming_state = context.Request.QueryString.Get("state");

            // Compares the receieved state to the expected value, to ensure that
            // this app made the request which resulted in authorization.
            if (incoming_state != state)
            {
                Output(String.Format("Received request with invalid state ({0})", incoming_state));
                return null;
            }
            Output("Authorization code: " + code);

            // Starts the code exchange at the Token Endpoint.
            return await PerformCodeExchange(code, redirectURI);
        }

        async Task<AuthenticationResult> PerformCodeExchange(string code, string redirectURI)
        {
            Output("Exchanging code for tokens...");

            // builds the  request
            string tokenRequestBody = string.Format("code={0}&redirect_uri={1}&client_id={2}&client_secret={3}&scope=&grant_type=authorization_code",
                code,
                System.Uri.EscapeDataString(redirectURI),
                ConfigurationExtensions.ClientId,
                ConfigurationExtensions.ClientSecret
                );

            // sends the request
            HttpWebRequest tokenRequest = (HttpWebRequest)WebRequest.Create(ConfigurationExtensions.TokenEndpoint);
            tokenRequest.Method = "POST";
            tokenRequest.ContentType = "application/x-www-form-urlencoded";
            tokenRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            byte[] _byteVersion = Encoding.ASCII.GetBytes(tokenRequestBody);
            tokenRequest.ContentLength = _byteVersion.Length;
            Stream stream = tokenRequest.GetRequestStream();
            await stream.WriteAsync(_byteVersion, 0, _byteVersion.Length);
            stream.Close();

            try
            {
                // gets the response
                WebResponse tokenResponse = await tokenRequest.GetResponseAsync();
                using (StreamReader reader = new StreamReader(tokenResponse.GetResponseStream()))
                {
                    // reads response body
                    string responseText = await reader.ReadToEndAsync();
                    Output(responseText);

                    // converts to dictionary
                    Dictionary<string, string> tokenEndpointDecoded = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseText);

                    string accessToken = tokenEndpointDecoded["access_token"];
                    JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
                    var tokenValidationParameters = new TokenValidationParameters
                    {
                        IssuerSigningKey = new X509SecurityKey(ConfigurationExtensions.IssuerSigningKey),
                        ValidAudience = ConfigurationExtensions.ResourceUri,
                        ValidIssuer = ConfigurationExtensions.Issuer
                        // Validate a lot of other things here
                    };

                    ClaimsPrincipal claimsPrincipal = jwtSecurityTokenHandler.ValidateToken(accessToken, tokenValidationParameters, out SecurityToken dummy);

                    string userInfo = await UserinfoCall(accessToken);
                    AppendUserinfoToClaimsPrincipal(claimsPrincipal, userInfo);

                    return new AuthenticationResult
                    {
                        AccessToken = accessToken,
                        ClaimsPrincipal = claimsPrincipal
                    };
                }
            }
            catch (WebException webException)
            {
                if (webException.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = webException.Response as HttpWebResponse;
                    if (response != null)
                    {
                        Output("HTTP: " + response.StatusCode);
                        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                        {
                            // reads response body
                            string responseText = await reader.ReadToEndAsync();
                            Output(responseText);
                        }
                    }

                }
            }
            catch (Exception ex)
            {
                Output(ex.ToString());
            }

            return null;
        }

        private static void AppendUserinfoToClaimsPrincipal(ClaimsPrincipal claimsPrincipal, string userInfo)
        {
            ClaimsIdentity firstIdentity = (ClaimsIdentity)claimsPrincipal.Identity;
            JObject user = JObject.Parse(userInfo);
            foreach (KeyValuePair<string, JToken> j in user)
            {
                var multiValuesClaim = j.Value as JArray;
                if (multiValuesClaim != null)
                {
                    multiValuesClaim.Values<string>().ToList().ForEach(v =>
                                            firstIdentity.AddClaim(new Claim(j.Key, v)));
                    continue;
                }

                firstIdentity.AddClaim(new Claim(j.Key, j.Value.Value<string>()));
            }
        }

        public async Task<string> UserinfoCall(string access_token)
        {
            Output("Making API Call to Userinfo...");

            // builds the  request
            string userinfoRequestURI = ConfigurationExtensions.UserInfoEndpoint;

            // sends the request
            HttpWebRequest userinfoRequest = (HttpWebRequest)WebRequest.Create(userinfoRequestURI);
            userinfoRequest.Method = "GET";
            userinfoRequest.Headers.Add(string.Format("Authorization: Bearer {0}", access_token));
            userinfoRequest.ContentType = "application/x-www-form-urlencoded";
            userinfoRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

            // gets the response
            WebResponse userinfoResponse = await userinfoRequest.GetResponseAsync();
            using (StreamReader userinfoResponseReader = new StreamReader(userinfoResponse.GetResponseStream()))
            {
                // reads response body
                string userinfoResponseText = await userinfoResponseReader.ReadToEndAsync();
                Output(userinfoResponseText);
                return userinfoResponseText;
            }
        }

        /// <summary>
        /// Appends the given string to the on-screen log, and the debug console.
        /// </summary>
        /// <param name="output">string to be appended</param>
        public void Output(string output)
        {
            logListener(output);
        }

        /// <summary>
        /// Returns URI-safe data with a given input length.
        /// </summary>
        /// <param name="length">Input length (nb. output will be longer)</param>
        /// <returns></returns>
        public static string RandomDataBase64url(uint length)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[length];
            rng.GetBytes(bytes);
            return Base64UrlEncodeNoPadding(bytes);
        }

        /// <summary>
        /// Returns the SHA256 hash of the input string.
        /// </summary>
        /// <param name="inputStirng"></param>
        /// <returns></returns>
        public static byte[] SHA256(string inputStirng)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(inputStirng);
            SHA256Managed sha256 = new SHA256Managed();
            return sha256.ComputeHash(bytes);
        }

        /// <summary>
        /// Base64url no-padding encodes the given input buffer.
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public static string Base64UrlEncodeNoPadding(byte[] buffer)
        {
            string base64 = Convert.ToBase64String(buffer);

            // Converts base64 to base64url.
            base64 = base64.Replace("+", "-");
            base64 = base64.Replace("/", "_");
            // Strips padding.
            base64 = base64.Replace("=", "");

            return base64;
        }

    }
}
