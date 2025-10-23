using Duende.IdentityModel.OidcClient;
using Duende.IdentityModel.OidcClient.DPoP;
using IdentityModel.Client;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using NSign;
using NSign.Client;
using NSign.Providers;
using NSign.Signatures;
using System.Configuration;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace console_app
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            // Set console encoding to UTF-8 to support Unicode characters and emojis
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            WriteHeader("mTLS Client Application Starting");

            try
            {
                string authority = ConfigurationManager.AppSettings["Authority"] ?? throw new Exception("Authority setting is required");
                string clientId = ConfigurationManager.AppSettings["ClientId"] ?? throw new Exception("ClientId setting is required");
                string certificatePath = ConfigurationManager.AppSettings["CertificatePath"] ?? throw new Exception("CertificatePath setting is required");
                string certificatePassword = ConfigurationManager.AppSettings["CertificatePassword"] ?? throw new Exception("CertificatePassword setting is required");
                string apiEndpoint = ConfigurationManager.AppSettings["ApiEndpoint"] ?? throw new Exception("ApiEndpoint setting is required");
                string tokenEndpoint = $"{authority}/mtls/token.idp";
                var useDpopSetting = ConfigurationManager.AppSettings["UseDpop"] ?? "false";
                bool useDpop = bool.TryParse(useDpopSetting, out var result) && result;
                var useHttpSignaturesSetting = ConfigurationManager.AppSettings["UseHttpSignatures"] ?? "false";
                bool useHttpSignatures = bool.TryParse(useHttpSignaturesSetting, out var httpSigResult) && httpSigResult;
                var dpopToken = string.Empty;

                WriteSuccess("Configuration loaded successfully");
                WriteData("Authority", authority);
                WriteData("Client ID", clientId);
                WriteData("API Endpoint", apiEndpoint);
                WriteData("Use DPoP", useDpop.ToString());
                WriteData("Use HTTP Signatures", useHttpSignatures.ToString());

                // Generate JWK once and reuse for both DPoP and HTTP Message Signatures
                string jwk = string.Empty;
                RSA? rsaKey = null;
                JsonWebKey jsonWebKey = null;
                if (useDpop || useHttpSignatures)
                {
                    WriteHeader("Key Generation");
                    var dpopAlg = ConfigurationManager.AppSettings["DpopAlg"] ?? "PS256";
                    WriteInfo($"Generating RSA key pair with algorithm: {dpopAlg}");
                    
                    // Creates a JWK using the configured Alg or default PS256 algorithm:
                    jwk = JsonWebKeys.CreateRsaJson(dpopAlg);
                    WriteData("JWK", jwk);
                    
                    // Extract RSA key from JWK for HTTP Message Signatures
                    if (useHttpSignatures)
                    {
                        jsonWebKey = new JsonWebKey(jwk);
                        rsaKey = FromJwk(jsonWebKey);
                        WriteSuccess("RSA key extracted for HTTP Message Signatures");
                    }
                    
                    WriteSuccess("Key pair generated successfully");
                }

                if (useDpop)
                {
                    WriteHeader("DPoP Token for Token Request");
                    var dpopMethod = ConfigurationManager.AppSettings["DpopMethod"] ?? "POST";
                    WriteInfo($"Generating DPoP token for token request (method: {dpopMethod})");
                    
                    var dpopRequest = new DPoPProofRequest
                    {
                        Url = tokenEndpoint,
                        Method = dpopMethod
                    };
                    var dpopTokenFactory = new DPoPProofTokenFactory(jwk);
                    dpopToken = dpopTokenFactory.CreateProofToken(dpopRequest).ProofToken;
                    WriteData("Token Request DPoP Token", dpopToken);
                    WriteSuccess("DPoP token for token request generated successfully");
                }

                WriteHeader("Certificate Loading");
                var clientCert = new X509Certificate2(certificatePath, certificatePassword);
                WriteSuccess("Client certificate loaded successfully");
                WriteData("Certificate Subject", clientCert.Subject);
                WriteData("Certificate Thumbprint", clientCert.Thumbprint);

                var handler = new HttpClientHandler();
                // Ignore SSL validation (for development only)
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
                
                // Include the client certificate for mTLS token requests
                handler.ClientCertificates.Add(clientCert);
                using var httpClient = new HttpClient(handler);

                WriteHeader("Token Request (Client Credentials Flow)");
                WriteInfo("Requesting access token using client credentials flow with mTLS");
                WriteData("Token Endpoint", tokenEndpoint);
                
                // Create the token request
                var request = new ClientCredentialsTokenRequest
                {
                    Address = tokenEndpoint,
                    GrantType = "client_credentials"
                };
                request.Parameters.Add("client_id", clientId);
                if (useDpop)
                {
                    request.Headers.Add("DPoP", dpopToken);
                    WriteInfo("DPoP header added to token request");
                }

                var tokenResponse = await httpClient.RequestClientCredentialsTokenAsync(request);

                if (tokenResponse.IsError)
                {
                    WriteError($"Token request failed: {tokenResponse.Error}");
                    if (!string.IsNullOrEmpty(tokenResponse.ErrorDescription))
                    {
                        WriteError($"Error Description: {tokenResponse.ErrorDescription}");
                    }
                    return;
                }

                WriteSuccess("Token request successful!");
                WriteJson(tokenResponse.Json.ToString());

                // Parse and display Access Token in Json format
                WriteHeader("Access Token Details");
                var handlerJwt = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                var jwt = handlerJwt.ReadJwtToken(tokenResponse.AccessToken);
                var jwtJsonHeader = System.Text.Json.JsonSerializer.Serialize(jwt.Header, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                WriteInfo("Access Token (Header):");
                WriteJson(jwtJsonHeader);
                var jwtJson = System.Text.Json.JsonSerializer.Serialize(jwt.Payload, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                WriteInfo("Access Token (Payload):");
                WriteJson(jwtJson);

                // Now make an API call using the access token
                WriteHeader("API Call");

                string apiDpopToken = string.Empty;
                if (useDpop)
                {
                    WriteHeader("Generate New DPoP Token for API Call");
                    WriteInfo("Generating fresh DPoP token for API request per RFC 9449");

                    // Generate a new DPoP proof for the API call with correct URL and method
                    var apiDpopRequest = new DPoPProofRequest
                    {
                        Url = apiEndpoint,
                        Method = "GET", // API call method
                        AccessToken = tokenResponse.AccessToken // Include access token for ath claim
                    };

                    // Reuse the same JWK but create a fresh proof
                    var apiDpopTokenFactory = new DPoPProofTokenFactory(jwk);
                    apiDpopToken = apiDpopTokenFactory.CreateProofToken(apiDpopRequest).ProofToken;

                    WriteData("API DPoP Token", apiDpopToken);
                    WriteSuccess("Fresh DPoP token generated for API call");

                }

                var useOidcClientPackage = ConfigurationManager.AppSettings["UseOidcClientPackage"] == "True";
                var response = useOidcClientPackage && useDpop ?
                        await CallRestApiWithOidcClientAsync(apiEndpoint, jwk, tokenResponse.AccessToken, authority) :
                        await CallRestApiWithStandardHandlerAsync(apiEndpoint, apiDpopToken, tokenResponse.TokenType, tokenResponse.AccessToken, useHttpSignatures, rsaKey, jsonWebKey);

                if (response.IsSuccessStatusCode)
                {
                    WriteSuccess($"API call successful! Status: {response.StatusCode}");
                    var content = await response.Content.ReadAsStringAsync();
                    WriteInfo("API Response:");
                    WriteJson(content);
                
                    // Display HTTP Message Signature headers if present
                    if (useHttpSignatures)
                    {
                        WriteHeader("Custom HTTP Message Signature Headers");
                        foreach (var header in response.Headers.Concat(response.Content.Headers))
                        {
                            if (header.Key.StartsWith("Signature", StringComparison.OrdinalIgnoreCase) ||
                                header.Key.StartsWith("Signature-Input", StringComparison.OrdinalIgnoreCase))
                            {
                                WriteData(header.Key, string.Join(", ", header.Value));
                            }
                        }
                    }
                }
                else
                {
                    WriteError($"API call failed: {response.StatusCode} {response.ReasonPhrase}");
                    var errorContent = await response.Content.ReadAsStringAsync();
                    if (!string.IsNullOrEmpty(errorContent))
                    {
                        WriteError($"Error Content: {errorContent}");
                    }
                }

                WriteHeader("Application Completed");
                WriteInfo("Press any key to exit...");
            }
            catch (Exception ex)
            {
                WriteError($"Application failed with exception: {ex}");
                if (ex.InnerException != null)
                {
                    WriteError($"Inner Exception: {ex.InnerException}");
                }
            }

            Console.Read();
        }

        /// <summary>
        /// This is a demonstration of using the OidcClient package to call REST API with DPoP and access token.
        /// This approach leverages the built-in DPoP support in the OidcClient library.
        /// However:
        ///     - it should be noted that the OidcClient package does not support HTTP Message Signatures (RFC 9421).
        ///     - it only is used for happy cases demo purposes here, when there is error from the demo web api, it will trigger its code flow implementation - This is not a flow of our demo..
        /// </summary>
        /// <param name="apiEndpoint"></param>
        /// <param name="dpopKey"></param>
        /// <param name="accessToken"></param>
        /// <param name="authority"></param>
        /// <returns></returns>
        private static async Task<HttpResponseMessage> CallRestApiWithOidcClientAsync(string apiEndpoint, string dpopKey, string accessToken, string authority)
        {
            var oidcClient = new OidcClient(new OidcClientOptions()
            {
                Authority = authority
            });
            var handler = CreateDPoPHandler(oidcClient, dpopKey, accessToken);
            var httpClient = new HttpClient(handler);

            var response = await httpClient.GetAsync(apiEndpoint);
            return response;
        }

        private static async Task<HttpResponseMessage> CallRestApiWithStandardHandlerAsync(string apiEndpoint, string dpop, string tokenType, string accessToken, bool useHttpSignatures, RSA? rsaKey, JsonWebKey jsonWebKey)
        {
            var apiHandler = new HttpClientHandler();

            HttpClient apiHttpClient;
            if (useHttpSignatures && rsaKey != null)
            {
                var keyId = Base64UrlEncoder.Encode(SHA256.Create().ComputeHash(jsonWebKey.ComputeJwkThumbprint()));
                // Create HTTP client with custom HTTP Message Signatures support
                WriteInfo("Creating HTTP client with custom HTTP Message Signatures support");
                apiHttpClient = CreateHttpClientWithSignatures(apiHandler, rsaKey, keyId);
            }
            else
            {
                apiHttpClient = new HttpClient(apiHandler);
            }

            // Add the fresh DPoP header for API request
            if (!string.IsNullOrEmpty(dpop))
            {
                apiHttpClient.DefaultRequestHeaders.Clear(); // Clear any existing headers
                apiHttpClient.DefaultRequestHeaders.Add("DPoP", dpop);
                WriteInfo("Fresh DPoP header added to API request");
            }

            apiHttpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(tokenType, accessToken);
            WriteData("Authorization Scheme", tokenType);

            WriteInfo("Sending HTTP request with custom HTTP Message Signatures");
            WriteData("API Endpoint", apiEndpoint);

            // Remove client certificate from the handler before making the API call
            apiHandler.ClientCertificates.Clear();

            var response = await apiHttpClient.GetAsync(apiEndpoint);
            return response;
        }

        private static HttpMessageHandler CreateDPoPHandler(OidcClient client,
            string proofKey,
            string accessToken,
            HttpMessageHandler? apiInnerHandler = null)
        {
            var apiDpopHandler = new ProofTokenMessageHandler(proofKey, apiInnerHandler ?? new HttpClientHandler());

            var handler = new RefreshTokenDelegatingHandler(
                client,
                accessToken,
                "any",
                "DPoP",
                apiDpopHandler);

            return handler;
        }

        private static void ConfigureServices(IServiceCollection services, RSA rsa, string keyId)
        {
            services.AddHttpClient("signedClient")
                .AddContentDigestAndSigningHandlers()
            .Services

            // Configure message signing options
            .Configure<AddContentDigestOptions>(options => options.WithHash(AddContentDigestOptions.Hash.Sha256))
            .ConfigureMessageSigningOptions(options =>
            {
                options.SignatureName = "http-msg-sign";
                options
                    .WithMandatoryComponent(SignatureComponent.RequestTargetUri)
                    .WithMandatoryComponent(SignatureComponent.Method)
                    .WithMandatoryComponent(SignatureComponent.Scheme)
                    .WithMandatoryComponent(SignatureComponent.Authority)
                    .WithOptionalComponent(SignatureComponent.ContentLength)
                    .SetParameters = (signingOptions) => signingOptions
                        .WithCreated(DateTimeOffset.UtcNow.AddMinutes(-2))
                        .WithExpires(TimeSpan.FromMinutes(10))
                        .WithNonce(Guid.NewGuid().ToString("N"))
                        .WithTag("nsign-example-client")
                    ;
            })
            .Services
            .AddSingleton<ISigner>(sp =>
            {
                return new RsaPssSha512SignatureProvider(rsa, rsa, keyId);
            });
        }

        // Create HTTP client with custom HTTP Message Signatures support (RFC 9421)
        private static HttpClient CreateHttpClientWithSignatures(HttpClientHandler handler, RSA rsaKey, string keyId)
        {
            WriteInfo("Configuring HTTP Message Signatures per RFC 9421 (Custom Implementation)");

            try
            {
                var services = new ServiceCollection();
                ConfigureServices(services, rsaKey, keyId);
                var builtProvider = services.BuildServiceProvider();
                var clientFactory = builtProvider.GetRequiredService<IHttpClientFactory>();

                var client = clientFactory.CreateClient("signedClient");

                WriteSuccess("HTTP Message Signatures configured successfully");
                WriteData("Key ID", keyId);
                WriteData("Implementation", "Custom RFC 9421 Implementation");
                WriteData("Algorithm", Constants.SignatureAlgorithms.RsaPssSha512);

                return client;
            }
            catch (Exception ex)
            {
                WriteWarning($"Failed to configure HTTP signatures: {ex.Message}");
                WriteInfo("Falling back to standard HTTP client");

                // Fallback to standard HTTP client if configuration fails
                return new HttpClient(handler);
            }
        }

        private static RSA FromJwk(JsonWebKey jsonWebKey)
        {
            var nBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.N);
            var eBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.E);
            var dBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.D);
            var pBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.P);
            var qBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.Q);
            var dpBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.DP);
            var dqBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.DQ);
            var qiBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.QI);

            var rsaParams = new RSAParameters
            {
                Modulus = nBytes,
                Exponent = eBytes,
                D = dBytes,
                P = pBytes,
                Q = qBytes,
                DP = dpBytes,
                DQ = dqBytes,
                InverseQ = qiBytes
            };

            var rsaKey = RSA.Create();
            rsaKey.ImportParameters(rsaParams);

            return rsaKey;
        }

        // Helper methods for colorful console output
        private static void WriteInfo(string message)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"ℹ️  {message}");
            Console.ResetColor();
        }

        private static void WriteSuccess(string message)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"✅ {message}");
            Console.ResetColor();
        }

        private static void WriteWarning(string message)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"⚠️  {message}");
            Console.ResetColor();
        }

        private static void WriteError(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"❌ {message}");
            Console.ResetColor();
        }

        private static void WriteHeader(string message)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine($"\n🚀 {message}");
            Console.WriteLine(new string('=', message.Length + 3));
            Console.ResetColor();
        }

        private static void WriteData(string label, string value)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"{label}: ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(value);
            Console.ResetColor();
        }

        private static void WriteJson(string json)
        {
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine(json);
            Console.ResetColor();
        }
    }
}
