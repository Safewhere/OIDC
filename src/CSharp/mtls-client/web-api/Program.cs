using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using NSign.AspNetCore;
using NSign.Providers;
using NSign.Signatures;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;
using web_api;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
// Register IHttpContextAccessor
builder.Services.AddHttpContextAccessor();

// Configure client certificate authentication
builder.Services.Configure<Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions>(options =>
{
    options.ConfigureHttpsDefaults(httpsOptions =>
    {
    });
});

// Configure HTTP Message Signatures
var enableHttpSignatures = builder.Configuration.GetValue<bool>("HttpSignatures:Enabled", false);
var signatureMaxAgeSeconds = builder.Configuration.GetValue<int>("HttpSignatures:MaxAge", 300);

// JWT authentication with certificate validation and cnf claim check
var authority = builder.Configuration["Jwt:Authority"] ?? "";
var audience = builder.Configuration["Jwt:Audience"] ?? "";
var enforceDpop = builder.Configuration.GetValue<bool>("Jwt:EnforceDpop", false);

Console.WriteLine($"[CONFIG] JWT Configuration:");
Console.WriteLine($"   Authority: {authority}");
Console.WriteLine($"   Audience: {audience}");
Console.WriteLine($"   EnforceDpop: {enforceDpop}");
Console.WriteLine($"   HTTP Signatures: {enableHttpSignatures}");

var httpClient = new HttpClient(new HttpClientHandler()
{
    ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
});
var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
    metadataAddress: $"{authority}/.well-known/openid-configuration",
    configRetriever: new OpenIdConnectConfigurationRetriever(),
    docRetriever: new HttpDocumentRetriever(httpClient)
);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = authority,
            ValidAudience = audience,
            ConfigurationManager = configurationManager,
            NameClaimType = "name",
            ClockSkew = TimeSpan.FromMinutes(5) // Allow for some clock skew
        };
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                Console.WriteLine("[AUTH] OnMessageReceived - JWT Bearer authentication started");
                var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
                var dpopHeader = context.Request.Headers["DPoP"].FirstOrDefault();
                
                if (!string.IsNullOrEmpty(authHeader))
                {
                    Console.WriteLine($"   Authorization Header: {authHeader}");
                    
                    // Handle DPoP authorization scheme by extracting the token
                    if (authHeader.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
                    {
                        var token = authHeader.Substring(5); // Remove "DPoP " prefix
                        context.Token = token;
                        Console.WriteLine("   Converted DPoP authorization to token for JWT validation");
                    }
                    else if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    {
                        // Standard Bearer token - let the default handler process it
                        Console.WriteLine("   Standard Bearer token detected");
                    }
                }
                else
                {
                    Console.WriteLine("   Authorization Header: [Not Present]");
                }
                
                Console.WriteLine($"   DPoP Header Present: {!string.IsNullOrEmpty(dpopHeader)}");
                Console.WriteLine($"   Request Path: {context.Request.Path}");
                Console.WriteLine($"   Request Method: {context.Request.Method}");
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                Console.WriteLine($"[ERROR] Authentication failed: {context.Exception?.Message}");
                Console.WriteLine($"   Exception Type: {context.Exception?.GetType().Name}");
                if (context.Exception?.InnerException != null)
                {
                    Console.WriteLine($"   Inner Exception: {context.Exception.InnerException.Message}");
                }
                return Task.CompletedTask;
            },
            OnChallenge = context =>
            {
                Console.WriteLine("[CHALLENGE] OnChallenge - Authentication challenge triggered");
                Console.WriteLine($"   Error: {context.Error}");
                Console.WriteLine($"   Error Description: {context.ErrorDescription}");
                
                // Check if this is a DPoP-related challenge
                var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
                var dpopHeader = context.Request.Headers["DPoP"].FirstOrDefault();
                bool isDpopRequest = !string.IsNullOrEmpty(dpopHeader) && 
                                   authHeader?.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase) == true;
                
                // Get custom error information from HttpContext.Items (more reliable than Properties.Items)
                context.HttpContext.Items.TryGetValue("auth_error_code", out var customError);
                context.HttpContext.Items.TryGetValue("auth_error_description", out var customErrorDescription);
                
                var errorCode = customError?.ToString() ?? context.Error ?? "unauthorized";
                var errorDescription = customErrorDescription?.ToString() ?? context.ErrorDescription ?? "Authentication failed";
                
                Console.WriteLine($"   [DEBUG] Custom error from HttpContext: {customError}");
                Console.WriteLine($"   [DEBUG] Properties.Items count: {context.Properties.Items.Count}");
                
                // Customize the WWW-Authenticate header based on request type
                if (isDpopRequest)
                {
                    // For DPoP requests, include DPoP in WWW-Authenticate header
                    var dpopChallenge = $"DPoP realm=\"{context.Request.Host}\" algs=\"RS256 RS384 RS512 PS256 PS384 PS512\"";
                    if (!string.IsNullOrEmpty(errorCode))
                    {
                        dpopChallenge += $", error=\"{errorCode}\"";
                    }
                    if (!string.IsNullOrEmpty(errorDescription))
                    {
                        dpopChallenge += $", error_description=\"{errorDescription}\"";
                    }
                    context.Response.Headers["WWW-Authenticate"] = dpopChallenge;
                }
                else
                {
                    // For Bearer requests, use standard Bearer challenge
                    var challengeHeader = $"Bearer realm=\"{context.Request.Host}\"";
                    if (!string.IsNullOrEmpty(errorCode))
                    {
                        challengeHeader += $", error=\"{errorCode}\"";
                    }
                    if (!string.IsNullOrEmpty(errorDescription))
                    {
                        challengeHeader += $", error_description=\"{errorDescription}\"";
                    }
                    context.Response.Headers["WWW-Authenticate"] = challengeHeader;
                }
                
                // Set custom error response body with detailed information
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                
                var errorResponse = new
                {
                    error = !string.IsNullOrEmpty(authHeader) ? errorCode : null,
                    error_description = !string.IsNullOrEmpty(authHeader) ? errorDescription : null,
                    request_type = isDpopRequest ? "DPoP" : "Bearer",
                    timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    details = new
                    {
                        path = context.Request.Path.Value,
                        method = context.Request.Method,
                        dpop_header_present = !string.IsNullOrEmpty(dpopHeader),
                        authorization_header_present = !string.IsNullOrEmpty(authHeader)
                    }
                };
                
                var errorJson = JsonSerializer.Serialize(errorResponse, new JsonSerializerOptions { WriteIndented = true });
                context.Response.WriteAsync(errorJson);
                
                // Mark the challenge as handled to prevent default behavior
                context.HandleResponse();
                
                Console.WriteLine($"   [INFO] Custom error response sent to client: {errorCode}");
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                Console.WriteLine("[SUCCESS] Token validation started");
                var httpContext = context.HttpContext;
                try
                {
                    var authorizationHeader = httpContext.Request.Headers["Authorization"].FirstOrDefault();
                    var dpopHeader = httpContext.Request.Headers["DPoP"].FirstOrDefault();
                    
                    bool isDpopRequest = !string.IsNullOrEmpty(dpopHeader) && 
                                       authorizationHeader?.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase) == true;
                    
                    Console.WriteLine($"   Request type: {(isDpopRequest ? "DPoP" : "Bearer")}");
                    Console.WriteLine($"   EnforceDpop setting: {enforceDpop}");
                    
                    // If DPoP is enforced and this is not a DPoP request, fail
                    if (enforceDpop && !isDpopRequest)
                    {
                        Console.WriteLine("   DPoP is enforced but request is not using DPoP");
                        
                        // Store error information in HttpContext for OnChallenge to access
                        httpContext.Items["auth_error_code"] = "dpop_required";
                        httpContext.Items["auth_error_description"] = "This resource requires DPoP authentication. Include a DPoP header with your request.";
                        
                        context.Fail("DPoP authentication is required.");
                        return Task.CompletedTask;
                    }
                    
                    // Handle DPoP-specific validation
                    if (isDpopRequest)
                    {
                        Console.WriteLine("   Validating DPoP request");

                        // Ensure that there is single DPoP header
                        if (httpContext.Request.Headers["DPoP"].Count > 1)
                        {
                            Console.WriteLine("   Multiple DPoP headers detected");
                            
                            // Store error information in HttpContext for OnChallenge to access
                            httpContext.Items["auth_error_code"] = "invalid_request";
                            httpContext.Items["auth_error_description"] = "Multiple DPoP headers are not allowed.";
                            
                            context.Fail("Multiple DPoP headers are not allowed.");
                            return Task.CompletedTask;
                        }

                        // Validate DPoP proof token - handle both JsonWebToken and JwtSecurityToken
                        var dpopProofValidation = DPoPValidator.ValidateDPoPProof(dpopHeader, httpContext, context.SecurityToken);
                        if (!dpopProofValidation.IsValid)
                        {
                            Console.WriteLine($"   DPoP proof validation failed: {dpopProofValidation.ErrorMessage}");
                            
                            // Store error information in HttpContext for OnChallenge to access
                            httpContext.Items["auth_error_code"] = dpopProofValidation.ErrorCode;
                            httpContext.Items["auth_error_description"] = dpopProofValidation.ErrorMessage;
                            
                            context.Fail($"DPoP proof validation failed: {dpopProofValidation.ErrorMessage}");
                            return Task.CompletedTask;
                        }
                        
                        Console.WriteLine("   DPoP proof validation successful");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"   Error during token validation: {ex.Message}");
                    
                    // Store error information in HttpContext for OnChallenge to access
                    httpContext.Items["auth_error_code"] = "validation_error";
                    httpContext.Items["auth_error_description"] = $"An error occurred during token validation: {ex.Message}";
                    
                    context.Fail($"Error during token validation: {ex.Message}");
                    return Task.CompletedTask;
                }
                
                Console.WriteLine("[SUCCESS] Token validation completed successfully");
                return Task.CompletedTask;
            }
        };
    });

// Add CORS policy to allow all origins (for testing only)
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod()
    );
});

if (enableHttpSignatures)
{
    builder.Services
        .Configure<RequestSignatureVerificationOptions>(options =>
        {
            options.TagsToVerify.Add("nsign-example-client");
            options.CreatedRequired =
                options.ExpiresRequired =
                options.KeyIdRequired =
                options.AlgorithmRequired =
                options.TagRequired = true;
            options.MissingSignatureResponseStatus = 404;
            options.MaxSignatureAge = TimeSpan.FromSeconds(signatureMaxAgeSeconds);

            // Note: The default behavior should continue to next middleware
            // after successful verification. Do not set options.OnSignatureVerificationSucceeded!
            // Setting it will prevent the middleware from continuing the pipeline.

            options.VerifyNonce = (SignatureParamsComponent signatureParams) =>
            {
                Console.WriteLine($"Got signature with tag={signatureParams.Tag} and nonce={signatureParams.Nonce}.");
                return true;
            };

            options.OnSignatureVerificationFailed = (context, reason) =>
            {
                Console.WriteLine($"Signature verification failed: {reason}");
                
                // Get HttpContext through service provider
                var serviceProvider = builder.Services.BuildServiceProvider();
                var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
                var httpContext = httpContextAccessor.HttpContext;
                
                if (httpContext != null)
                {
                    // Set error response for client
                    httpContext.Response.StatusCode = 401;
                    httpContext.Response.ContentType = "application/json";
                    
                    var errorResponse = new
                    {
                        error = "signature_verification_failed",
                        error_description = $"HTTP Message Signature verification failed: {reason}",
                        timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                        details = new
                        {
                            path = httpContext.Request.Path.Value,
                            method = httpContext.Request.Method,
                            required_signatures = "HTTP Message Signatures per RFC 9421"
                        }
                    };
                    
                    var errorJson = JsonSerializer.Serialize(errorResponse, new JsonSerializerOptions { WriteIndented = true });
                    return httpContext.Response.WriteAsync(errorJson);
                }
                
                return Task.CompletedTask;
            };

            options.OnSignatureInputError = (error, context) =>
            {
                Console.WriteLine($"Signature input error: {error}");
                
                // Get HttpContext through service provider
                var serviceProvider = builder.Services.BuildServiceProvider();
                var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
                var httpContext = httpContextAccessor.HttpContext;
                
                if (httpContext != null)
                {
                    // Set error response for client
                    httpContext.Response.StatusCode = 400;
                    httpContext.Response.ContentType = "application/json";
                    
                    var errorResponse = new
                    {
                        error = "signature_input_error",
                        error_description = $"HTTP Message Signature input error: {error}",
                        timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                        details = new
                        {
                            path = httpContext.Request.Path.Value,
                            method = httpContext.Request.Method,
                            required_format = "HTTP Message Signatures per RFC 9421"
                        }
                    };
                    
                    var errorJson = JsonSerializer.Serialize(errorResponse, new JsonSerializerOptions { WriteIndented = true });
                    return httpContext.Response.WriteAsync(errorJson);
                }
                
                return Task.CompletedTask;
            };

            options.OnMissingSignatures = (context) =>
            {
                Console.WriteLine("Missing signatures.");
                
                // Get HttpContext through service provider
                var serviceProvider = builder.Services.BuildServiceProvider();
                var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
                var httpContext = httpContextAccessor.HttpContext;
                
                if (httpContext != null)
                {
                    // Set error response for client
                    httpContext.Response.StatusCode = 401;
                    httpContext.Response.ContentType = "application/json";
                    
                    // Add WWW-Authenticate header to indicate signature requirements
                    httpContext.Response.Headers["WWW-Authenticate"] = "Signature realm=\"API\", algorithm=\"rsa-pss-sha512\"";
                    
                    var errorResponse = new
                    {
                        error = "missing_signature",
                        error_description = "HTTP Message Signature is required but not provided",
                        timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                        details = new
                        {
                            path = httpContext.Request.Path.Value,
                            method = httpContext.Request.Method,
                            required_headers = new[] { "Signature", "Signature-Input" },
                            specification = "RFC 9421 - HTTP Message Signatures"
                        }
                    };
                    
                    var errorJson = JsonSerializer.Serialize(errorResponse, new JsonSerializerOptions { WriteIndented = true });
                    return httpContext.Response.WriteAsync(errorJson);
                }
                
                return Task.CompletedTask;
            };
        })
        .AddSignatureVerification((serviceProvider) =>
        {
            // Get current HttpContext
            var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
            var httpContext = httpContextAccessor.HttpContext;
            var rsaFromDPoP = ExtractPublicKeyFromDPoP(httpContext, out string keyId);
            return new RsaPssSha512SignatureProvider(null, rsaFromDPoP, keyId);
        });
}

static void ValidateSignatureAndDigest(IApplicationBuilder builder)
{
    builder.UseSignatureVerification();
}

static RSA? ExtractPublicKeyFromDPoP(HttpContext httpContext, out string keyId)
{
    keyId = string.Empty;
    var dpopHeader = httpContext.Request.Headers["DPoP"].FirstOrDefault();
    if (dpopHeader != null)
    {
        // 
        var handler = new JwtSecurityTokenHandler();
        var dpopToken = handler.ReadJwtToken(dpopHeader);
        if (!dpopToken.Header.TryGetValue("jwk", out var jwkObj))
        {
            return null;
        }
        // Convert JWK object to JSON string for processing
        var jwkJson = JsonSerializer.Serialize(jwkObj);

        // Create JsonWebKey from the embedded JWK
        var jsonWebKey = new JsonWebKey(jwkJson);

        keyId = Base64UrlEncoder.Encode(SHA256.Create().ComputeHash(jsonWebKey.ComputeJwkThumbprint()));
        return FromJwk(jsonWebKey);
    }
    return null;
}

// Only need public RSA key from JWK
static RSA FromJwk(JsonWebKey jsonWebKey)
{
    var nBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.N);
    var eBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.E);

    var rsaParams = new RSAParameters
    {
        Modulus = nBytes,
        Exponent = eBytes
    };

    var rsaKey = RSA.Create();
    rsaKey.ImportParameters(rsaParams);

    return rsaKey;
}

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseCors(); // Enable CORS before authentication/authorization

app.UseAuthentication();

app.UseAuthorization();


if (enableHttpSignatures)
{
    app.UseWhen(ctx => ctx.Request.Path.StartsWithSegments("/HelloWorld"), ValidateSignatureAndDigest);
}

app.MapControllers();

Console.WriteLine("[STARTUP] Web API starting up...");
app.Run();
