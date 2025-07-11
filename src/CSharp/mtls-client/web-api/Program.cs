using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.JsonWebTokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Configure client certificate authentication
builder.Services.Configure<Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions>(options =>
{
    options.ConfigureHttpsDefaults(httpsOptions =>
    {
        httpsOptions.ClientCertificateMode = Microsoft.AspNetCore.Server.Kestrel.Https.ClientCertificateMode.AllowCertificate;
    });
});

// JWT authentication with certificate validation and cnf claim check
var authority = builder.Configuration["Jwt:Authority"] ?? "";
var audience = builder.Configuration["Jwt:Audience"] ?? "";

// Load the public key/certificate for signature validation
var certPath = builder.Configuration["Jwt:Certificate:Path"];
var cert = !string.IsNullOrEmpty(certPath) ? new X509Certificate2(certPath) : null;

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = authority;
        options.Audience = audience;
        options.RequireHttpsMetadata = false; // For development only
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = cert != null ? new X509SecurityKey(cert) : null,
            NameClaimType = "name",
            ClockSkew = TimeSpan.FromMinutes(5) // Allow for some clock skew
        };
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                Console.WriteLine($"Authentication failed: {context.Exception}");
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                Console.WriteLine("Token validation started");
                
                // Check cnf claim and client certificate
                var cnf = context.Principal?.FindFirst("cnf")?.Value;
                if (string.IsNullOrEmpty(cnf))
                {
                    Console.WriteLine("Missing cnf claim in token");
                    context.Fail("Missing cnf claim.");
                    return Task.CompletedTask;
                }

                var httpContext = context.HttpContext;
                // Get client certificate from connection
                var clientCert = httpContext.Connection.ClientCertificate;
                if(clientCert == null)
                {
                    Console.WriteLine("Client certificate is required but not provided");
                    context.Fail("Client certificate is required.");
                    return Task.CompletedTask;
                }

                try
                {
                    // Parse cnf as JSON and compare thumbprints
                    var cnfObj = System.Text.Json.JsonDocument.Parse(cnf);
                    if (cnfObj.RootElement.TryGetProperty("x5t#S256", out var thumbprintElement))
                    {
                        // Calculate SHA256 thumbprint of the client certificate
                        using var sha256 = SHA256.Create();
                        var certBytes = clientCert.GetRawCertData();
                        var sha256Hash = sha256.ComputeHash(certBytes);
                        var base64UrlThumbprint = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(sha256Hash);
                        
                        var expectedThumbprint = thumbprintElement.GetString();
                        Console.WriteLine($"Client cert thumbprint: {base64UrlThumbprint}");
                        Console.WriteLine($"Expected thumbprint: {expectedThumbprint}");
                        
                        if (!string.Equals(base64UrlThumbprint, expectedThumbprint, StringComparison.OrdinalIgnoreCase))
                        {
                            Console.WriteLine("Client certificate thumbprint does not match cnf claim");
                            context.Fail("Client certificate thumbprint does not match cnf claim.");
                            return Task.CompletedTask;
                        }
                        
                        Console.WriteLine("Certificate thumbprint validation successful");
                    }
                    else
                    {
                        Console.WriteLine("Missing x5t#S256 property in cnf claim");
                        context.Fail("Missing x5t#S256 property in cnf claim.");
                        return Task.CompletedTask;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error validating cnf claim: {ex}");
                    context.Fail($"Error validating cnf claim: {ex.Message}");
                    return Task.CompletedTask;
                }
                
                Console.WriteLine("Token validation completed successfully");
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

app.MapControllers();

app.Run();
