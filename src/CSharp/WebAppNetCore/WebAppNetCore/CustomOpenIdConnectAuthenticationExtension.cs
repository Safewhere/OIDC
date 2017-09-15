using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Threading.Tasks;

namespace WebAppNetCore
{
    public static class CustomOpenIdConnectAuthenticationExtension
    {
        public static IServiceCollection ConfigureOpenIdServices(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddOpenIdConnect(connectOptions => InitializeConnectOptions(connectOptions, configuration));

            return services;
        }

        private static void InitializeConnectOptions(OpenIdConnectOptions connectOptions, IConfiguration configuration)
        {
            connectOptions.ClientId = configuration["OpenIdConnectOptions:ClientId"];
            connectOptions.ClientSecret = configuration["OpenIdConnectOptions:ClientSecret"];
            connectOptions.ResponseType = configuration["OpenIdConnectOptions:ResponseType"];
            connectOptions.UseTokenLifetime = true;
            connectOptions.SaveTokens = true;
            connectOptions.ClaimsIssuer = configuration["OpenIdConnectOptions:ClaimsIssuer"];
            connectOptions.GetClaimsFromUserInfoEndpoint = true;
            connectOptions.Configuration = new OpenIdConnectConfiguration()
            {
                AuthorizationEndpoint = configuration.AuthorizationEndpoint(),
                TokenEndpoint = configuration.TokenEndpoint(),
                UserInfoEndpoint = configuration.UserInfoEndpoint(),
                EndSessionEndpoint = configuration.EndSessionEndpoint(),
                HttpLogoutSupported = true
            };
            connectOptions.Events = new OpenIdConnectEvents
            {
                OnAuthorizationCodeReceived = async (context) =>
                {
                    await Task.FromResult(0);
                },
                OnTokenResponseReceived = async (context) =>
                {
                    Console.WriteLine("OnTokenResponseReceived.");
                    
                    await Task.FromResult(0);
                },
                OnRemoteFailure = async (context) =>
                {
                    Console.WriteLine("OnRemoteFailure.");
                    Console.WriteLine(context.Failure.ToString());

                    await Task.FromResult(0);
                },
                OnMessageReceived = async (context) =>
                {
                    await Task.FromResult(0);
                },
                OnTicketReceived = async (context) =>
                {
                    await Task.FromResult(0);
                },
                OnUserInformationReceived = async (context) =>
                {
                    await Task.FromResult(0);
                },
                OnTokenValidated = async (context) =>
                {
                    Console.WriteLine("OnTicketReceived.");
                    Console.WriteLine(context.SecurityToken.ToString());
                    await Task.FromResult(0);
                }
            };

            var scopes = configuration["OpenIdConnectOptions:Scope"]
                .Split(new char[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            connectOptions.Scope.Clear();
            foreach (var scope in scopes)
            {
                connectOptions.Scope.Add(scope);
            }

            connectOptions.TokenValidationParameters.IssuerSigningKey = new X509SecurityKey(configuration.IssuerSigningKey());
            connectOptions.TokenValidationParameters.ValidateAudience = true;   // by default, when we don't explicitly set ValidAudience, it is set to ClientId
            connectOptions.TokenValidationParameters.ValidateIssuer = true;
            connectOptions.TokenValidationParameters.ValidIssuer = configuration["OpenIdConnectOptions:ClaimsIssuer"];
            connectOptions.ProtocolValidator.RequireNonce = false;

            connectOptions.BackchannelHttpHandler = HttpClientHandlerProvider.Create();
        }
    }
}
