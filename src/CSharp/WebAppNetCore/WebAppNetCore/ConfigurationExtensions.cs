using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;

namespace WebAppNetCore
{
    public static class ConfigurationExtensions
    {
        public static string IssuerDomain(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:IssuerDomain"].TrimEnd('/');
        }

        public static string AuthorizationEndpoint(this IConfiguration configuration)
        {
            return configuration.IssuerDomain() + "/runtime/oauth2/authorize.idp";
        }

        public static string TokenEndpoint(this IConfiguration configuration)
        {
            return configuration.IssuerDomain() + "/runtime/oauth2/token.idp";
        }

        public static string UserInfoEndpoint(this IConfiguration configuration)
        {
            return configuration.IssuerDomain() + "/runtime/openidconnect/userinfo.idp";
        }

        public static string EndSessionEndpoint(this IConfiguration configuration)
        {
            return configuration.IssuerDomain() + "/runtime/openidconnect/logout.idp";
        }

        public static X509Certificate2 IssuerSigningKey(this IConfiguration configuration)
        {
            return new X509Certificate2(Convert.FromBase64String(configuration["OpenIdConnectOptions:TokenValidationParameters:IssuerSigningKey"]));
        }

        public static Uri EditMyProfileUri(this IConfiguration configuration)
        {
            return new Uri(configuration["OpenIdConnectOptions:EditMyProfileUri"]);
        }
    }
}
